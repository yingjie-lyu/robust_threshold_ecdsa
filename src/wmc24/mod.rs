use crate::cdn::ElGamalCiphertext;
use crate::cdn::ThresholdCLPubParams;
use crate::spdz::ThresholdPubKey;
use crate::utils::ECDSASignature;
use crate::utils::Id;
use crate::utils::Zq;
use crate::utils::G;
use bicycl::{CL_HSMqk, CipherText, Mpz, PublicKey, RandGen, SecretKey, QFI};
use curv::arithmetic::Converter;
use curv::BigInt;
use serde::{Deserialize, Serialize};
use sha2::Digest;
use sha2::Sha256;
use std::collections::BTreeMap;

use itertools::Itertools;

pub use crate::zk::*;
pub mod round1;
pub use round1::*;
pub mod round2;
pub use round2::*;
pub mod round3;
pub use round3::*;

pub struct WMC24 {}

pub struct Offine {
    pub rs: BTreeMap<u8, G>,
    pub xk_ciphertexts: BTreeMap<u8, CipherText>,
    pub k_ciphertexts: BTreeMap<u8, CipherText>,
}

impl WMC24 {
    pub fn sign(n: Id, t: Id) {
        let (pp, secret_keys) = ThresholdCLPubParams::simulate(n, t);
        let (threshold_pk, x_shares, x) = ThresholdPubKey::simulate(n, t);

        let mut rng = RandGen::new();

        let offine_msg = Self::offine_sign(&pp, &threshold_pk, &secret_keys, &x_shares, &mut rng);

        let message_hash = Zq::random();

        let sig = Self::online_sign(
            &pp,
            &threshold_pk,
            &secret_keys,
            &x_shares,
            &offine_msg,
            &message_hash,
            &mut rng,
        );
    }

    fn offine_sign(
        pp: &ThresholdCLPubParams,
        threshold_pk: &ThresholdPubKey,
        secret_keys: &BTreeMap<Id, SecretKey>,
        x_shares: &BTreeMap<Id, Zq>,
        rng: &mut RandGen,
    ) -> Offine {
        let round1_msg = Round1::new(pp, rng);

        let round2_msg = Round2::new(pp, threshold_pk, x_shares, &round1_msg, rng);

        let round3_msg = Round3::new(pp, threshold_pk, secret_keys, x_shares, &round2_msg, rng);

        let mut gammaks = BTreeMap::new();
        let mut ggammas = BTreeMap::new();
        let mut rs = BTreeMap::new();
        for i in 1..=pp.n {
            //fully decrypts γk
            let gamak_nominator = round3_msg
                .gammak_ciphertexts
                .get(&i)
                .unwrap()
                .c2()
                .exp(&pp.cl, &pp.n_factorial.pow(3));

            let filtered_pd_gammak = round3_msg
                .pd_gammak
                .get(&i)
                .unwrap()
                .clone()
                .into_iter()
                .take(pp.t as usize)
                .collect::<BTreeMap<_, _>>();

            let lagrange_coeffs_times_n_factorial = pp
                .lagrange_coeffs_times_n_factorial(filtered_pd_gammak.keys().cloned().collect())
                .unwrap();

            let gamak_denominator = filtered_pd_gammak
                .iter()
                .take(pp.t as usize)
                .map(|(i, gamaki)| gamaki.exp(&pp.cl, &lagrange_coeffs_times_n_factorial[i]))
                .reduce(|acc, qf| acc.compose(&pp.cl, &qf));

            let f_pow_gamak = gamak_nominator.compose(
                &pp.cl,
                &gamak_denominator.unwrap().exp(&pp.cl, &Mpz::from(-1i64)),
            );

            let gamak = pp.cl.dlog_in_F(&f_pow_gamak);
            let gamak = Zq::from(BigInt::from_bytes(&gamak.to_bytes()));
            gammaks.insert(i, gamak.clone());

            if i != 1 {
                assert_eq!(gammaks.get(&i).unwrap(), gammaks.get(&(i - 1)).unwrap());
            }

            //fully decrypts g^\gamma
            let ggamma_nominator = round3_msg.ggama_ciphertexts.get(&i).unwrap().c2.clone();

            let filtered_pd_ggamma = round3_msg
                .pd_ggamma
                .get(&i)
                .unwrap()
                .clone()
                .into_iter()
                .take(pp.t as usize)
                .collect::<BTreeMap<_, _>>();

            let ggamma_denominator = pp.interpolate_on_curve(&filtered_pd_ggamma).unwrap();

            let ggamma = ggamma_nominator + ggamma_denominator * Zq::from(-1);
            ggammas.insert(i, ggamma.clone());

            if i != 1 {
                assert_eq!(ggammas.get(&i).unwrap(), ggammas.get(&(i - 1)).unwrap());
            }

            // R = (g^\gamma)^{1/gammak}
            let R = ggamma * gamak.invert().unwrap();
            rs.insert(i, R);

            if i != 1 {
                assert_eq!(rs.get(&i).unwrap(), rs.get(&(i - 1)).unwrap());
            }
        }
        Offine {
            rs: rs,
            xk_ciphertexts: round3_msg.xk_ciphertexts,
            k_ciphertexts: round2_msg.k_ciphertexts,
        }
    }

    fn online_sign(
        pp: &ThresholdCLPubParams,
        threshold_pk: &ThresholdPubKey,
        secret_keys: &BTreeMap<Id, SecretKey>,
        x_shares: &BTreeMap<Id, Zq>,
        offine_msg: &Offine,
        message_hash: &Zq,
        mut rng: &mut RandGen,
    ) -> ECDSASignature {
        let mut rcoords = BTreeMap::new();
        let mut mk_plus_rxk_ciphertexts = BTreeMap::new();
        let mut pd_mk_plus_rxk_ciphertexts = BTreeMap::new();
        for i in 1..=pp.n {
            let r = Zq::from_bigint(&offine_msg.rs.get(&i).unwrap().x_coord().unwrap());
            rcoords.insert(i, r.clone());

            let k_ciphertext = offine_msg.k_ciphertexts.get(&i).unwrap().clone();

            let mk_ciphertext = CipherText::new(
                &k_ciphertext.c1().exp(&pp.cl, &Mpz::from(message_hash)),
                &k_ciphertext.c2().exp(&pp.cl, &Mpz::from(message_hash)),
            );

            let xk_ciphertext = offine_msg.xk_ciphertexts.get(&i).unwrap().clone();
            let rxk_ciphertext = CipherText::new(
                &xk_ciphertext.c1().exp(&pp.cl, &Mpz::from(&r)),
                &xk_ciphertext.c2().exp(&pp.cl, &Mpz::from(&r)),
            );

            let mk_plus_rxk_ciphertext = CipherText::new(
                &mk_ciphertext.c1().compose(&pp.cl, &rxk_ciphertext.c1()),
                &mk_ciphertext.c2().compose(&pp.cl, &rxk_ciphertext.c2()),
            );

            mk_plus_rxk_ciphertexts.insert(i, mk_plus_rxk_ciphertext.clone());

            let pd_mk_plus_rxk_ciphertext = mk_plus_rxk_ciphertext
                .c1()
                .exp(&pp.cl, &secret_keys[&i].mpz());

            let proof = PDCLProof::prove(
                &pp,
                &mut rng,
                &threshold_pk,
                &pd_mk_plus_rxk_ciphertext,
                &mk_plus_rxk_ciphertext.c1(),
                &secret_keys[&i].mpz(),
            );

            pd_mk_plus_rxk_ciphertexts.insert(
                i,
                (
                    pd_mk_plus_rxk_ciphertext,
                    mk_plus_rxk_ciphertext.c1(),
                    proof,
                ),
            );

            if i != 1 {
                assert_eq!(rcoords.get(&i).unwrap(), rcoords.get(&(i - 1)).unwrap());
            }
        }

        let mut ss = BTreeMap::new();
        for i in 1..=pp.n {
            let mk_plus_rxk_nominator = mk_plus_rxk_ciphertexts
                .get(&i)
                .unwrap()
                .c2()
                .exp(&pp.cl, &pp.n_factorial.pow(3));

            let mut each_party_pd_mk_plus_rxk_ciphertexts = BTreeMap::new();

            pd_mk_plus_rxk_ciphertexts
                .iter()
                .for_each(|(j, (pow1, gen1, proof))| {
                    if proof.verify(&pp, &mut rng, &threshold_pk, &pow1, &gen1) {
                        each_party_pd_mk_plus_rxk_ciphertexts.insert(*j, pow1.clone());
                    }
                });

            assert_eq!(each_party_pd_mk_plus_rxk_ciphertexts.len(), pp.n as usize);

            let filtered_pd_mk_plus_rxk = each_party_pd_mk_plus_rxk_ciphertexts
                .into_iter()
                .take(pp.t as usize)
                .collect::<BTreeMap<_, _>>();

            let lagrange_coeffs_times_n_factorial = pp
                .lagrange_coeffs_times_n_factorial(
                    filtered_pd_mk_plus_rxk.keys().cloned().collect(),
                )
                .unwrap();

            let mk_plus_rxk_denominator = filtered_pd_mk_plus_rxk
                .iter()
                .map(|(i, gamaki)| gamaki.exp(&pp.cl, &lagrange_coeffs_times_n_factorial[i]))
                .reduce(|acc, qf| acc.compose(&pp.cl, &qf));

            let f_pow_mk_plus_rxk = mk_plus_rxk_nominator.compose(
                &pp.cl,
                &mk_plus_rxk_denominator
                    .unwrap()
                    .exp(&pp.cl, &Mpz::from(-1i64)),
            );

            let mk_plus_rxk = pp.cl.dlog_in_F(&f_pow_mk_plus_rxk);
            let s = Zq::from(BigInt::from_bytes(&mk_plus_rxk.to_bytes()));
            ss.insert(i, s);

            if i != 1 {
                assert_eq!(ss.get(&i).unwrap(), ss.get(&(i - 1)).unwrap());
            }
        }
        ECDSASignature {
            r: rcoords.get(&1).unwrap().clone(),
            s: ss.get(&1).unwrap().clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign() {
        WMC24::sign(3, 2);
    }
}
