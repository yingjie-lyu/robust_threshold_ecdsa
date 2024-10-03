use super::*;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Round3 {
    pub pd_gammak: BTreeMap<u8, BTreeMap<u8, QFI>>,
    pub pd_ggamma: BTreeMap<u8, BTreeMap<u8, G>>,

    pub ggama_ciphertexts: BTreeMap<u8, ElGamalCiphertext>,
    pub xk_ciphertexts: BTreeMap<u8, CipherText>,
    pub gammak_ciphertexts: BTreeMap<u8, CipherText>,
}

impl Round3 {
    pub fn new(
        pp: &ThresholdCLPubParams,
        threshold_pk: &ThresholdPubKey,
        secret_keys: &BTreeMap<Id, SecretKey>,
        x_shares: &BTreeMap<Id, Zq>,
        round2: &Round2,
        mut rng: &mut RandGen,
    ) -> Self {
        let mut msgs = Vec::with_capacity(pp.n as usize);
        let mut ggama_ciphertexts = BTreeMap::new();
        let mut xk_ciphertexts = BTreeMap::new();
        let mut gammak_ciphertexts = BTreeMap::new();

        for i in 1..=pp.n {
            let ggama_ciphertext = round2
                .ggama_ciphertexts
                .get(&i)
                .unwrap()
                .values()
                .take(pp.t as usize)
                .cloned()
                .reduce(|acc, ct| ElGamalCiphertext {
                    c1: acc.c1 + ct.c1,
                    c2: acc.c2 + ct.c2,
                })
                .unwrap();

            ggama_ciphertexts.insert(i, ggama_ciphertext.clone());

            let pd_ggamma = ggama_ciphertext.c1.clone() * x_shares.get(&i).unwrap();

            let gammak_ciphertext = round2
                .gammak_ciphertexts
                .get(&i)
                .unwrap()
                .values()
                .take(pp.t as usize)
                .cloned()
                .reduce(|acc, ct| {
                    CipherText::new(
                        &acc.c1().compose(&pp.cl, &ct.c1()),
                        &acc.c2().compose(&pp.cl, &ct.c2()),
                    )
                })
                .unwrap();

            gammak_ciphertexts.insert(i, gammak_ciphertext.clone());

            let pd_gammak = gammak_ciphertext.c1().exp(&pp.cl, &secret_keys[&i].mpz());

            let pd_proof = PDProof::prove(
                &pp,
                &mut rng,
                &threshold_pk,
                &pd_gammak,
                &gammak_ciphertext.c1(),
                &pd_ggamma,
                &ggama_ciphertext.c1,
                &secret_keys[&i].mpz(),
                &x_shares[&i],
            );

            msgs.push((
                i,
                pd_ggamma,
                pd_gammak,
                gammak_ciphertext.c1(),
                ggama_ciphertext.c1.clone(),
                pd_proof,
            ));

            let xk_ciphertext = pp
                .interpolate_for_cl(
                    &round2
                        .xk_ciphertexts
                        .get(&i)
                        .unwrap()
                        .clone()
                        .into_iter()
                        .take(pp.t as usize)
                        .collect(),
                )
                .unwrap();
            xk_ciphertexts.insert(i, xk_ciphertext);
        }

        let mut pd_gammak = BTreeMap::new();
        let mut pd_ggamma = BTreeMap::new();
        for i in 1..=pp.n {
            let mut each_party_pd_ggamma = BTreeMap::new();
            let mut each_party_pd_gammak = BTreeMap::new();
            let filter_verify_proof_msgs: Vec<_> = msgs
                .iter()
                .filter_map(|(j, pow2, pow1, gen1, gen2, proof)| {
                    //if proof.verify(pp, &pp.pk, ki_ciphertext) && *j != i {
                    if proof.verify(&pp, &mut rng, &threshold_pk, pow1, gen1, pow2, gen2) {
                        Some((*j, pow2.clone(), pow1.clone()))
                    } else {
                        None
                    }
                })
                .collect();
            assert_eq!(filter_verify_proof_msgs.len(), pp.n as usize);
            filter_verify_proof_msgs
                .into_iter()
                //.take((pp.t - 1) as usize)
                .take((pp.t) as usize)
                .for_each(|(j, pd_ggamma, pd_gammak)| {
                    each_party_pd_ggamma.insert(j, pd_ggamma);
                    each_party_pd_gammak.insert(j, pd_gammak);
                });

            pd_ggamma.insert(i, each_party_pd_ggamma);
            pd_gammak.insert(i, each_party_pd_gammak);
        }

        Self {
            pd_gammak,
            pd_ggamma,

            ggama_ciphertexts,
            xk_ciphertexts,
            gammak_ciphertexts,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_round3() {
        let n = 3;
        let t = 2;
        let (pp, secrect_keys) = ThresholdCLPubParams::simulate(n, t);
        let (threshold_pk, x_shares, x) = ThresholdPubKey::simulate(n, t);
        let mut rng = RandGen::new();
        let round1_msg = Round1::new(&pp, &mut rng);

        let round2_msg = Round2::new(&pp, &threshold_pk, &x_shares, &round1_msg, &mut rng);

        let round3_msg = Round3::new(
            &pp,
            &threshold_pk,
            &secrect_keys,
            &x_shares,
            &round2_msg,
            &mut rng,
        );
    }
}
