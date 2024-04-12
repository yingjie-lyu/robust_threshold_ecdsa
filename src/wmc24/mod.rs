use crate::cdn::ThresholdCLPubParams;
use crate::spdz::ThresholdPubKey;
use crate::utils::Id;
use crate::utils::Zq;
use bicycl::{CL_HSMqk, CipherText, Mpz, PublicKey, RandGen, SecretKey, QFI};
use curv::arithmetic::Converter;
use curv::BigInt;
use serde::{Deserialize, Serialize};
use sha2::Digest;
use sha2::Sha256;

pub use crate::zk::*;
pub mod round1;

pub struct WMC24 {}

impl WMC24 {
    pub fn sign(n: Id, t: Id) {
        let (pp, secret_keys) = ThresholdCLPubParams::simulate(n, t);
        let (threshold_pk, x_shares, x) = ThresholdPubKey::simulate(n, t);

        let mut rng = RandGen::new();
        rng.set_seed(&Mpz::from(&Zq::random()));
        let r = rng.random_mpz(&pp.cl.encrypt_randomness_bound());
        let x_ciphertext = CipherText::new(
            &pp.cl.power_of_h(&r),
            &pp.cl
                .power_of_f(&Mpz::from(&x))
                .compose(&pp.cl, &pp.pk.exponentiation(&pp.cl, &r)),
        );
    }

    fn offine_sign(
        my_id: Id,
        pp: &ThresholdCLPubParams,
        threshold_pk: &ThresholdPubKey,
        my_cl_sk: &SecretKey,
        x_ciphertext: &CipherText,
        my_x_share: &Zq,
        lazy_verification: bool,
    ) {
        let mut rng = RandGen::new();
        rng.set_seed(&Mpz::from(&Zq::random()));

        // Pi encrypts ki
    }

    fn online_sign() {}
}
