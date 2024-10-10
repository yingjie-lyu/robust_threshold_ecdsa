use bicycl::{CipherText, Mpz, PublicKey, RandGen, QFI};
use curv::arithmetic::Converter;
use curv::BigInt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    cdn::ThresholdCLPubParams,
    utils::{Zq, G},
};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct L1heCiphertextWithProof {
    pub point: G,
    pub masked: Zq,
    pub mask_cl_ciphertext: CipherText,
    pub consistency_proof: ClDlNizk,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ClDlNizk {
    pub challenge: Zq,
    pub z1: Mpz,
    pub z2: Zq,
}

fn cl_encrypt(m: &Zq, pp: &ThresholdCLPubParams, rng: &mut RandGen) -> (CipherText, Mpz) {
    let encryption_randomness = rng.random_mpz(&pp.cl.encrypt_randomness_bound());
    let c1 = pp.cl.power_of_h(&encryption_randomness);
    let c2 = pp
        .cl
        .power_of_f(&Mpz::from(m))
        .compose(&pp.cl, &pp.pk.exp(&pp.cl, &encryption_randomness));
    (CipherText::new(&c1, &c2), encryption_randomness)
}

impl ClDlNizk {
    pub fn prove(
        pp: &ThresholdCLPubParams,
        rng: &mut RandGen,
        point: &G,
        clpk: &PublicKey,
        clct: &CipherText,
        scalar: &Zq,
        encryption_randomness: &Mpz,
    ) -> Self {
        let u1 = rng.random_mpz(&pp.cl.encrypt_randomness_bound()); // needs revising to use the correct bound
        let u2 = Zq::random();

        let U1 = pp.cl.power_of_h(&u1);
        let U2 = pp
            .cl
            .power_of_f(&Mpz::from(&u2))
            .compose(&pp.cl, &pp.pk.exp(&pp.cl, &u1));

        let U3 = G::generator() * &u2;

        let challenge = Self::fiat_shamir_challenge(clpk, point, clct, &U1, &U2, &U3);

        let z1 = u1 + Mpz::from(&challenge) * encryption_randomness;
        let z2 = u2 + &challenge * scalar;

        Self { challenge, z1, z2 }
    }

    fn fiat_shamir_challenge(
        clpk: &PublicKey,
        point: &G,
        clct: &CipherText,
        U1: &QFI,
        U2: &QFI,
        U3: &G,
    ) -> Zq {
        let mut hasher = Sha256::new();

        for item in &[
            clpk.to_bytes(),
            point.to_bytes(false).to_vec(),
            clct.c1().to_bytes(),
            clct.c2().to_bytes(),
            U1.to_bytes(),
            U2.to_bytes(),
            U3.to_bytes(false).to_vec(),
        ] {
            hasher.update(item);
        }

        Zq::from_bigint(&BigInt::from_bytes(&hasher.finalize()[..16]))
    }

    pub fn verify(
        &self,
        pp: &ThresholdCLPubParams,
        point: &G,
        clpk: &PublicKey,
        clct: &CipherText,
    ) -> bool {
        let U1 = pp
            .cl
            .power_of_h(&self.z1)
            .compose(&pp.cl, &clct.c1().exp(&pp.cl, &-Mpz::from(&self.challenge)));

        let U2 = pp
            .cl
            .power_of_f(&Mpz::from(&self.z2))
            .compose(&pp.cl, &pp.pk.exp(&pp.cl, &self.z1))
            .compose(&pp.cl, &clct.c2().exp(&pp.cl, &-Mpz::from(&self.challenge)));

        let U3 = G::generator() * &self.z2 - point * &self.challenge;

        let challenge = Self::fiat_shamir_challenge(clpk, point, clct, &U1, &U2, &U3);

        self.challenge == challenge
    }
}

impl L1heCiphertextWithProof {
    pub fn random(pp: &ThresholdCLPubParams, rng: &mut RandGen) -> Self {
        let scalar = Zq::random();
        let point = G::generator() * &scalar;

        let pad = Zq::random();

        let (mask_cl_ciphertext, encryption_randomness) = cl_encrypt(&pad, pp, rng);

        let masked = &scalar - &pad;

        let consistency_proof = ClDlNizk::prove(
            pp,
            rng,
            &point,
            &pp.pk,
            &mask_cl_ciphertext,
            &scalar,
            &encryption_randomness,
        );

        Self {
            point,
            masked,
            mask_cl_ciphertext,
            consistency_proof,
        }
    }

    pub fn verify(&self, pp: &ThresholdCLPubParams) -> bool {
        let mask_point = &self.point - G::generator() * &self.masked;

        ClDlNizk::verify(
            &self.consistency_proof,
            pp,
            &mask_point,
            &pp.pk,
            &self.mask_cl_ciphertext,
        )
    }

    pub fn add(&self, other: &Self, pp: &ThresholdCLPubParams) -> Self {
        Self {
            point: &self.point + &other.point,
            masked: &self.masked + &other.masked,
            mask_cl_ciphertext: CipherText::new(
                &self
                    .mask_cl_ciphertext
                    .c1()
                    .compose(&pp.cl, &other.mask_cl_ciphertext.c1()),
                &self
                    .mask_cl_ciphertext
                    .c2()
                    .compose(&pp.cl, &other.mask_cl_ciphertext.c2()),
            ),
            consistency_proof: ClDlNizk {
                challenge: Zq::zero(),
                z1: Mpz::from(0u64),
                z2: Zq::zero(),
            }, // dummy field, should not be used further
        }
    }

    // todo: adding a const. may need a thinned ciphertext type, without point, consistency_proof fields

    pub fn aggregate(ciphertexts: &[Self], pp: &ThresholdCLPubParams) -> Self {
        ciphertexts
            .into_iter()
            .cloned()
            .reduce(|a, b| a.add(&b, pp))
            .unwrap()
    }

    pub fn scale(&self, scalar: &Zq, pp: &ThresholdCLPubParams) -> Self {
        Self {
            point: &self.point * scalar,
            masked: &self.masked * scalar,
            mask_cl_ciphertext: CipherText::new(
                &self.mask_cl_ciphertext.c1().exp(&pp.cl, &Mpz::from(scalar)),
                &self.mask_cl_ciphertext.c2().exp(&pp.cl, &Mpz::from(scalar)),
            ),
            consistency_proof: self.consistency_proof.clone(), // dummy field, should not be used further
        }
    }

    pub fn multiply(&self, other: &Self, pp: &ThresholdCLPubParams) -> Level2Ciphertext {
        let ct1_left = self
            .mask_cl_ciphertext
            .c1()
            .exp(&pp.cl, &Mpz::from(&other.masked))
            .compose(
                &pp.cl,
                &other
                    .mask_cl_ciphertext
                    .c1()
                    .exp(&pp.cl, &Mpz::from(&self.masked)),
            );

        let ct1_right = self
            .mask_cl_ciphertext
            .c2()
            .exp(&pp.cl, &Mpz::from(&other.masked))
            .compose(
                &pp.cl,
                &other
                    .mask_cl_ciphertext
                    .c2()
                    .exp(&pp.cl, &Mpz::from(&self.masked)),
            )
            .compose(
                &pp.cl,
                &pp.cl.power_of_f(&Mpz::from(&self.masked * &other.masked)),
            );

        Level2Ciphertext {
            clct1: CipherText::new(&ct1_left, &ct1_right),
            clct2: self.mask_cl_ciphertext.clone(),
            clct3: other.mask_cl_ciphertext.clone(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Level2Ciphertext {
    clct1: CipherText,
    clct2: CipherText,
    clct3: CipherText,
}

impl Level2Ciphertext {
    pub fn rerandomize(
        &self,
        ciphertext_prim: &CipherText,
        hash1: Zq,
        hash2: Zq,
        pp: &ThresholdCLPubParams,
    ) -> Self {
        let clct1_left = self
            .clct1
            .c1()
            .compose(
                &pp.cl,
                &ciphertext_prim
                    .c1()
                    .exp(&pp.cl, &Mpz::from(-&hash1 * &hash2)),
            )
            .compose(&pp.cl, &self.clct2.c1().exp(&pp.cl, &Mpz::from(-&hash2)))
            .compose(&pp.cl, &self.clct3.c1().exp(&pp.cl, &Mpz::from(-&hash1)));

        let clct1_right = self
            .clct1
            .c2()
            .compose(
                &pp.cl,
                &ciphertext_prim
                    .c2()
                    .exp(&pp.cl, &Mpz::from(-&hash1 * &hash2)),
            )
            .compose(&pp.cl, &self.clct2.c2().exp(&pp.cl, &Mpz::from(-&hash2)))
            .compose(&pp.cl, &self.clct3.c2().exp(&pp.cl, &Mpz::from(-&hash1)));

        let clct2_left = self.clct2.c1().compose(
            &pp.cl,
            &ciphertext_prim.c1().exp(&pp.cl, &Mpz::from(&hash1)),
        );

        let clct2_right = self.clct2.c2().compose(
            &pp.cl,
            &ciphertext_prim.c2().exp(&pp.cl, &Mpz::from(&hash1)),
        );

        let clct3_left = self.clct3.c1().compose(
            &pp.cl,
            &ciphertext_prim.c1().exp(&pp.cl, &Mpz::from(&hash2)),
        );

        let clct3_right = self.clct3.c2().compose(
            &pp.cl,
            &ciphertext_prim.c2().exp(&pp.cl, &Mpz::from(&hash2)),
        );

        Self {
            clct1: CipherText::new(&clct1_left, &clct1_right),
            clct2: CipherText::new(&clct2_left, &clct2_right),
            clct3: CipherText::new(&clct3_left, &clct3_right),
        }
    }
}

