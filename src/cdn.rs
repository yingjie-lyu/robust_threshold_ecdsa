use std::ops::Add;

use bicycl::{CipherText, ClearText, Mpz, PublicKey, RandGen, QFI};
use curv::{arithmetic::Converter, elliptic::curves::Secp256k1, BigInt};
use crate::{spdz::OpenPowerMsg, utils::*};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};


#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ElGamalCiphertext {
    pub c1: G,
    pub c2: G,
}

impl ElGamalCiphertext {
    pub fn new(m: &Zq, pk: &G) -> (Self, Zq) {
        let r = Zq::random();
        let c1 = G::generator() * &r;
        let c2 = G::generator() * m + pk * &r;
        ( ElGamalCiphertext { c1, c2 }, r )
    }

}

impl Add for ElGamalCiphertext {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        ElGamalCiphertext {
            c1: self.c1 + other.c1,
            c2: self.c2 + other.c2,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CLEGDoubleEncNizk {
    pub e: Zq,
    pub z1: Mpz,
    pub z2: Zq,
    pub z3: Zq,
}

impl CLEGDoubleEncNizk {
    pub fn prove(pp: &PubParams, rng: &mut RandGen, clpk: &PublicKey, clct: &CipherText, ecpk: &G, egct: &ElGamalCiphertext, m: &Zq, cl_rand: &Mpz, eg_rand: &Zq) -> Self {
        let u1 = rng.random_mpz(&pp.cl.encrypt_randomness_bound());
        let u2 = Zq::random();
        let u3 = Zq::random();

        let U1 = pp.cl.power_of_h(&u1);
        let U2 = pp.cl.power_of_f(&Mpz::from(&u2))
                           .compose(&pp.cl, &clpk.exponentiation(&pp.cl, &u1));
        let U3 = G::generator() * &u3;
        let U4 = G::generator() * &u2 + ecpk * &u3;

        let e = Self::challenge(clpk, clct, ecpk, egct, &U1, &U2, &U3, &U4);
        let z1 = &u1 + Mpz::from(&e) * cl_rand;
        let z2 = &u2 + &e * m;
        let z3 = &u3 + &e * eg_rand;

        Self { e, z1, z2, z3 }
    }

    pub fn verify(&self, pp: &PubParams, clpk: &PublicKey, clct: &CipherText, ecpk: &G, egct: &ElGamalCiphertext) -> bool {
        let U1 = pp.cl.power_of_h(&self.z1).compose(&pp.cl, &clct.c1().exp(&pp.cl, &-Mpz::from(&self.e)));
        let U2 = pp.cl.power_of_f(&Mpz::from(&self.z2))
                           .compose(&pp.cl, &clpk.exponentiation(&pp.cl, &self.z1))
                           .compose(&pp.cl, &clct.c2().exp(&pp.cl, &-Mpz::from(&self.e)));
        let U3 = G::generator() * &self.z3 - &egct.c1 * &self.e;
        let U4 = G::generator() * &self.z2 + ecpk * &self.z3 - &egct.c2 * &self.e;

        let e = Self::challenge(clpk, clct, ecpk, egct, &U1, &U2, &U3, &U4);
        e == self.e
    }

    fn challenge(clpk: &PublicKey, clct: &CipherText, ecpk: &G, egct: &ElGamalCiphertext,
                 U1: &QFI, U2: &QFI, U3: &G, U4: &G) -> Zq {
        let mut hasher = Sha256::new();

        for item in 
            &[clpk.to_bytes(),
            clct.c1().to_bytes(),
            clct.c2().to_bytes(),
            ecpk.to_bytes(false).to_vec(),
            egct.c1.to_bytes(false).to_vec(),
            egct.c2.to_bytes(false).to_vec(),
            U1.to_bytes(),
            U2.to_bytes(),
            U3.to_bytes(false).to_vec(),
            U4.to_bytes(false).to_vec()]
        {
            hasher.update(item);
        }

        Zq::from_bigint(&BigInt::from_bytes(&hasher.finalize()[..16]))
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct NonceProposalMsg {
    pub ki_ciphertext: CipherText,
    pub Ri_ciphertext: ElGamalCiphertext,
    pub proof: CLEGDoubleEncNizk,
}

impl NonceProposalMsg {
    pub fn new(pp: &PubParams, rng: &mut RandGen, clpk: &PublicKey, ecpk: &G) -> Self {
        let ki = Zq::random();
        let cl_rand = rng.random_mpz(&pp.cl.encrypt_randomness_bound());
        let c1 = pp.cl.power_of_h(&cl_rand);
        let c2 = pp.cl.power_of_f(&Mpz::from(&ki)).compose(&pp.cl, &clpk.exponentiation(&pp.cl, &cl_rand));
        let ki_ciphertext = CipherText::new(&c1, &c2);
        let (Ri_ciphertext, eg_rand) = ElGamalCiphertext::new(&ki, ecpk);

        let proof = CLEGDoubleEncNizk::prove(pp, rng, clpk, &ki_ciphertext, ecpk, &Ri_ciphertext, &ki, &cl_rand, &eg_rand);

        Self { ki_ciphertext, Ri_ciphertext, proof }
    }

    pub fn verify(&self, pp: &PubParams, clpk: &PublicKey, ecpk: &G, egct: &ElGamalCiphertext) -> bool {
        self.proof.verify(pp, clpk, &self.ki_ciphertext, ecpk, egct)
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CLScal2Nizk {
    pub e: Zq,
    pub z1: Mpz,
    pub z2: Zq,
}

impl CLScal2Nizk {
    pub fn prove(pp: &PubParams, rng: &mut RandGen, pk: &PublicKey, scalar_ct: &CipherText, base: &G, scalar_pub: &G,
        orig_ct1: &CipherText, scaled_ct1: &CipherText, orig_ct2: &CipherText, scaled_ct2: &CipherText,
        scalar: &Zq, cl_rand: &Mpz)
    -> Self {
        let u1 = rng.random_mpz(&pp.cl.encrypt_randomness_bound());
        let u2 = Zq::random();

        let U1 = pp.cl.power_of_h(&u1);
        let U2 = pp.cl.power_of_f(&Mpz::from(&u2))
                           .compose(&pp.cl, &pk.exponentiation(&pp.cl, &u1));
        let U3 = base * &u2;
        let U4 = orig_ct1.c1().exp(&pp.cl,&Mpz::from(&u2));
        let U5 = orig_ct1.c2().exp(&pp.cl,&Mpz::from(&u2));
        let U6 = orig_ct2.c1().exp(&pp.cl,&Mpz::from(&u2));
        let U7 = orig_ct2.c2().exp(&pp.cl,&Mpz::from(&u2));

        let e = Self::challenge(pk, scalar_ct, scalar_pub, base, orig_ct1, scaled_ct1, orig_ct2, scaled_ct2, &U1, &U2, &U3, &U4, &U5, &U6, &U7);
        let z1 = &u1 + Mpz::from(&e) * cl_rand;
        let z2 = &u2 + &e * scalar;

        Self { e, z1, z2 }
    }

    pub fn verify(&self, pp: &PubParams, pk: &PublicKey, scalar_ct: &CipherText, base: &G, scalar_pub: &G,
        orig_ct1: &CipherText, scaled_ct1: &CipherText, orig_ct2: &CipherText, scaled_ct2: &CipherText)
    -> bool {
        let U1 = pp.cl.power_of_h(&self.z1).compose(&pp.cl, &scalar_ct.c1().exp(&pp.cl, &-Mpz::from(&self.e)));
        let U2 = pp.cl.power_of_f(&Mpz::from(&self.z2))
                           .compose(&pp.cl, &pk.exponentiation(&pp.cl, &self.z1))
                           .compose(&pp.cl, &scalar_ct.c2().exp(&pp.cl, &-Mpz::from(&self.e)));
        let U3 = base * &self.z2 - scalar_pub * &self.e;
        let U4 = orig_ct1.c1().exp(&pp.cl,&Mpz::from(&self.z2))
                        .compose(&pp.cl, &scaled_ct1.c1().exp(&pp.cl, &-Mpz::from(&self.e)));
        let U5 = orig_ct1.c2().exp(&pp.cl,&Mpz::from(&self.z2))
                        .compose(&pp.cl, &scaled_ct1.c2().exp(&pp.cl, &-Mpz::from(&self.e)));
        let U6 = orig_ct2.c1().exp(&pp.cl,&Mpz::from(&self.z2))
                        .compose(&pp.cl, &scaled_ct2.c1().exp(&pp.cl, &-Mpz::from(&self.e)));
        let U7 = orig_ct2.c2().exp(&pp.cl,&Mpz::from(&self.z2))
                        .compose(&pp.cl, &scaled_ct2.c2().exp(&pp.cl, &-Mpz::from(&self.e)));

        let e = Self::challenge(pk, scalar_ct, base, scalar_pub, orig_ct1, scaled_ct1, orig_ct2, scaled_ct2, &U1, &U2, &U3, &U4, &U5, &U6, &U7);
        e == self.e
    }

    fn challenge(pk: &PublicKey, scalar_ct: &CipherText, base: &G, scalar_pub: &G,
        orig_ct1: &CipherText, scaled_ct1: &CipherText, orig_ct2: &CipherText, scaled_ct2: &CipherText,
        U1: &QFI, U2: &QFI, U3: &G, U4: &QFI, U5: &QFI, U6: &QFI, U7: &QFI) -> Zq {
        let mut hasher = Sha256::new();

        for item in 
            &[pk.to_bytes(),
            scalar_ct.c1().to_bytes(),
            scalar_ct.c2().to_bytes(),
            base.to_bytes(false).to_vec(),
            scalar_pub.to_bytes(false).to_vec(),
            orig_ct1.c1().to_bytes(),
            orig_ct1.c2().to_bytes(),
            scaled_ct1.c1().to_bytes(),
            scaled_ct1.c2().to_bytes(),
            orig_ct2.c1().to_bytes(),
            orig_ct2.c2().to_bytes(),
            scaled_ct2.c1().to_bytes(),
            scaled_ct2.c2().to_bytes(),
            U1.to_bytes(),
            U2.to_bytes(),
            U3.to_bytes(false).to_vec(),
            U4.to_bytes(),
            U5.to_bytes(),
            U6.to_bytes(),
            U7.to_bytes()]
        {
            hasher.update(item);
        }

        Zq::from_bigint(&BigInt::from_bytes(&hasher.finalize()[..16]))
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct NonceExtractMaskMsg {
    pub R_partial_dec: OpenPowerMsg,
    pub phi_i_ciphertext: CipherText,
    pub kphi_i_ciphertext: CipherText,
    pub xphi_i_ciphertext: CipherText,
    Phi_i: G,
    proof: CLScal2Nizk,
}

impl NonceExtractMaskMsg {
    pub fn new(pp: &PubParams, rng: &mut RandGen, clpk: &PublicKey, ec_pub_share: &G, k_ciphertext: &CipherText, x_ciphertext: &CipherText,
        R_ciphertext: &ElGamalCiphertext, xi: &Zq) -> Self {
            let R_partial_dec = OpenPowerMsg::new(xi, &G::generator(), ec_pub_share, &R_ciphertext.c1);
            let phi_i = Zq::random();
            let cl_rand = rng.random_mpz(&pp.cl.encrypt_randomness_bound());
            
            let phi_i_ciphertext = CipherText::new(&pp.cl.power_of_h(&cl_rand),
                &pp.cl.power_of_f(&Mpz::from(&phi_i))
                    .compose(&pp.cl, &clpk.exponentiation(&pp.cl, &cl_rand)));

            let kphi_i_ciphertext = k_ciphertext.scal(&pp.cl, &Mpz::from(&phi_i));
            let xphi_i_ciphertext = x_ciphertext.scal(&pp.cl, &Mpz::from(&phi_i));

            let Phi_i = G::generator() * &phi_i;

            let proof = CLScal2Nizk::prove(pp, rng, clpk, &phi_i_ciphertext, &G::generator(), &Phi_i, &k_ciphertext, &kphi_i_ciphertext, &x_ciphertext, &xphi_i_ciphertext, &phi_i, &cl_rand);

            Self { R_partial_dec, phi_i_ciphertext, kphi_i_ciphertext, xphi_i_ciphertext, Phi_i, proof }
        }

    pub fn verify(&self, pp: &PubParams, ec_pub_share: &G, R_ciphertext: &ElGamalCiphertext, clpk: &PublicKey, k_ciphertext: &CipherText, x_ciphertext: &CipherText) -> bool {
        self.R_partial_dec.proof.verify(&G::generator(), ec_pub_share, &R_ciphertext.c1, &self.R_partial_dec.point)
            &&
        self.proof.verify(pp, clpk, &self.phi_i_ciphertext, &G::generator(), &self.Phi_i, &k_ciphertext, &self.kphi_i_ciphertext, &x_ciphertext, &self.xphi_i_ciphertext)
    }
}


pub struct CLThresholdDec2Nizk {
    pub e: Zq,
    pub z: Zq,
}