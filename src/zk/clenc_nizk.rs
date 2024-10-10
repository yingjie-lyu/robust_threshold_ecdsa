use super::*;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CLEncProof {
    pub e: Zq,
    pub z1: Mpz,
    pub z2: Zq,
}

impl CLEncProof {
    pub fn prove(
        pp: &ThresholdCLPubParams,
        rng: &mut RandGen,
        clpk: &PublicKey,
        clct: &CipherText,
        m: &Zq,
        cl_rand: &Mpz,
    ) -> Self {
        let u1 = rng.random_mpz(&pp.cl.encrypt_randomness_bound());
        let u2 = Zq::random();

        let U1 = pp.cl.power_of_h(&u1);
        let U2 = pp
            .cl
            .power_of_f(&Mpz::from(&u2))
            .compose(&pp.cl, &clpk.exp(&pp.cl, &u1));

        let e = Self::challenge(clpk, clct, &U1, &U2);
        let z1 = &u1 + Mpz::from(&e) * cl_rand;
        let z2 = &u2 + &e * m;

        Self { e, z1, z2 }
    }

    pub fn verify(&self, pp: &ThresholdCLPubParams, clpk: &PublicKey, clct: &CipherText) -> bool {
        let U1 = pp
            .cl
            .power_of_h(&self.z1)
            .compose(&pp.cl, &clct.c1().exp(&pp.cl, &-Mpz::from(&self.e)));
        let U2 = pp
            .cl
            .power_of_f(&Mpz::from(&self.z2))
            .compose(&pp.cl, &clpk.exp(&pp.cl, &self.z1))
            .compose(&pp.cl, &clct.c2().exp(&pp.cl, &-Mpz::from(&self.e)));

        let e = Self::challenge(clpk, clct, &U1, &U2);
        e == self.e
    }

    fn challenge(clpk: &PublicKey, clct: &CipherText, U1: &QFI, U2: &QFI) -> Zq {
        let mut hasher = Sha256::new();

        for item in &[
            clpk.to_bytes(),
            clct.c1().to_bytes(),
            clct.c2().to_bytes(),
            U1.to_bytes(),
            U2.to_bytes(),
        ] {
            hasher.update(item);
        }

        Zq::from_bigint(&BigInt::from_bytes(&hasher.finalize()[..16]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clenc_nizk() {
        let (pp, _) = ThresholdCLPubParams::simulate(3, 2);
        let ki = Zq::random();
        let mut rng = RandGen::new();
        let cl_rand = rng.random_mpz(&pp.cl.encrypt_randomness_bound());
        let c1 = pp.cl.power_of_h(&cl_rand);
        let c2 = pp
            .cl
            .power_of_f(&Mpz::from(&ki))
            .compose(&pp.cl, &pp.pk.exp(&pp.cl, &cl_rand));

        let ki_ciphertext = CipherText::new(&c1, &c2);
        rng.set_seed(&Mpz::from(&Zq::random()));

        let proof = CLEncProof::prove(&pp, &mut rng, &pp.pk, &ki_ciphertext, &ki, &cl_rand);

        assert_eq!(true, proof.verify(&pp, &pp.pk, &ki_ciphertext))
    }
}
