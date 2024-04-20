use super::*;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CLDLProof {
    pub e: Zq,
    pub z: Mpz,
}

impl CLDLProof {
    pub fn prove(
        pp: &ThresholdCLPubParams,
        rng: &mut RandGen,
        pow1: &CipherText,
        gen1: &CipherText,
        pow2: &G,
        gen2: &G,
        xi: &Zq,
    ) -> Self {
        let u = Zq::random();

        let U1 = gen1.c1().exp(&pp.cl, &Mpz::from(&u));
        let U2 = gen1.c2().exp(&pp.cl, &Mpz::from(&u));
        let U3 = gen2 * &u;

        let e = Self::challenge(pow1, pow2, &U1, &U2, &U3);
        let z = Mpz::from(&u) + Mpz::from(&e) * Mpz::from(xi);

        Self { e, z }
    }

    pub fn verify(
        &self,
        pp: &ThresholdCLPubParams,
        rng: &mut RandGen,
        pow1: &CipherText,
        gen1: &CipherText,
        pow2: &G,
        gen2: &G,
    ) -> bool {
        let U1 = gen1
            .c1()
            .exp(&pp.cl, &self.z)
            .compose(&pp.cl, &pow1.c1().exp(&pp.cl, &-Mpz::from(&self.e)));
        let U2 = gen1
            .c2()
            .exp(&pp.cl, &self.z)
            .compose(&pp.cl, &pow1.c2().exp(&pp.cl, &-Mpz::from(&self.e)));

        let U3 = gen2 * Zq::from_bigint(&BigInt::from_bytes(&self.z.to_bytes())) - pow2 * &self.e;

        let e = Self::challenge(pow1, pow2, &U1, &U2, &U3);
        e == self.e
    }

    fn challenge(pow1: &CipherText, pow2: &G, U1: &QFI, U2: &QFI, U3: &G) -> Zq {
        let mut hasher = Sha256::new();

        for item in &[
            pow1.c1().to_bytes(),
            pow1.c2().to_bytes(),
            pow2.to_bytes(false).to_vec(),
            U1.to_bytes(),
            U2.to_bytes(),
            U3.to_bytes(false).to_vec(),
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
    fn test_cldl_nizk() {
        let n = 3;
        let t = 2;
        let (pp, secrect_keys) = ThresholdCLPubParams::simulate(n, t);
        let (threshold_pk, x_shares, x) = ThresholdPubKey::simulate(n, t);
        let mut rng = RandGen::new();
        let round1_msg = Round1::new(&pp, &mut rng);

        let round2_msg = Round2::new(&pp, &threshold_pk, &x_shares, &round1_msg, &mut rng);

        //let pow1 = round2_msg.xk_ciphertexts.get(&1).unwrap().get(&1).unwrap();

        let gen1 = round2_msg.k_ciphertexts.get(&1).unwrap();

        let pow1 = CipherText::new(
            &gen1.c1().exp(&pp.cl, &Mpz::from(&x_shares[&1])),
            &gen1.c2().exp(&pp.cl, &Mpz::from(&x_shares[&1])),
        );

        let pow2 = threshold_pk.pub_shares[&1].clone();

        let gen2 = G::generator().clone();

        assert_eq!(pow2, gen2 * &x_shares[&1]);

        let proof = CLDLProof::prove(&pp, &mut rng, &pow1, gen1, &pow2, &gen2, &x_shares[&1]);

        assert_eq!(true, proof.verify(&pp, &mut rng, &pow1, gen1, &pow2, &gen2))
    }
}
