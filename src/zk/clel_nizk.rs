use super::*;
use crate::cdn::ElGamalCiphertext;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CLELProof {
    pub e: Zq,
    pub z_1: Mpz,
    pub z_2: Mpz,
}

impl CLELProof {
    pub fn prove(
        pp: &ThresholdCLPubParams,
        rng: &mut RandGen,
        threshold_pk: &ThresholdPubKey,
        pow1: &CipherText,
        gen1: &CipherText,
        pow2: &ElGamalCiphertext,
        gen2: &G,
        gammai: &Zq,
        eg_rand: &Zq,
    ) -> Self {
        let u_1 = Zq::random(); //gamma
        let u_2 = Zq::random(); //random

        let U1 = gen1.c1().exp(&pp.cl, &Mpz::from(&u_1));
        let U2 = gen1.c2().exp(&pp.cl, &Mpz::from(&u_1));
        let U3 = gen2 * &u_2;
        let U4 = gen2 * &u_1 + &threshold_pk.pk * &u_2;

        let e = Self::challenge(pow1, pow2, &U1, &U2, &U3, &U4);
        let z_1 = Mpz::from(&u_1) + Mpz::from(&e) * Mpz::from(gammai);
        let z_2 = Mpz::from(&u_2) + Mpz::from(&e) * Mpz::from(eg_rand);

        Self { e, z_1, z_2 }
    }

    pub fn verify(
        &self,
        pp: &ThresholdCLPubParams,
        rng: &mut RandGen,
        threshold_pk: &ThresholdPubKey,
        pow1: &CipherText,
        gen1: &CipherText,
        pow2: &ElGamalCiphertext,
        gen2: &G,
    ) -> bool {
        let U1 = gen1
            .c1()
            .exp(&pp.cl, &self.z_1)
            .compose(&pp.cl, &pow1.c1().exp(&pp.cl, &-Mpz::from(&self.e)));
        let U2 = gen1
            .c2()
            .exp(&pp.cl, &self.z_1)
            .compose(&pp.cl, &pow1.c2().exp(&pp.cl, &-Mpz::from(&self.e)));

        let U3 =
            gen2 * Zq::from_bigint(&BigInt::from_bytes(&self.z_2.to_bytes())) - &pow2.c1 * &self.e;

        let U4 = gen2 * Zq::from_bigint(&BigInt::from_bytes(&self.z_1.to_bytes()))
            + threshold_pk.pk.clone() * Zq::from_bigint(&BigInt::from_bytes(&self.z_2.to_bytes()))
            - &pow2.c2 * &self.e;

        let e = Self::challenge(pow1, pow2, &U1, &U2, &U3, &U4);
        e == self.e
    }

    fn challenge(
        pow1: &CipherText,
        pow2: &ElGamalCiphertext,
        U1: &QFI,
        U2: &QFI,
        U3: &G,
        U4: &G,
    ) -> Zq {
        let mut hasher = Sha256::new();

        for item in &[
            pow1.c1().to_bytes(),
            pow1.c2().to_bytes(),
            pow2.c1.to_bytes(false).to_vec(),
            pow2.c2.to_bytes(false).to_vec(),
            U1.to_bytes(),
            U2.to_bytes(),
            U3.to_bytes(false).to_vec(),
            U4.to_bytes(false).to_vec(),
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
    fn test_clel_nizk() {
        let n = 3;
        let t = 2;
        let (pp, secrect_keys) = ThresholdCLPubParams::simulate(n, t);
        let (threshold_pk, x_shares, x) = ThresholdPubKey::simulate(n, t);
        let mut rng = RandGen::new();
        let round1_msg = Round1::new(&pp, &mut rng);

        let round2_msg = Round2::new(&pp, &threshold_pk, &x_shares, &round1_msg, &mut rng);

        let gen1 = round2_msg.k_ciphertexts.get(&1).unwrap();
        let gammai = Zq::random();

        let (pow2, eg_rand) = ElGamalCiphertext::new(&gammai, &threshold_pk.pk);

        let pow1 = CipherText::new(
            &gen1.c1().exp(&pp.cl, &Mpz::from(&gammai)),
            &gen1.c2().exp(&pp.cl, &Mpz::from(&gammai)),
        );

        let gen2 = G::generator().clone();
        let proof = CLELProof::prove(
            &pp,
            &mut rng,
            &threshold_pk,
            &pow1,
            gen1,
            &pow2,
            &gen2,
            &gammai,
            &eg_rand,
        );

        assert_eq!(
            true,
            proof.verify(&pp, &mut rng, &threshold_pk, &pow1, gen1, &pow2, &gen2)
        )
    }
}
