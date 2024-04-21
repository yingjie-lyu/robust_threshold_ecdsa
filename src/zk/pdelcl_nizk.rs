use super::*;
use crate::cdn::ElGamalCiphertext;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PDProof {
    pub e: Zq,
    pub z_1: Mpz,
    pub z_2: Zq,
}

impl PDProof {
    pub fn prove(
        pp: &ThresholdCLPubParams,
        rng: &mut RandGen,
        threshold_pk: &ThresholdPubKey,
        pow1: &QFI,
        gen1: &QFI,
        pow2: &G,
        gen2: &G,
        secret_keyi: &Mpz,
        xi: &Zq,
    ) -> Self {
        let u_1 = Zq::random();
        let u_2 = Zq::random();

        let U1 = gen1.exp(&pp.cl, &Mpz::from(&u_1));
        let U2 = gen2 * &u_2;

        let e = Self::challenge(pow1, pow2, &U1, &U2);
        let z_1 = Mpz::from(&u_1) + Mpz::from(&e) * secret_keyi;
        let z_2 = &u_2 + &e * xi;

        Self { e, z_1, z_2 }
    }

    pub fn verify(
        &self,
        pp: &ThresholdCLPubParams,
        rng: &mut RandGen,
        threshold_pk: &ThresholdPubKey,
        pow1: &QFI,
        gen1: &QFI,
        pow2: &G,
        gen2: &G,
    ) -> bool {
        let U1 = gen1
            .exp(&pp.cl, &self.z_1)
            .compose(&pp.cl, &pow1.exp(&pp.cl, &-Mpz::from(&self.e)));

        let U2 = gen2 * &self.z_2 - pow2 * &self.e;

        let e = Self::challenge(pow1, pow2, &U1, &U2);
        e == self.e
    }

    fn challenge(pow1: &QFI, pow2: &G, U1: &QFI, U2: &G) -> Zq {
        let mut hasher = Sha256::new();

        for item in &[
            pow1.to_bytes(),
            pow2.to_bytes(false).to_vec(),
            U1.to_bytes(),
            U2.to_bytes(false).to_vec(),
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
    fn test_pd_nizk() {
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

        let gen1 = round3_msg.gammak_ciphertexts.get(&1).unwrap().c1();
        let pow1 = round3_msg.pd_gammak.get(&1).unwrap().get(&1).unwrap();

        let gen2 = round3_msg.ggama_ciphertexts.get(&1).unwrap().c1.clone();
        let pow2 = round3_msg.pd_ggamma.get(&1).unwrap().get(&1).unwrap();

        let proof = PDProof::prove(
            &pp,
            &mut rng,
            &threshold_pk,
            &pow1,
            &gen1,
            &pow2,
            &gen2,
            &secrect_keys[&1].mpz(),
            &x_shares[&1],
        );

        assert_eq!(
            true,
            proof.verify(&pp, &mut rng, &threshold_pk, &pow1, &gen1, &pow2, &gen2)
        )
    }
}
