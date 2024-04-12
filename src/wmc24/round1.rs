use std::collections::BTreeMap;

use itertools::Itertools;

use super::*;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Round1 {
    pub k_ciphertexts: BTreeMap<u8, BTreeMap<u8, CipherText>>,
}

impl Round1 {
    pub fn new(pp: &ThresholdCLPubParams, rng: &mut RandGen) -> Self {
        let mut msgs = Vec::with_capacity(pp.n as usize);

        let mut per_cipher = BTreeMap::new();

        //Generate ki_ciphertext and corresponding proof
        for i in 1..=pp.n {
            let ki = Zq::random();
            let cl_rand = rng.random_mpz(&pp.cl.encrypt_randomness_bound());
            let c1 = pp.cl.power_of_h(&cl_rand);
            let c2 = pp
                .cl
                .power_of_f(&Mpz::from(&ki))
                .compose(&pp.cl, &pp.pk.exponentiation(&pp.cl, &cl_rand));
            let ki_ciphertext = CipherText::new(&c1, &c2);
            let proof = CLEncProof::prove(&pp, rng, &pp.pk, &ki_ciphertext, &ki, &cl_rand);
            msgs.push((i, ki_ciphertext.clone(), proof));
            per_cipher.insert(i, ki_ciphertext);
        }

        // Each party can obtain different ki_ciphertexts
        let mut k_ciphertexts = BTreeMap::new();
        for i in 1..=pp.n {
            let mut each_party_k_ciphertexts = BTreeMap::new();
            let ki_ciphertexts: Vec<_> = msgs
                .iter()
                .filter_map(|(j, ki_ciphertext, proof)| {
                    if proof.verify(pp, &pp.pk, ki_ciphertext) {
                        Some((*j, ki_ciphertext.clone(), proof.clone()))
                    } else {
                        None
                    }
                })
                .collect();
            
            each_party_k_ciphertexts.insert(i, per_cipher.get(&i).unwrap().clone());

            ki_ciphertexts
                .into_iter()
                .take(pp.t as usize)
                .for_each(|(j, ki_ciphertext, _)| {
                    each_party_k_ciphertexts.insert(j, ki_ciphertext);
                });

            k_ciphertexts.insert(i, each_party_k_ciphertexts);

            //msgs.rotate_left(1);
        }

        Self { k_ciphertexts }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_round1() {
        let (pp, _) = ThresholdCLPubParams::simulate(3, 2);
        let mut rng = RandGen::new();
        let msg = Round1::new(&pp, &mut rng);
        let mut k_cipers = Vec::with_capacity(pp.n as usize);
        for (key, value) in &msg.k_ciphertexts {
            println!("{:?}", value.keys());
            k_cipers.push(pp.interpolate_for_cl(value).unwrap());
        }
        assert_eq!(k_cipers[0].c2(), k_cipers[1].c2());
    }
}
