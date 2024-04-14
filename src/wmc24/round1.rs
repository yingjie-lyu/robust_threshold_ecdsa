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
                    //if proof.verify(pp, &pp.pk, ki_ciphertext) && *j != i {
                    if proof.verify(pp, &pp.pk, ki_ciphertext) {
                        Some((*j, ki_ciphertext.clone(), proof.clone()))
                    } else {
                        None
                    }
                })
                .collect();

            //each_party_k_ciphertexts.insert(i, per_cipher.get(&i).unwrap().clone());

            ki_ciphertexts
                .into_iter()
                //.take((pp.t - 1) as usize)
                .take((pp.t) as usize)
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
        let (pp, secrect_keys) = ThresholdCLPubParams::simulate(3, 2);
        let mut rng = RandGen::new();
        let msg = Round1::new(&pp, &mut rng);
        let mut k_cipers = Vec::with_capacity(pp.n as usize);
        for (key, value) in &msg.k_ciphertexts {
            println!("{:?}", value.keys());
            let mut each_party_k_cipers = BTreeMap::new();
            for (id, cipher) in value {
                each_party_k_cipers.insert(
                    *id,
                    CipherText::new(
                        &cipher.c1().exp(&pp.cl, &secrect_keys[id].mpz()),
                        &cipher.c2(),
                    ),
                );
            }
            k_cipers.push(pp.interpolate_for_cl(&each_party_k_cipers).unwrap());
            // let k_ciphertext = value
            //     .values()
            //     .take(pp.t as usize)
            //     .cloned()
            //     .reduce(|acc, ct| {
            //         CipherText::new(
            //             &acc.c1().compose(&pp.cl, &ct.c1()),
            //             &acc.c2().compose(&pp.cl, &ct.c2()),
            //         )
            //     })
            //     .unwrap();
            // k_cipers.push(k_ciphertext);
        }

        for (i, item) in k_cipers.clone().iter().enumerate() {
            if i != 0 {
                assert_eq!(k_cipers[i - 1].c1(), k_cipers[i].c1());
                assert_eq!(k_cipers[i - 1].c2(), k_cipers[i].c2());
            }
        }
    }
}
