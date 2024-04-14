use super::*;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Round2 {
    pub ggama_ciphertexts: BTreeMap<u8, BTreeMap<u8, ElGamalCiphertext>>,
    pub xk_ciphertexts: BTreeMap<u8, BTreeMap<u8, CipherText>>,
    pub gammak_ciphertexts: BTreeMap<u8, BTreeMap<u8, CipherText>>,

    pub k_ciphertexts: BTreeMap<u8, CipherText>,
}

impl Round2 {
    pub fn new(
        pp: &ThresholdCLPubParams,
        threshold_pk: &ThresholdPubKey,
        x_shares: &BTreeMap<Id, Zq>,
        round1: &Round1,
        rng: &mut RandGen,
    ) -> Self {
        let mut msgs = Vec::with_capacity(pp.n as usize);

        let mut k_ciphertexts = BTreeMap::new();

        for (id, map) in round1.k_ciphertexts.clone() {
            let k_ciphertext = map
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

            k_ciphertexts.insert(id, k_ciphertext.clone());

            let xi_k_ciphertext = CipherText::new(
                &k_ciphertext.c1().exp(&pp.cl, &Mpz::from(&x_shares[&id])),
                &k_ciphertext.c2().exp(&pp.cl, &Mpz::from(&x_shares[&id])),
            );

            let gammai = Zq::random();
            let (ggamai_ciphertext, eg_rand) = ElGamalCiphertext::new(&gammai, &threshold_pk.pk);

            let gammaik_ciphertext = CipherText::new(
                &k_ciphertext.c1().exp(&pp.cl, &Mpz::from(&gammai)),
                &k_ciphertext.c2().exp(&pp.cl, &Mpz::from(&gammai)),
            );
            msgs.push((id, ggamai_ciphertext, xi_k_ciphertext, gammaik_ciphertext));
        }

        let mut ggama_ciphertexts = BTreeMap::new();
        let mut xk_ciphertexts = BTreeMap::new();
        let mut gammak_ciphertexts = BTreeMap::new();

        for i in 1..=pp.n {
            let mut each_party_ggamai_ciphertext = BTreeMap::new();
            let mut each_party_xi_k_ciphertext = BTreeMap::new();
            let mut each_party_gammaik_ciphertext = BTreeMap::new();

            let filter_verify_proof_msgs: Vec<_> = msgs
                .iter()
                .filter_map(
                    |(j, ggamai_ciphertext, xi_k_ciphertext, gammaik_ciphertext)| {
                        //if proof.verify(pp, &pp.pk, ki_ciphertext) && *j != i {
                        if true {
                            Some((
                                *j,
                                ggamai_ciphertext.clone(),
                                xi_k_ciphertext.clone(),
                                gammaik_ciphertext.clone(),
                            ))
                        } else {
                            None
                        }
                    },
                )
                .collect();

            filter_verify_proof_msgs
                .into_iter()
                //.take((pp.t - 1) as usize)
                .take((pp.t) as usize)
                .for_each(
                    |(j, ggamai_ciphertext, xi_k_ciphertext, gammaik_ciphertext)| {
                        each_party_ggamai_ciphertext.insert(j, ggamai_ciphertext);
                        each_party_xi_k_ciphertext.insert(j, xi_k_ciphertext);
                        each_party_gammaik_ciphertext.insert(j, gammaik_ciphertext);
                    },
                );

            ggama_ciphertexts.insert(i, each_party_ggamai_ciphertext);
            xk_ciphertexts.insert(i, each_party_xi_k_ciphertext);
            gammak_ciphertexts.insert(i, each_party_gammaik_ciphertext);
        }
        Self {
            ggama_ciphertexts,
            xk_ciphertexts,
            gammak_ciphertexts,
            k_ciphertexts,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_round2() {
        let n = 3;
        let t = 2;
        let (pp, secrect_keys) = ThresholdCLPubParams::simulate(n, t);
        let (threshold_pk, x_shares, x) = ThresholdPubKey::simulate(n, t);
        let mut rng = RandGen::new();
        let round1_msg = Round1::new(&pp, &mut rng);
        let mut ggama_ciphertexts = Vec::with_capacity(pp.n as usize);
        let mut xk_ciphertexts = Vec::with_capacity(pp.n as usize);
        let mut gammak_ciphertexts = Vec::with_capacity(pp.n as usize);

        let round2_msg = Round2::new(&pp, &threshold_pk, &x_shares, &round1_msg, &mut rng);

        for (key, value) in &round2_msg.ggama_ciphertexts {
            let ggama_ciphertext = value
                .values()
                .take(pp.t as usize)
                .cloned()
                .reduce(|acc, ct| ElGamalCiphertext {
                    c1: acc.c1 + ct.c1,
                    c2: acc.c2 + ct.c2,
                })
                .unwrap();
            ggama_ciphertexts.push(ggama_ciphertext);
        }

        for (i, item) in ggama_ciphertexts.clone().iter().enumerate() {
            if i != 0 {
                assert_eq!(ggama_ciphertexts[i - 1].c1, ggama_ciphertexts[i].c1);
                assert_eq!(ggama_ciphertexts[i - 1].c2, ggama_ciphertexts[i].c2);
            }
        }

        for (key, value) in &round2_msg.xk_ciphertexts {
            // println!("{:?}", value.keys());
            let xk_ciphertext = pp.interpolate_for_cl(&value).unwrap();
            xk_ciphertexts.push(xk_ciphertext);
        }

        for (i, item) in xk_ciphertexts.clone().iter().enumerate() {
            if i != 0 {
                assert_eq!(xk_ciphertexts[i - 1].c1(), xk_ciphertexts[i].c1());
                assert_eq!(xk_ciphertexts[i - 1].c2(), xk_ciphertexts[i].c2());
            }
        }

        for (key, value) in &round2_msg.gammak_ciphertexts {
            let gammak_ciphertext = value
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
            gammak_ciphertexts.push(gammak_ciphertext);
        }

        for (i, item) in gammak_ciphertexts.clone().iter().enumerate() {
            if i != 0 {
                assert_eq!(gammak_ciphertexts[i - 1].c1(), gammak_ciphertexts[i].c1());
                assert_eq!(gammak_ciphertexts[i - 1].c2(), gammak_ciphertexts[i].c2());
            }
        }
    }
}
