#![allow(unused_imports)]

use std::collections::BTreeMap;
use std::ops::{Add, Mul};

use class_group::{
    primitives::cl_dl_public_setup::{
        decrypt, encrypt_predefined_randomness, eval_sum, CLGroup, Ciphertext, PK, SK,
    },
    BinaryQF,
};

use curv::{
    arithmetic::{BasicOps, Converter, Samplable},
    elliptic::curves::{Point, Scalar, Secp256k1},
    BigInt,
};

use futures::SinkExt;
use round_based::{
    rounds_router::simple_store::RoundInput, rounds_router::RoundsRouter, simulation::Simulation,
    Delivery, Mpc, MpcParty, Outgoing, PartyIndex, ProtocolMessage,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct NiDkgMsg {
    parties: Vec<usize>,
    rand_cmt: BinaryQF,
    encrypted_shares: BTreeMap<usize, BinaryQF>,
    poly_coeff_cmt: Vec<Point<Secp256k1>>,
    proof: ProofCorrectSharing,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ProofCorrectSharing {
    W: BinaryQF,
    X: Point<Secp256k1>,
    Y: BinaryQF,
    z_r: BigInt,
    z_s: Scalar<Secp256k1>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct NiDkgOutput {
    pub parties: Vec<usize>, // ids of parties, used as indexes of all hashmaps.
    pub share: Scalar<Secp256k1>,
    pub pk: Point<Secp256k1>,
    pub shares_cmt: BTreeMap<usize, Point<Secp256k1>>,
    pub encrypted_shares: Option<BTreeMap<usize, Ciphertext>>,
}

impl NiDkgMsg {
    fn verify(&self, _clgroup: &CLGroup, _clpk: BTreeMap<usize, PK>) -> bool {
        // challenges, from (common) inst

        // let eq1: bool = self
        //     .proof
        //     .W
        //     .compose(&self.rand_cmt.exp(&gamma_prime.to_bigint()))
        //     .reduce()
        //     == clgroup.gq.exp(&self.proof.z_r);

        // let eq2rhs = Point::<Secp256k1>::zero();

        true
    }

    pub fn new(t: usize, parties: Vec<usize>, clgroup: CLGroup, clpk: BTreeMap<usize, PK>) -> Self {
        // make coefficients of a (t-1)-degree polynomial, and derive the shares
        let coeffs: Vec<_> = (0..t).map(|_| Scalar::<Secp256k1>::random()).collect();

        let mut shares: BTreeMap<usize, Scalar<Secp256k1>> = BTreeMap::new();

        // lets set parties to 0..n by default, and use j+1 as the id in Shamir SS
        for j in &parties {
            let j_bigint = BigInt::from((j + 1) as u64);
            let s_j = coeffs
                .iter()
                .enumerate()
                .map(|(k, a)| a * Scalar::<Secp256k1>::from(j_bigint.pow(k.try_into().unwrap())))
                .sum();
            shares.insert(*j, s_j);
        }

        let (r, R) = clgroup.keygen();
        let encrypted_shares: BTreeMap<usize, BinaryQF> = shares
            .iter()
            .map(|(&j, share)| {
                (
                    j,
                    encrypt_predefined_randomness(&clgroup, &clpk[&j], &share, &r).c2,
                )
            })
            .collect();

        let poly_coeff_cmt: Vec<_> = coeffs
            .iter()
            .map(|a| a * Point::<Secp256k1>::generator())
            .collect();

        // NIZK proof; Groth21, Kate23
        let (rho, W) = clgroup.keygen();
        let alpha = Scalar::<Secp256k1>::random();
        let X = &alpha * Point::<Secp256k1>::generator();

        // challenge 1
        let mut gamma_hash = Sha256::new();
        clpk.iter()
            .for_each(|(_, pk)| gamma_hash.update(pk.0.to_bytes()));
        gamma_hash.update(R.0.to_bytes());
        encrypted_shares
            .iter()
            .for_each(|(_, ct)| gamma_hash.update(ct.to_bytes()));
        poly_coeff_cmt
            .iter()
            .for_each(|point| gamma_hash.update(point.to_bytes(true)));
        let gamma_hash = gamma_hash.finalize();

        let gamma = BigInt::from_bytes(&gamma_hash[..16]);

        // EXPENSIVELY calculates Y in proof
        // todo: check if reduce() reduces overhead.

        let temp_pk = clpk
            .iter()
            .map(|(j, pk)| pk.0.exp(&gamma.pow((j + 1).try_into().unwrap())).reduce())
            .reduce(|prod, pk| prod.compose(&pk).reduce())
            .unwrap();

        let Y = encrypt_predefined_randomness(&clgroup, &PK(temp_pk), &alpha, &rho).c2;

        // challenge 2
        let mut gamma_prime_hash = Sha256::new();
        gamma_prime_hash.update(gamma_hash);
        gamma_prime_hash.update(W.0.to_bytes());
        gamma_prime_hash.update(X.to_bytes(true));
        gamma_prime_hash.update(Y.to_bytes());
        let gamma_prime_hash = gamma_prime_hash.finalize();

        let gamma_prime = BigInt::from_bytes(&gamma_prime_hash[..16]);

        let z_r = &r.0 * &gamma_prime + &rho.0;

        let z_s = shares
            .iter()
            .map(|(j, s)| {
                s.mul(Scalar::<Secp256k1>::from_bigint(
                    &gamma.pow((j + 1).try_into().unwrap()),
                ))
            })
            .sum::<Scalar<Secp256k1>>()
            .mul(Scalar::<Secp256k1>::from_bigint(&gamma_prime))
            .add(&alpha);

        let W = W.0;
        let rand_cmt = R.0;
        let proof = ProofCorrectSharing { W, X, Y, z_r, z_s };

        NiDkgMsg {
            parties,
            rand_cmt,
            encrypted_shares,
            poly_coeff_cmt,
            proof,
        }
    }
}

impl NiDkgOutput {
    pub fn from_combining(
        parties: Vec<usize>,
        messages: &Vec<NiDkgMsg>,
        myid: usize,
        clgroup: CLGroup,
        want_encrypted_shares: bool,
        clpk: BTreeMap<usize, PK>,
        mysk: &SK,
    ) -> Self {
        let honest_parties: Vec<usize> = parties
            .into_iter()
            .filter(|j| messages[*j].verify(&clgroup, clpk.clone()))
            .collect();

        let mut x_i = Scalar::<Secp256k1>::from(0);
        let mut X = Point::<Secp256k1>::zero();
        let mut X_j_list = BTreeMap::<usize, Point<Secp256k1>>::new();

        for &j in &honest_parties {
            x_i = x_i
                + decrypt(
                    &clgroup,
                    mysk,
                    &Ciphertext {
                        c1: messages[j].rand_cmt.clone(),
                        c2: messages[j].encrypted_shares[&myid].clone(),
                    },
                );
            X = X + &messages[j].poly_coeff_cmt[0];

            // additively make the committed shares
            for &l in &honest_parties {
                let addition = messages[j]
                    .poly_coeff_cmt
                    .iter()
                    .enumerate()
                    .map(|(k, A)| {
                        A * Scalar::<Secp256k1>::from((l + 1).pow(k.try_into().unwrap()) as u64)
                    })
                    .sum::<Point<Secp256k1>>();
                let new_X_l = &*X_j_list.entry(l).or_insert(Point::<Secp256k1>::zero()) + addition;
                X_j_list.insert(l, new_X_l);
            }
        }

        let mut c_j_list = BTreeMap::<usize, Ciphertext>::new();

        // combine ciphertexts of shares which is expensive and therefore optional
        if want_encrypted_shares {
            for j in &honest_parties {
                let c_j = honest_parties
                    .iter()
                    .map(|&l| Ciphertext {
                        c1: messages[l].rand_cmt.clone(),
                        c2: messages[l].encrypted_shares[&j].clone(),
                    })
                    .reduce(|sum, ct| eval_sum(&sum, &ct))
                    .unwrap();
                c_j_list.insert(*j, c_j.clone());
            }
        }

        NiDkgOutput {
            parties: honest_parties,
            share: x_i,
            pk: X,
            shares_cmt: X_j_list,
            encrypted_shares: match want_encrypted_shares {
                true => Some(c_j_list),
                false => None,
            },
        }
    }
}



// below are code for testing

#[derive(Clone, Debug, PartialEq, ProtocolMessage, Serialize, Deserialize)]
pub enum Msg {
    NiDkgMsg(NiDkgMsg),
}

pub async fn protocol_ni_dkg<M>(
    party: M,
    myid: PartyIndex,
    t: usize,
    n: usize,
    clgroup: CLGroup,
    clpk: BTreeMap<usize, PK>,
    mysk: SK,
) -> Result<NiDkgOutput, Error<M::ReceiveError, M::SendError>>
where
    M: Mpc<ProtocolMessage = Msg>,
{
    let MpcParty { delivery, .. } = party.into_party();
    let (incoming, mut outgoing) = delivery.split();
    let mut rounds = RoundsRouter::<Msg>::builder();
    let round1 = rounds.add_round(RoundInput::<NiDkgMsg>::broadcast(
        myid,
        n.try_into().unwrap(),
    ));
    let mut rounds = rounds.listen(incoming);

    let my_ni_dkg_msg = NiDkgMsg::new(t, (0..n).collect(), clgroup.clone(), clpk.clone());

    outgoing
        .send(Outgoing::broadcast(Msg::NiDkgMsg(my_ni_dkg_msg.clone())))
        .await
        .unwrap();

    let all_messages = rounds
        .complete(round1)
        .await
        .unwrap()
        .into_vec_including_me(my_ni_dkg_msg);

    Ok(NiDkgOutput::from_combining(
        (0..n).collect(),
        &all_messages,
        myid.into(),
        clgroup,
        false,
        clpk,
        &mysk,
    ))
}

#[derive(Debug, Error)]
pub enum Error<RecvErr, SendErr> {
    Round1Send(SendErr),
    Round1Receive(RecvErr),
}

#[tokio::test]
async fn test_cl_keygen_overhead() {
    let n: u16 = 5;

    let clgroup = CLGroup::new_from_setup(&1600, &BigInt::strict_sample(1500));

    let mut clsk = BTreeMap::<usize, SK>::new();
    let mut clpk = BTreeMap::<usize, PK>::new();

    for i in 0..n {
        let (sk_i, pk_i) = clgroup.keygen();
        clsk.insert(i.into(), sk_i);
        clpk.insert(i.into(), pk_i);
    }
}

#[tokio::test]
async fn test_ni_dkg() {
    let n: u16 = 3;
    let t: usize = 3;

    let mut simulation = Simulation::<Msg>::new();
    let mut party_output = vec![];
    let clgroup = CLGroup::new_from_setup(&1600, &BigInt::strict_sample(1500));

    let mut clsk = BTreeMap::<usize, SK>::new();
    let mut clpk = BTreeMap::<usize, PK>::new();

    for i in 0..n {
        let (sk_i, pk_i) = clgroup.keygen();
        clsk.insert(i.into(), sk_i);
        clpk.insert(i.into(), pk_i);
    }

    for i in 0..n {
        let party = simulation.add_party();
        let mysk = clsk[&(i as usize)].clone();
        let output = protocol_ni_dkg(party, i, t, n.into(), clgroup.clone(), clpk.clone(), mysk);
        party_output.push(output);
    }

    let _output = futures::future::try_join_all(party_output).await.unwrap();
}
