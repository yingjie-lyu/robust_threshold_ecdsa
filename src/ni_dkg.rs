use bicycl::{CL_HSMqk, CipherText, ClearText, Mpz, PublicKey, RandGen, SecretKey, QFI};
use curv::{
    arithmetic::{BasicOps, Converter, Samplable},
    cryptographic_primitives::hashing::merkle_tree::Proof,
    elliptic::curves::{Point, Scalar, Secp256k1},
    BigInt,
};
use ecdsa::elliptic_curve::point;
use futures::SinkExt;
use round_based::{
    rounds_router::simple_store::RoundInput, rounds_router::RoundsRouter, simulation::Simulation,
    Delivery, Mpc, MpcParty, Outgoing, PartyIndex, ProtocolMessage,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::ops::{Add, Mul};
use std::{collections::BTreeMap, ops::Deref};
use thiserror::Error;

use rayon::prelude::*;

use crate::lagrange_coeff;

type Zq = Scalar<Secp256k1>;
type G = Point<Secp256k1>;

type id = u8;

/// Polynomial defined over Zq, with coefficients in ascending order
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Polynomial {
    pub coeffs: Vec<Zq>,
}

impl Polynomial {
    pub fn new(coeffs: Vec<Zq>) -> Self {
        Polynomial { coeffs }
    }

    pub fn degree(&self) -> usize {
        self.coeffs.len() - 1
    }

    pub fn eval(&self, x: &Zq) -> Zq {
        let mut result = Zq::zero();
        for i in (0..self.coeffs.len()).rev() {
            result = result * x + &self.coeffs[i];
        }
        result
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CurvePolynomial {
    pub coeffs: Vec<G>,
}

impl CurvePolynomial {
    pub fn new(coeffs: Vec<G>) -> Self {
        CurvePolynomial { coeffs }
    }

    pub fn from_exp(polynomial: &Polynomial, generator: &G) -> Self {
        CurvePolynomial {
            coeffs: polynomial.coeffs.iter().map(|x| generator * x).collect(),
        }
    }

    pub fn eval(&self, x: &Zq) -> G {
        let mut result = G::zero();
        for i in (0..self.coeffs.len()).rev() {
            result = result * x + &self.coeffs[i];
        }
        result
    }
}


/// TODO: refactor to use the `CurvePolynomial` struct
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ClassGroupPolynomial {
    pub coefficients: Vec<QFI>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CLMultiRecvCiphertext {
    pub randomness: QFI,
    pub encryption: BTreeMap<id, QFI>,
}

impl CLMultiRecvCiphertext {
    pub fn new(
        group: &CL_HSMqk,
        rng: &mut RandGen,
        keyring: &CLKeyRing,
        plaintexts: &BTreeMap<id, Zq>,
    ) -> (Self, Mpz) {
        let r = rng.random_mpz(&group.encrypt_randomness_bound());

        let randomness = group.power_of_h(&r);

        let encryption = plaintexts
            .iter()
            .map(|(id, m)| {
                let m_mpz = Mpz::from(m);
                let f_pow_m = group.power_of_f(&m_mpz);
                let pk_pow_r = keyring[id].exponentiation(group, &r);
                (*id, f_pow_m.compose(&group, &pk_pow_r))
            })
            .collect();

        (
            CLMultiRecvCiphertext {
                randomness,
                encryption,
            },
            r,
        )
    }
}

type CLKeyRing = BTreeMap<id, PublicKey>;

pub struct PubParams {
    pub CL_group: CL_HSMqk,
    pub t: u8, // minimal number of parties to reconstruct the secret
    // any polynomial should be of degree t-1
    pub n: u8,
    pub CL_keyring: CLKeyRing,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PvssDealing {
    pub curve_polynomial: CurvePolynomial,
    pub encrypted_shares: CLMultiRecvCiphertext,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PvssNizk {
    pub e: Zq,
    pub z1: Mpz,
    pub z2: Zq,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct NiDkgOutput {
    pub parties: Vec<usize>, // ids of parties, used as indexes of all hashmaps
    pub share: Scalar<Secp256k1>,
    pub pk: Point<Secp256k1>,
    pub shares_cmt: BTreeMap<usize, Point<Secp256k1>>,
    pub encrypted_shares: Option<BTreeMap<usize, CipherText>>,
}

impl PvssDealing {
    pub fn new(
        pp: &PubParams,
        rng: &mut RandGen,
        curve_generator: &G,
    ) -> (Self, Mpz, Polynomial, BTreeMap<id, Zq>) {
        // make coefficients of a (t-1)-degree polynomial, and derive the shares
        let poly = Polynomial {
            coeffs: (0..pp.t).map(|_| Zq::random()).collect(),
        };

        let shares = (1..=pp.n).into_iter()
            .map(|id| (id, poly.eval(&Zq::from(id as u64))))
            .collect();

        let curve_polynomial = CurvePolynomial::from_exp(&poly, &curve_generator);

        let (encrypted_shares, r) =
            CLMultiRecvCiphertext::new(&pp.CL_group, rng, &pp.CL_keyring, &shares);

        (
            PvssDealing {
                curve_polynomial,
                encrypted_shares,
            },
            r,
            poly,
            shares,
        )
    }
}

impl PvssNizk {
    pub fn prove(
        dealing: &PvssDealing,
        r: &Mpz,
        shares: &BTreeMap<id, Zq>,
        pp: &PubParams,
        rng: &mut RandGen,
        curve_generator: &G,
    ) -> Self {
        let u1 = rng.random_mpz(&pp.CL_group.encrypt_randomness_bound());
        let u2 = Zq::random();
        let U1 = &pp.CL_group.power_of_h(&u1);
        let U2 = curve_generator * &u2;
        let gamma = PvssNizk::challenge1(pp, dealing, curve_generator);

        let mut U3 = &pp.CL_group.power_of_h(&Mpz::from(0u64));
        for (id, pk) in pp.CL_keyring.iter().rev() {
            U3 = &U3
                .exp(&pp.CL_group, &Mpz::from(&gamma))
                .compose(&pp.CL_group, &pk.elt());
        } // Horner's method for polynomial evaluation
        U3 = &U3
            .exp(&pp.CL_group, &u1)
            .compose(&pp.CL_group, &pp.CL_group.power_of_f(&Mpz::from(&u2)));

        let e = Self::challenge2(&gamma, &U1, &U2, &U3);

        let z1 = u1 + Mpz::from(&e) * r;
        let poly = Polynomial::new(shares.values().cloned().collect());
        let z2 = u2 + e * poly.eval(&gamma);

        PvssNizk { e, z1, z2 }
    }

    pub fn verify(&self, dealing: &PvssDealing, pp: &PubParams, curve_generator: &G) -> bool {
        let gamma = Self::challenge1(pp, dealing, curve_generator);

        // U1
        let mut U1 = &pp.CL_group.power_of_h(&self.z1);
        let U1d = &dealing
            .encrypted_shares
            .randomness
            .exp(&pp.CL_group, &Mpz::from(&-self.e));
        U1 = &U1.compose(&pp.CL_group, &U1d);

        // U2
        // curve polynomial defined by shares
        let shares_on_curve = (1..=pp.n).into_iter()
            .map(|id| dealing.curve_polynomial.eval(&Zq::from(id as u64)))
            .collect();
        let shares_curve_poly = CurvePolynomial::new(shares_on_curve);
        let U2 = curve_generator * &self.z2 - shares_curve_poly.eval(&gamma) * &self.e;

        // U3
        let mut U3 = &pp.CL_group.power_of_h(&Mpz::from(0 as u64));
        for (id, pk) in pp.CL_keyring.iter().rev() {
            U3 = &U3
                .exp(&pp.CL_group, &Mpz::from(&gamma))
                .compose(&pp.CL_group, &pk.elt());
        } // Horner's method for polynomial evaluation
        U3 = &U3
            .exp(&pp.CL_group, &self.z1)
            .compose(&pp.CL_group, &pp.CL_group.power_of_f(&Mpz::from(&self.z2)));

        let mut U3d = &pp.CL_group.power_of_h(&Mpz::from(0 as u64));
        for (id, E) in dealing.encrypted_shares.encryption.iter().rev() {
            U3d = &U3d
                .exp(&pp.CL_group, &Mpz::from(&gamma))
                .compose(&pp.CL_group, &E);
        } // Horner's method

        U3 = &U3.compose(&pp.CL_group, &U3d.exp(&pp.CL_group, &Mpz::from(&-self.e)));

        let e = Self::challenge2(&gamma, &U1, &U2, &U3);
        self.e == e
    }

    fn challenge1(pp: &PubParams, dealing: &PvssDealing, curve_generator: &G) -> Zq {
        let mut hasher = Sha256::new();
        hasher.update(&pp.CL_group.discriminant().to_bytes());
        for (id, pk) in &pp.CL_keyring {
            hasher.update(&id.to_be_bytes());
            hasher.update(&pk.to_bytes());
        }
        hasher.update(&dealing.encrypted_shares.randomness.to_bytes());
        for (id, enc) in &dealing.encrypted_shares.encryption {
            hasher.update(&id.to_be_bytes());
            hasher.update(&enc.to_bytes());
        }
        hasher.update(&curve_generator.to_bytes(true));
        for coeff in &dealing.curve_polynomial.coeffs {
            hasher.update(&coeff.to_bytes(true));
        }
        Zq::from_bytes(&hasher.finalize()[..16]).unwrap()
    }

    fn challenge2(gamma: &Zq, U1: &QFI, U2: &G, U3: &QFI) -> Zq {
        let hash = Sha256::new()
            .chain_update(&gamma.to_bigint().to_bytes())
            .chain_update(&U1.to_bytes())
            .chain_update(&U2.to_bytes(true))
            .chain_update(&U3.to_bytes())
            .finalize();
        Zq::from_bytes(&hash[..16]).unwrap()
    }
}

/// Aggregates multiple PVSS dealings to a single one.
/// The caller should verify the NIZKs and ensure that enough dealings are passed.
pub fn pvss_aggregate(pp: &PubParams, dealings: &[PvssDealing]) -> PvssDealing {
    let curve_polynomial = CurvePolynomial {
        coeffs: (0..pp.t)
            .map(|i| {
                let sum = dealings
                    .iter()
                    .map(|d| d.curve_polynomial.coeffs[i as usize])
                    .sum::<G>();
                sum
            })
            .collect(),
    };

    let randomness = dealings
        .iter()
        .map(|d| d.encrypted_shares.randomness)
        .reduce(|acc, R| acc.compose(&pp.CL_group, &R))
        .unwrap();

    let encryption = pp
        .CL_keyring
        .iter()
        .map(|(id, _)| {
            let sum = dealings
                .iter()
                .map(|d| {
                    d.encrypted_shares
                        .encryption
                        .get(id)
                        .unwrap_or(&pp.CL_group.power_of_h(&Mpz::from(0u64)))
                })
                .reduce(|acc, E| &acc.compose(&pp.CL_group, &E))
                .unwrap();
            (*id, *sum)
        })
        .collect();

    PvssDealing {
        curve_polynomial,
        encrypted_shares: CLMultiRecvCiphertext {
            randomness,
            encryption,
        },
    }
}

pub struct MtaDealing {
    pub randomness: QFI,
    pub encryption: BTreeMap<id, QFI>,
    pub curve_macs: BTreeMap<id, G>,
}

impl MtaDealing {
    /// the caller should remove disqualified parties from pvss_result
    /// the pairwise shares returned should be negated when later used
    pub fn new(
        pp: &PubParams,
        pvss_result: &PvssDealing,
        scalar: &Zq,
        curve_generator: &G,
    ) -> (Self, BTreeMap<id, Zq>) {
        let randomness = pvss_result
            .encrypted_shares
            .randomness
            .exp(&pp.CL_group, &Mpz::from(scalar));

        let multienc = &pvss_result.encrypted_shares.encryption;

        let pairwise_shares: BTreeMap<id, Zq> =
            multienc.iter().map(|(&id, _)| (id, Zq::random())).collect();

        let encryption = multienc
            .iter()
            .map(|(id, E)| {
                let res = E.exp(&pp.CL_group, &Mpz::from(scalar)).compose(
                    &pp.CL_group,
                    &pp.CL_group.power_of_f(&Mpz::from(&pairwise_shares[id])),
                );
                (*id, res)
            })
            .collect();

        let curve_macs = multienc
            .iter()
            .map(|(&id, _)| (id, pvss_result.curve_polynomial.eval(&Zq::from(id as u64))))
            .map(|(id, mac)| (id, scalar * mac + curve_generator * pairwise_shares[&id]))
            .collect();

        (
            MtaDealing {
                randomness,
                encryption,
                curve_macs,
            },
            pairwise_shares,
        )
    }
}

pub struct MtaNizk {
    pub e: Zq,
    pub z1: Mpz,
    pub z2: Zq,
}

impl MtaNizk {
    pub fn prove(
        pp: &PubParams,
        pvss_result: &PvssDealing,
        mta_result: &MtaDealing,
        curve_generator: &G,
        rng: &mut RandGen,
        scalar: &Zq,
        pairwise_shares: &BTreeMap<id, Zq>,
    ) -> Self {
        let u1 = rng.random_mpz(&pp.CL_group.encrypt_randomness_bound());
        let u2 = Zq::random();
        // let gamma = Self::challenge1(pp, pvss_result, mta_result, curve_generator);
        let gamma = Zq::random();

        let u1_modq = Zq::from(BigInt::from_bytes(&u1.to_bytes()) % Zq::group_order());
        let U1 = G::generator() * &u1_modq;
        let U2 = pvss_result
            .encrypted_shares
            .randomness
            .exp(&pp.CL_group, &u1);

        // U3
        let mut U3 = &pp.CL_group.power_of_h(&Mpz::from(0 as u64));
        for (id, _) in mta_result.encryption.iter().rev() {
            U3 = &U3
                .exp(&pp.CL_group, &Mpz::from(&gamma))
                .compose(&pp.CL_group, &pvss_result.encrypted_shares.encryption[&id]);
        } 
        U3 = &U3
            .exp(&pp.CL_group, &u1)
            .compose(&pp.CL_group, &pp.CL_group.power_of_f(&Mpz::from(&u2)));

        // compute original macs from pvss_result.curve_polynomial
        // TODO: profile, and may make sense to optimize by reusing the curve_macs from MtaDealing.new
        let orig_curve_macs = mta_result
            .curve_macs
            .iter()
            .map(|(&id, _)| (id, pvss_result.curve_polynomial.eval(&Zq::from(id as u64))));

        let mut U4 = G::zero();
        for (id, M) in orig_curve_macs.rev() {
            U4 = &U4 * &gamma + M;
        }
        U4 = U4 * &u1_modq + curve_generator * &u2;

        // let e = Self::challenge2(&gamma, &U1, &U2, &U3, &U4);
        let e = Zq::random();
        let z1 = &u1 + Mpz::from(&(&e * scalar));

        // computes z2. Since some indices may be missing (due to the parties dropping out),
        // we need to explicitly compute the polynomial evaluation using Horner's method
        let mut z2 = Zq::zero();
        for (id, b) in pairwise_shares.iter() {
            z2 = &z2 + b * &gamma;
        }
        z2 = &u2 + e * z2;

        Self { e, z1, z2 }
    }

    pub fn verify(
        &self,
        pp: &PubParams,
        pvss_result: &PvssDealing,
        mta_result: &MtaDealing,
        curve_generator: &G,
        scalar_pub: &G,
        pairwise_shares: &BTreeMap<id, Zq>,
    ) -> bool {
        // let gamma = Self::challenge1(pp, pvss_result, mta_result, curve_generator);
        let gamma = Zq::random();

        let z1_modq = Zq::from(BigInt::from_bytes(&self.z1.to_bytes()) % Zq::group_order());
        let U1 = G::generator() * z1_modq - scalar_pub * &self.e;

        // U2
        let U2d = mta_result.randomness.exp(&pp.CL_group, &Mpz::from(&-self.e));
        let U2 = pvss_result
            .encrypted_shares
            .randomness
            .exp(&pp.CL_group, &self.z1)
            .compose(&pp.CL_group, &U2d);

        // U3
        let mut U3 = &pp.CL_group.power_of_h(&Mpz::from(0 as u64));
        let mut U3d = &pp.CL_group.power_of_h(&Mpz::from(0 as u64));
        for (id, E) in mta_result.encryption.iter().rev() {
            U3 = &U3
                .exp(&pp.CL_group, &Mpz::from(&gamma))
                .compose(&pp.CL_group, &pvss_result.encrypted_shares.encryption[&id]);

            U3d = &U3d
                .exp(&pp.CL_group, &Mpz::from(&gamma))
                .compose(&pp.CL_group, &E);
        } 
        U3d = &U3d.exp(&pp.CL_group, &Mpz::from(&-self.e));
        U3 = &U3
            .exp(&pp.CL_group, &self.z1)
            .compose(&pp.CL_group, &U3d)
            .compose(&pp.CL_group, &pp.CL_group.power_of_f(&Mpz::from(&self.z2)));

        // U4
        let orig_curve_macs = mta_result
            .curve_macs
            .iter()
            .map(|(&id, _)| (id, pvss_result.curve_polynomial.eval(&Zq::from(id as u64))));

        let mut U4 = G::zero();
        for (id, M) in orig_curve_macs.rev() {
            U4 = &U4 * &gamma + M;
        }
        U4 = U4 * &self.z1 + curve_generator * &self.z2;

        let e = Zq::random();
        let z1 = &self.z1 + Mpz::from(&(&e * scalar));

        e == self.e
    }
}
// impl NiDkgOutput {
//     pub fn from_combining(
//         parties: Vec<usize>,
//         messages: &[PvssDealing],
//         myid: usize,
//         clgroup: CL_HSMqk,
//         rand_gen: &mut RandGen,
//         want_encrypted_shares: bool,
//         clpk: BTreeMap<usize, PublicKey>,
//         mysk: &SecretKey,
//     ) -> Self {
//         let honest_parties: Vec<usize> = parties
//             .into_iter()
//             .filter(|j| PvssNizk::verify(&messages[*j], &clgroup, &clpk))
//             .collect();

//         let mut x_i = Scalar::<Secp256k1>::from(0);
//         let mut X = Point::<Secp256k1>::zero();
//         let mut X_j_list = BTreeMap::<usize, Point<Secp256k1>>::new();

//         for &j in &honest_parties {
//             let ct = CipherText::new(&messages[j].rand_cmt, &messages[j].encrypted_shares[&myid]);
//             let pt = clgroup.decrypt(mysk, &ct);
//             x_i = x_i
//                 + Scalar::<Secp256k1>::from_bigint(&BigInt::from_bytes(
//                     pt.mpz().to_bytes().as_slice(),
//                 ));

//             X = X + &messages[j].poly_coeff_cmt[0];

//             // additively make the committed shares
//             for &l in &honest_parties {
//                 let addition = messages[j]
//                     .poly_coeff_cmt
//                     .iter()
//                     .enumerate()
//                     .map(|(k, A)| {
//                         A * Scalar::<Secp256k1>::from((l + 1).pow(k.try_into().unwrap()) as u64)
//                     })
//                     .sum::<Point<Secp256k1>>();
//                 let new_X_l = &*X_j_list.entry(l).or_insert(Point::<Secp256k1>::zero()) + addition;
//                 X_j_list.insert(l, new_X_l);
//             }
//         }

//         let mut c_j_list = BTreeMap::<usize, CipherText>::new();

//         // combine ciphertexts of shares which is expensive and therefore optional
//         if want_encrypted_shares {
//             for j in &honest_parties {
//                 let c_j = honest_parties
//                     .iter()
//                     .map(|&l| {
//                         CipherText::new(&messages[l].rand_cmt, &messages[l].encrypted_shares[j])
//                     })
//                     .reduce(|sum, ct| clgroup.add_ciphertexts(&clpk[j], &sum, &ct, rand_gen))
//                     .unwrap();
//                 c_j_list.insert(*j, c_j.clone());
//             }
//         }

//         NiDkgOutput {
//             parties: honest_parties,
//             share: x_i,
//             pk: X,
//             shares_cmt: X_j_list,
//             encrypted_shares: match want_encrypted_shares {
//                 true => Some(c_j_list),
//                 false => None,
//             },
//         }
//     }
// }

// below are code for testing

#[derive(Clone, Debug, PartialEq, ProtocolMessage, Serialize, Deserialize)]
pub enum Msg {
    PvssMsg((PvssDealing, PvssNizk)),
}

pub async fn protocol_ni_dkg<M>(
    party: M,
    myid: PartyIndex,
    t: usize,
    n: usize,
    clgroup: CL_HSMqk,
    mut rand_gen: RandGen,
    clpk: BTreeMap<usize, PublicKey>,
    mysk: SecretKey,
) -> Result<NiDkgOutput, Error<M::ReceiveError, M::SendError>>
where
    M: Mpc<ProtocolMessage = Msg>,
{
    let MpcParty { delivery, .. } = party.into_party();
    let (incoming, mut outgoing) = delivery.split();
    let mut rounds = RoundsRouter::<Msg>::builder();
    let round1 = rounds.add_round(RoundInput::<PvssDealing>::broadcast(
        myid,
        n.try_into().unwrap(),
    ));
    let mut rounds = rounds.listen(incoming);

    let my_ni_dkg_msg = PvssDealing::new(t, (0..n).collect(), &clgroup, &mut rand_gen, &clpk);

    outgoing
        .send(Outgoing::broadcast(Msg::PvssMsg(my_ni_dkg_msg.clone())))
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
        &mut rand_gen,
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
    let n: u16 = 6;

    let seed = Mpz::from(chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default());
    let mut rand_gen = RandGen::new();
    rand_gen.set_seed(&seed);

    let clgroup =
        CL_HSMqk::with_qnbits_rand_gen(50, 1, 150, &mut rand_gen, &Mpz::from(0i64), false);

    let mut clsk = BTreeMap::<usize, SecretKey>::new();
    let mut clpk = BTreeMap::<usize, PublicKey>::new();

    for i in 0..n {
        let sk_i = clgroup.secret_key_gen(&mut rand_gen);
        let pk_i = clgroup.public_key_gen(&sk_i);
        clsk.insert(i.into(), sk_i);
        clpk.insert(i.into(), pk_i);
    }
}

#[tokio::test]
async fn test_ni_dkg() {
    let n: u16 = 3;
    let t: usize = 2;

    let mut simulation = Simulation::<Msg>::new();
    let mut party_output = vec![];

    let seed = Mpz::from(chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default());
    let mut rand_gen = RandGen::new();
    rand_gen.set_seed(&seed);

    let clgroup =
        CL_HSMqk::with_qnbits_rand_gen(50, 1, 150, &mut rand_gen, &Mpz::from(0i64), false);

    let mut clsk = BTreeMap::<usize, SecretKey>::new();
    let mut clpk = BTreeMap::<usize, PublicKey>::new();

    for i in 0..n {
        let sk_i = clgroup.secret_key_gen(&mut rand_gen);
        let pk_i = clgroup.public_key_gen(&sk_i);
        clsk.insert(i.into(), sk_i);
        clpk.insert(i.into(), pk_i);
    }

    for i in 0..n {
        let party = simulation.add_party();
        let mysk = clsk[&(i as usize)].clone();

        let mut rand = RandGen::new();
        rand.set_seed(&rand_gen.random_mpz(&clgroup.encrypt_randomness_bound()));

        let output = protocol_ni_dkg(
            party,
            i,
            t,
            n.into(),
            clgroup.clone(),
            rand,
            clpk.clone(),
            mysk,
        );
        party_output.push(output);
    }

    let _output = futures::future::try_join_all(party_output).await.unwrap();
}
