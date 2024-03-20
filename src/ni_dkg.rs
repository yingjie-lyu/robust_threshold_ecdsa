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

use crate::lagrange_coeff;

type Zq = Scalar<Secp256k1>;
type G = Point<Secp256k1>;

type id = u8;

/// Polynomial defined over Zq, with coefficients in ascending order
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Polynomial {
    pub coefficients: Vec<Zq>,
}

impl Polynomial {
    pub fn new(coefficients: Vec<Zq>) -> Self {
        Polynomial { coefficients }
    }

    pub fn degree(&self) -> usize {
        self.coefficients.len() - 1
    }

    pub fn eval(&self, x: Zq) -> Zq {
        let mut result = Zq::zero();
        for i in (0..self.coefficients.len()).rev() {
            result = result * &x + &self.coefficients[i];
        }
        result
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CurvePolynomial {
    pub coefficients: Vec<G>,
}

impl CurvePolynomial {
    pub fn new(coefficients: Vec<G>) -> Self {
        CurvePolynomial { coefficients }
    }

    pub fn from_exp(polynomial: &Polynomial, generator: &G) -> Self {
        CurvePolynomial {
            coefficients: polynomial
                .coefficients
                .iter()
                .map(|x| generator * x)
                .collect(),
        }
    }

    pub fn eval(&self, x: Zq) -> G {
        let mut result = G::zero();
        for i in (0..self.coefficients.len()).rev() {
            result = result * &x + &self.coefficients[i];
        }
        result
    }
}

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
    CL_group: CL_HSMqk,
    t: u8, // minimal number of parties to reconstruct the secret
    // any polynomial should be of degree t-1
    n: u8,
    CL_keyring: CLKeyRing,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PvssDealing {
    curve_polynomial: CurvePolynomial,
    encrypted_shares: CLMultiRecvCiphertext,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PvssNizk {
    e: Zq,
    z1: Mpz,
    z2: Zq,
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
        pub_params: &PubParams,
        rng: &mut RandGen,
        curve_generator: &G,
    ) -> (Self, Mpz, Polynomial, BTreeMap<id, Zq>) {
        // make coefficients of a (t-1)-degree polynomial, and derive the shares
        let coeffs: Vec<_> = (0..*&pub_params.t).map(|_| Zq::random()).collect();
        let poly = Polynomial::new(coeffs);

        let shares = pub_params
            .CL_keyring
            .iter()
            .map(|(id, CLpk)| (*id, poly.eval(Zq::from(*id as u64))))
            .collect();

        let curve_polynomial = CurvePolynomial::from_exp(&poly, &curve_generator);

        let (multienc, r) =
            CLMultiRecvCiphertext::new(&pub_params.CL_group, rng, &pub_params.CL_keyring, &shares);

        (
            PvssDealing {
                curve_polynomial,
                encrypted_shares: multienc,
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
        pub_params: &PubParams,
        rng: &mut RandGen,
        curve_generator: &G,
    ) -> Self {
        let u1 = rng.random_mpz(&pub_params.CL_group.encrypt_randomness_bound());
        let u2 = Zq::random();
        let U1 = &pub_params.CL_group.power_of_h(&u1);
        let U2 = *&curve_generator * &u2;
        let gamma = PvssNizk::challenge1(pub_params, dealing, curve_generator);

        let mut U3 = &pub_params.CL_group.power_of_h(&Mpz::from(0 as u64));
        for (id, pk) in pub_params.CL_keyring.into_iter().rev() {
            U3 = &U3
                .exp(&pub_params.CL_group, &Mpz::from(&gamma))
                .compose(&pub_params.CL_group, &pk.elt());
        }
        U3 = &U3.exp(&pub_params.CL_group, &u1).compose(
            &pub_params.CL_group,
            &pub_params.CL_group.power_of_f(&Mpz::from(&u2)),
        );

        let mut hash = Sha256::new()
            .chain_update(&gamma.to_bigint().to_bytes())
            .chain_update(&U1.to_bytes())
            .chain_update(&U2.to_bytes(true))
            .chain_update(&U3.to_bytes())
            .finalize();
        let e = Zq::from_bytes(&hash[..16]).unwrap();

        let z1 = u1 + Mpz::from(&e) * r;
        let poly = Polynomial::new(shares.values().cloned().collect());
        let z2 = u2 + e * poly.eval(*&gamma);

        PvssNizk { e, z1, z2 }
    }

    fn verify(
        proof: &PvssNizk,
        dealing: &PvssDealing,
        pub_params: &PubParams,
        curve_generator: &G,
    ) -> bool {
        let gamma = PvssNizk::challenge1(pub_params, dealing, curve_generator);

        let U1 = &pub_params.CL_group.power_of_h(&proof.z1).compose(&pub_params.CL_group, &proof.e);

        let U3 = pub_params
            .CL_keyring
            .iter()
            .rev()
            .fold(
                pub_params.CL_group.power_of_h(&Mpz::from(0 as u64)),
                |acc, (id, pk)| {
                    acc.exp(&pub_params.CL_group, &Mpz::from(&gamma))
                        .compose(&pub_params.CL_group, &pk.elt())
                },
            )
            .exp(&pub_params.CL_group, &proof.z1)
            .compose(
                &pub_params.CL_group,
                &pub_params.CL_group.power_of_f(&Mpz::from(&proof.z2)),
            );

        let mut hash = Sha256::new()
            .chain_update(&gamma.to_bigint().to_bytes())
            .chain_update(&proof.e.to_bigint().to_bytes())
            .chain_update(&U3.to_bytes())
            .finalize();
        let e_prime = Zq::from_bytes(&hash[..16]).unwrap();

        proof.e == e_prime
    }
}

impl NiDkgOutput {
    pub fn from_combining(
        parties: Vec<usize>,
        messages: &[PvssDealing],
        myid: usize,
        clgroup: CL_HSMqk,
        rand_gen: &mut RandGen,
        want_encrypted_shares: bool,
        clpk: BTreeMap<usize, PublicKey>,
        mysk: &SecretKey,
    ) -> Self {
        let honest_parties: Vec<usize> = parties
            .into_iter()
            .filter(|j| PvssNizk::verify(&messages[*j], &clgroup, &clpk))
            .collect();

        let mut x_i = Scalar::<Secp256k1>::from(0);
        let mut X = Point::<Secp256k1>::zero();
        let mut X_j_list = BTreeMap::<usize, Point<Secp256k1>>::new();

        for &j in &honest_parties {
            let ct = CipherText::new(&messages[j].rand_cmt, &messages[j].encrypted_shares[&myid]);
            let pt = clgroup.decrypt(mysk, &ct);
            x_i = x_i
                + Scalar::<Secp256k1>::from_bigint(&BigInt::from_bytes(
                    pt.mpz().to_bytes().as_slice(),
                ));

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

        let mut c_j_list = BTreeMap::<usize, CipherText>::new();

        // combine ciphertexts of shares which is expensive and therefore optional
        if want_encrypted_shares {
            for j in &honest_parties {
                let c_j = honest_parties
                    .iter()
                    .map(|&l| {
                        CipherText::new(&messages[l].rand_cmt, &messages[l].encrypted_shares[j])
                    })
                    .reduce(|sum, ct| clgroup.add_ciphertexts(&clpk[j], &sum, &ct, rand_gen))
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

impl PvssNizk {
    pub fn old_prove(
        clgroup: &CL_HSMqk,
        rand_gen: &mut RandGen,
        clpk: &BTreeMap<usize, PublicKey>,
        shares: &BTreeMap<usize, Scalar<Secp256k1>>,
        poly_coeff_cmt: &[Point<Secp256k1>],
        r: &SecretKey,
        rand_cmt: &QFI,
        encrypted_shares: &BTreeMap<usize, QFI>,
    ) -> PvssNizk {
        let rho = clgroup.secret_key_gen(rand_gen);
        let W = clgroup.public_key_gen(&rho);
        let W = W.elt();

        let alpha = Scalar::<Secp256k1>::random();
        let X = &alpha * Point::<Secp256k1>::generator();

        // challenge 1
        let gamma = PvssNizk::challenge1(clpk, rand_cmt, encrypted_shares, poly_coeff_cmt);

        // the Y in proof is rather expensive
        let temp_pk = clpk
            .iter()
            .map(|(j, pk)| pk.exponentiation(clgroup, &gamma.pow((j + 1) as u64)))
            .reduce(|prod, pk| prod.compose(clgroup, &pk))
            .unwrap();

        let pk = PublicKey::from_qfi(clgroup, &temp_pk);
        let alpha_mpz = Mpz::from_bytes(alpha.to_bigint().to_bytes().as_slice());
        let Y = clgroup
            .encrypt_with_r(&pk, &ClearText::with_mpz(clgroup, &alpha_mpz), &rho.mpz())
            .c2();

        let gamma_prime = PvssNizk::challenge_gamma_prime(&gamma, &W, &X, &Y);

        let z_r = r.mpz() * &gamma_prime + rho.mpz();

        let z_s = shares
            .iter()
            .map(|(j, s)| {
                s.mul(Scalar::<Secp256k1>::from_bigint(&BigInt::from_bytes(
                    &gamma.pow((j + 1) as u64).to_bytes(),
                )))
            })
            .sum::<Scalar<Secp256k1>>()
            .mul(Scalar::<Secp256k1>::from_bigint(&BigInt::from_bytes(
                &gamma_prime.to_bytes(),
            )))
            .add(&alpha);

        PvssNizk { W, X, Y, z_r, z_s }
    }

    pub fn old_verify(
        msg: &PvssDealing,
        clgroup: &CL_HSMqk,
        clpk: &BTreeMap<usize, PublicKey>,
    ) -> bool {
        let gamma = PvssNizk::challenge1(
            clpk,
            &msg.rand_cmt,
            &msg.encrypted_shares,
            &msg.poly_coeff_cmt,
        );
        let gamma_prime =
            PvssNizk::challenge_gamma_prime(&gamma, &msg.proof.W, &msg.proof.X, &msg.proof.Y);

        // check equation 1
        if msg
            .proof
            .W
            .compose(&clgroup, &msg.rand_cmt.exp(&clgroup, &gamma_prime))
            != clgroup.power_of_h(&msg.proof.z_r)
        {
            return false;
        }

        // check equation 2
        let eq2in: Point<Secp256k1> = msg
            .poly_coeff_cmt
            .iter()
            .enumerate()
            .map(|(k, A)| {
                A * &msg
                    .parties
                    .iter()
                    .map(|j| j + 1)
                    .map(|j| {
                        BigInt::from(j.pow(k.try_into().unwrap()) as u64)
                            * BigInt::from_bytes(gamma.pow(j as u64).to_bytes().as_slice())
                    })
                    .map(|exp| Scalar::<Secp256k1>::from_bigint(&exp))
                    .sum()
            })
            .sum();
        if &msg.proof.X
            + eq2in * Scalar::<Secp256k1>::from_bigint(&BigInt::from_bytes(&gamma_prime.to_bytes()))
            != Point::<Secp256k1>::generator() * &msg.proof.z_s
        {
            return false;
        }

        //check equation 3
        let temp_pk = clpk
            .iter()
            .map(|(j, pk)| pk.exponentiation(clgroup, &gamma.pow((j + 1) as u64)))
            .reduce(|prod, pk| prod.compose(clgroup, &pk))
            .unwrap();

        let pk = PublicKey::from_qfi(clgroup, &temp_pk);
        let msg_mpz = Mpz::from_bytes(msg.proof.z_s.to_bigint().to_bytes().as_slice());
        let eq3rhs = clgroup
            .encrypt_with_r(&pk, &ClearText::with_mpz(clgroup, &msg_mpz), &msg.proof.z_r)
            .c2();

        let eq3in = msg
            .parties
            .iter()
            .map(|&j| {
                msg.encrypted_shares[&j].exp(clgroup, &gamma.pow((j + 1).try_into().unwrap()))
            })
            .reduce(|prod, item| prod.compose(clgroup, &item))
            .unwrap();
        if msg
            .proof
            .Y
            .compose(clgroup, &eq3in.exp(clgroup, &gamma_prime))
            != eq3rhs
        {
            return false;
        }

        // all checks passed
        true
    }

    pub fn challenge1(pub_params: &PubParams, dealing: &PvssDealing, curve_generator: &G) -> Zq {
        let mut hasher = Sha256::new();
        hasher.update(&pub_params.CL_group.discriminant().to_bytes());
        for (id, pk) in &pub_params.CL_keyring {
            hasher.update(&id.to_be_bytes());
            hasher.update(&pk.to_bytes());
        }

        hasher.update(&dealing.encrypted_shares.randomness.to_bytes());
        for (id, enc) in &dealing.encrypted_shares.encryption {
            hasher.update(&id.to_be_bytes());
            hasher.update(&enc.to_bytes());
        }

        hasher.update(&curve_generator.to_bytes(true));

        for coeff in &dealing.curve_polynomial.coefficients {
            hasher.update(&coeff.to_bytes(true));
        }

        let gamma = hasher.finalize();

        Zq::from_bytes(&gamma[..16]).unwrap()
    }

    pub fn challenge_gamma_prime(gamma: &Mpz, W: &QFI, X: &Point<Secp256k1>, Y: &QFI) -> Mpz {
        let mut hasher = Sha256::new();
        hasher.update(gamma.to_bytes());
        hasher.update(W.to_bytes());
        hasher.update(X.to_bytes(true));
        hasher.update(Y.to_bytes());
        let gamma_prime_hash = hasher.finalize();

        Mpz::from_bytes(&gamma_prime_hash[..16])
    }
}

// below are code for testing

#[derive(Clone, Debug, PartialEq, ProtocolMessage, Serialize, Deserialize)]
pub enum Msg {
    NiDkgMsg(PvssDealing),
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
