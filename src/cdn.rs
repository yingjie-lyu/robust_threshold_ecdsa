use std::{collections::BTreeMap, ops::Add, time::Instant};

use bicycl::{CL_HSMqk, CipherText, ClearText, Mpz, PublicKey, RandGen, SecretKey, QFI};
use curv::{arithmetic::Converter, cryptographic_primitives::proofs::low_degree_exponent_interpolation, elliptic::curves::Secp256k1, BigInt};
use futures::{stream::{futures_unordered::Iter, once}, SinkExt};
use itertools::Itertools;
use rayon::iter::{ParallelBridge, ParallelIterator};
use thiserror::Error;
use crate::{spdz::{OpenPowerMsg, ThresholdPubKey}, utils::*};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use round_based::{
    rounds_router::{
        errors::OtherError, simple_store::{RoundInput, RoundInputError}, CompleteRoundError, RoundsRouter
    },
    simulation::Simulation,
};
use round_based::{Delivery, Mpc, MpcParty, MsgId, Outgoing, PartyIndex, ProtocolMessage};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ElGamalCiphertext {
    pub c1: G,
    pub c2: G,
}

impl ElGamalCiphertext {
    pub fn new(m: &Zq, pk: &G) -> (Self, Zq) {
        let r = Zq::random();
        let c1 = G::generator() * &r;
        let c2 = G::generator() * m + pk * &r;
        ( ElGamalCiphertext { c1, c2 }, r )
    }

}

impl Add for ElGamalCiphertext {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        ElGamalCiphertext {
            c1: self.c1 + other.c1,
            c2: self.c2 + other.c2,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CLEGDoubleEncNizk {
    pub e: Zq,
    pub z1: Mpz,
    pub z2: Zq,
    pub z3: Zq,
}

impl CLEGDoubleEncNizk {
    pub fn prove(pp: &ThresholdCLPubParams, rng: &mut RandGen, clpk: &PublicKey, clct: &CipherText, ecpk: &G, egct: &ElGamalCiphertext, m: &Zq, cl_rand: &Mpz, eg_rand: &Zq) -> Self {
        let u1 = rng.random_mpz(&pp.cl.encrypt_randomness_bound());
        let u2 = Zq::random();
        let u3 = Zq::random();

        let U1 = pp.cl.power_of_h(&u1);
        let U2 = pp.cl.power_of_f(&Mpz::from(&u2))
                           .compose(&pp.cl, &clpk.exponentiation(&pp.cl, &u1));
        let U3 = G::generator() * &u3;
        let U4 = G::generator() * &u2 + ecpk * &u3;

        let e = Self::challenge(clpk, clct, ecpk, egct, &U1, &U2, &U3, &U4);
        let z1 = &u1 + Mpz::from(&e) * cl_rand;
        let z2 = &u2 + &e * m;
        let z3 = &u3 + &e * eg_rand;

        Self { e, z1, z2, z3 }
    }

    pub fn verify(&self, pp: &ThresholdCLPubParams, clpk: &PublicKey, clct: &CipherText, ecpk: &G, egct: &ElGamalCiphertext) -> bool {
        let U1 = pp.cl.power_of_h(&self.z1).compose(&pp.cl, &clct.c1().exp(&pp.cl, &-Mpz::from(&self.e)));
        let U2 = pp.cl.power_of_f(&Mpz::from(&self.z2))
                           .compose(&pp.cl, &clpk.exponentiation(&pp.cl, &self.z1))
                           .compose(&pp.cl, &clct.c2().exp(&pp.cl, &-Mpz::from(&self.e)));
        let U3 = G::generator() * &self.z3 - &egct.c1 * &self.e;
        let U4 = G::generator() * &self.z2 + ecpk * &self.z3 - &egct.c2 * &self.e;

        let e = Self::challenge(clpk, clct, ecpk, egct, &U1, &U2, &U3, &U4);
        e == self.e
    }

    fn challenge(clpk: &PublicKey, clct: &CipherText, ecpk: &G, egct: &ElGamalCiphertext,
                 U1: &QFI, U2: &QFI, U3: &G, U4: &G) -> Zq {
        let mut hasher = Sha256::new();

        for item in 
            &[clpk.to_bytes(),
            clct.c1().to_bytes(),
            clct.c2().to_bytes(),
            ecpk.to_bytes(false).to_vec(),
            egct.c1.to_bytes(false).to_vec(),
            egct.c2.to_bytes(false).to_vec(),
            U1.to_bytes(),
            U2.to_bytes(),
            U3.to_bytes(false).to_vec(),
            U4.to_bytes(false).to_vec()]
        {
            hasher.update(item);
        }

        Zq::from_bigint(&BigInt::from_bytes(&hasher.finalize()[..16]))
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct NonceProposalMsg {
    pub ki_ciphertext: CipherText,
    pub Ri_ciphertext: ElGamalCiphertext,
    pub proof: CLEGDoubleEncNizk,
}

impl NonceProposalMsg {
    pub fn new(pp: &ThresholdCLPubParams, rng: &mut RandGen, ecpk: &G) -> Self {
        let ki = Zq::random();
        let cl_rand = rng.random_mpz(&pp.cl.encrypt_randomness_bound());
        let c1 = pp.cl.power_of_h(&cl_rand);
        let c2 = pp.cl.power_of_f(&Mpz::from(&ki)).compose(&pp.cl, &pp.pk.exponentiation(&pp.cl, &cl_rand));
        let ki_ciphertext = CipherText::new(&c1, &c2);
        let (Ri_ciphertext, eg_rand) = ElGamalCiphertext::new(&ki, ecpk);

        let proof = CLEGDoubleEncNizk::prove(pp, rng, &pp.pk, &ki_ciphertext, ecpk, &Ri_ciphertext, &ki, &cl_rand, &eg_rand);

        Self { ki_ciphertext, Ri_ciphertext, proof }
    }

    pub fn verify(&self, pp: &ThresholdCLPubParams, ecpk: &G) -> bool {
        self.proof.verify(pp, &pp.pk, &self.ki_ciphertext, ecpk, &self.Ri_ciphertext)
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CLScal2Nizk {
    pub e: Zq,
    pub z1: Mpz,
    pub z2: Mpz,
}

impl CLScal2Nizk {
    pub fn prove(pp: &ThresholdCLPubParams, rng: &mut RandGen, scalar_ct: &CipherText, base: &G, scalar_pub: &G,
        orig_ct1: &CipherText, scaled_ct1: &CipherText, orig_ct2: &CipherText, scaled_ct2: &CipherText,
        scalar: &Zq, cl_rand: &Mpz)
    -> Self {
        let u1 = rng.random_mpz(&pp.cl.encrypt_randomness_bound());
        let u2 = Zq::random();

        let U1 = pp.cl.power_of_h(&u1);
        let U2 = pp.cl.power_of_f(&Mpz::from(&u2))
                           .compose(&pp.cl, &pp.pk.exponentiation(&pp.cl, &u1));
        let U3 = base * &u2;
        let U4 = orig_ct1.c1().exp(&pp.cl,&Mpz::from(&u2));
        let U5 = orig_ct1.c2().exp(&pp.cl,&Mpz::from(&u2));
        let U6 = orig_ct2.c1().exp(&pp.cl,&Mpz::from(&u2));
        let U7 = orig_ct2.c2().exp(&pp.cl,&Mpz::from(&u2));

        let e = Self::challenge(&pp.pk, scalar_ct, base, scalar_pub, orig_ct1, scaled_ct1, orig_ct2, scaled_ct2, &U1, &U2, &U3, &U4, &U5, &U6, &U7);
        let z1 = &u1 + Mpz::from(&e) * cl_rand;
        let z2 = Mpz::from(&u2) + Mpz::from(&e) * Mpz::from(scalar);

        Self { e, z1, z2 }
    }

    pub fn verify(&self, pp: &ThresholdCLPubParams, scalar_ct: &CipherText, base: &G, scalar_pub: &G,
        orig_ct1: &CipherText, scaled_ct1: &CipherText, orig_ct2: &CipherText, scaled_ct2: &CipherText)
    -> bool {
        let U1 = pp.cl.power_of_h(&self.z1).compose(&pp.cl, &scalar_ct.c1().exp(&pp.cl, &-Mpz::from(&self.e)));
        let U2 = pp.cl.power_of_f(&self.z2)
                           .compose(&pp.cl, &pp.pk.exponentiation(&pp.cl, &self.z1))
                           .compose(&pp.cl, &scalar_ct.c2().exp(&pp.cl, &-Mpz::from(&self.e)));
        let z2_modq = Zq::from(BigInt::from_bytes(&self.z2.to_bytes()) % Zq::group_order());
        let U3 = base * z2_modq - scalar_pub * &self.e;
        let U4 = orig_ct1.c1().exp(&pp.cl,&self.z2)
                        .compose(&pp.cl, &scaled_ct1.c1().exp(&pp.cl, &-Mpz::from(&self.e)));
        let U5 = orig_ct1.c2().exp(&pp.cl,&self.z2)
                        .compose(&pp.cl, &scaled_ct1.c2().exp(&pp.cl, &-Mpz::from(&self.e)));
        let U6 = orig_ct2.c1().exp(&pp.cl,&self.z2)
                        .compose(&pp.cl, &scaled_ct2.c1().exp(&pp.cl, &-Mpz::from(&self.e)));
        let U7 = orig_ct2.c2().exp(&pp.cl,&self.z2)
                        .compose(&pp.cl, &scaled_ct2.c2().exp(&pp.cl, &-Mpz::from(&self.e)));

        let e = Self::challenge(&pp.pk, scalar_ct, base, scalar_pub, orig_ct1, scaled_ct1, orig_ct2, scaled_ct2, &U1, &U2, &U3, &U4, &U5, &U6, &U7);

        e == self.e
    }

    fn challenge(pk: &PublicKey, scalar_ct: &CipherText, base: &G, scalar_pub: &G,
        orig_ct1: &CipherText, scaled_ct1: &CipherText, orig_ct2: &CipherText, scaled_ct2: &CipherText,
        U1: &QFI, U2: &QFI, U3: &G, U4: &QFI, U5: &QFI, U6: &QFI, U7: &QFI) -> Zq {
        let mut hasher = Sha256::new();

        for item in 
            &[pk.to_bytes(),
            scalar_ct.c1().to_bytes(),
            scalar_ct.c2().to_bytes(),
            base.to_bytes(false).to_vec(),
            scalar_pub.to_bytes(false).to_vec(),
            orig_ct1.c1().to_bytes(),
            orig_ct1.c2().to_bytes(),
            scaled_ct1.c1().to_bytes(),
            scaled_ct1.c2().to_bytes(),
            orig_ct2.c1().to_bytes(),
            orig_ct2.c2().to_bytes(),
            scaled_ct2.c1().to_bytes(),
            scaled_ct2.c2().to_bytes(),
            U1.to_bytes(),
            U2.to_bytes(),
            U3.to_bytes(false).to_vec(),
            U4.to_bytes(),
            U5.to_bytes(),
            U6.to_bytes(),
            U7.to_bytes()]
        {
            hasher.update(item);
        }

        Zq::from_bigint(&BigInt::from_bytes(&hasher.finalize()[..16]))
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct NonceExtractMaskMsg {
    pub R_partial_dec: OpenPowerMsg,
    pub phi_i_ciphertext: CipherText,
    pub kphi_i_ciphertext: CipherText,
    pub xphi_i_ciphertext: CipherText,
    Phi_i: G,
    proof: CLScal2Nizk,
}

impl NonceExtractMaskMsg {
    pub fn new(pp: &ThresholdCLPubParams, rng: &mut RandGen, ec_pub_share: &G, k_ciphertext: &CipherText, x_ciphertext: &CipherText,
        R_ciphertext: &ElGamalCiphertext, xi: &Zq)
    -> Self {
        let R_partial_dec = OpenPowerMsg::new(xi, &G::generator(), ec_pub_share, &R_ciphertext.c1);
        let phi_i = Zq::random();
        let cl_rand = rng.random_mpz(&pp.cl.encrypt_randomness_bound());
        
        let phi_i_ciphertext = CipherText::new(&pp.cl.power_of_h(&cl_rand),
            &pp.cl.power_of_f(&Mpz::from(&phi_i))
                .compose(&pp.cl, &pp.pk.exponentiation(&pp.cl, &cl_rand)));

        let kphi_i_ciphertext = k_ciphertext.scal(&pp.cl, &Mpz::from(&phi_i));
        let xphi_i_ciphertext = x_ciphertext.scal(&pp.cl, &Mpz::from(&phi_i));

        let Phi_i = G::generator() * &phi_i;

        let proof = CLScal2Nizk::prove(pp, rng,  &phi_i_ciphertext, &G::generator(), &Phi_i, &k_ciphertext, &kphi_i_ciphertext, &x_ciphertext, &xphi_i_ciphertext, &phi_i, &cl_rand);

        Self { R_partial_dec, phi_i_ciphertext, kphi_i_ciphertext, xphi_i_ciphertext, Phi_i, proof }
        }

    pub fn verify(&self, pp: &ThresholdCLPubParams, ec_pub_share: &G, R_ciphertext: &ElGamalCiphertext, k_ciphertext: &CipherText, x_ciphertext: &CipherText) -> bool {
        self.R_partial_dec.proof.verify(&G::generator(), ec_pub_share, &R_ciphertext.c1, &self.R_partial_dec.point)
            &&
        self.proof.verify(pp, &self.phi_i_ciphertext, &G::generator(), &self.Phi_i, &k_ciphertext, &self.kphi_i_ciphertext, &x_ciphertext, &self.xphi_i_ciphertext)
    }
}


#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ClassGroup3DleqNizk {
    pub e: Mpz,
    pub z: Mpz,
}

impl ClassGroup3DleqNizk {
    pub fn prove(pp: &ThresholdCLPubParams, rng: &mut RandGen, gen1: &QFI, pow1: &QFI, gen2: &QFI, pow2: &QFI, gen3: &QFI, pow3: &QFI, x: &Mpz) -> Self {
        let u = rng.random_mpz(&pp.cl.encrypt_randomness_bound());

        let U1 = gen1.exp(&pp.cl, &u);
        let U2 = gen2.exp(&pp.cl, &u);
        let U3 = gen3.exp(&pp.cl, &u);
        
        let e = Self::challenge(gen1, pow1, gen2, pow2, gen3, pow3, &U1, &U2, &U3);
        let z = &u + e.clone() * x;

        Self { e, z }
    }

    pub fn verify(&self, pp: &ThresholdCLPubParams, gen1: &QFI, pow1: &QFI, gen2: &QFI, pow2: &QFI, gen3: &QFI, pow3: &QFI) -> bool {
        let neg_e = -self.e.clone();
        let U1 = gen1.exp(&pp.cl, &self.z).compose(&pp.cl, &pow1.exp(&pp.cl, &neg_e));
        let U2 = gen2.exp(&pp.cl, &self.z).compose(&pp.cl, &pow2.exp(&pp.cl, &neg_e));
        let U3 = gen3.exp(&pp.cl, &self.z).compose(&pp.cl, &pow3.exp(&pp.cl, &neg_e));

        let e = Self::challenge(gen1, pow1, gen2, pow2, gen3, pow3, &U1, &U2, &U3);
        e == self.e
    }

    fn challenge(gen1: &QFI, pow1: &QFI, gen2: &QFI, pow2: &QFI, gen3: &QFI, pow3: &QFI, U1: &QFI, U2: &QFI, U3: &QFI) -> Mpz {
        let mut hasher = Sha256::new();
        for item in [gen1, pow1, gen2, pow2, gen3, pow3, U1, U2, U3] {
            hasher.update(item.to_bytes());
        }
        Mpz::from_bytes(&hasher.finalize()[..16])
    }
}


pub struct ThresholdCLPubParams {
    pub cl: CL_HSMqk,
    pub t: Id,
    pub n: Id,
    pub n_factorial: Mpz,
    pub pk: PublicKey,
    pub pub_shares: CLKeyRing,
}

impl ThresholdCLPubParams {
    pub fn simulate(n: Id, t: Id) -> (Self, BTreeMap<Id, SecretKey>) {
        let mut rng = RandGen::new();
        rng.set_seed(&Mpz::from(&Zq::random()));

        let cl = CL_HSMqk::with_rand_gen(
            &Mpz::from_bytes(&Zq::group_order().to_bytes()),
            1,
            1827,
            &mut rng,
            &(Mpz::from_bytes(&(BigInt::from(1) << 40).to_bytes())),
            false,
        );
        
        let mut n_factorial = Mpz::from(1u64);
        for i in 1..=n {
            n_factorial = Mpz::from(i as u64) * &n_factorial;
        }
        
        // define the polynomial
        let mut coeffs = (0..t).map(|_| rng.random_mpz(&cl.encrypt_randomness_bound())).collect_vec();
        let pk = PublicKey::from_qfi(&cl, &cl.power_of_h(&coeffs[0]));

        coeffs[0] = coeffs[0].clone() * &n_factorial;

        let mut secret_shares = BTreeMap::new();
        let mut pub_shares = BTreeMap::new();

        for i in 1..=n {
            let mut secret = Mpz::from(0u64);
            for k in (0..t).rev() {
                secret = secret * Mpz::from(i as u64) + coeffs[k as usize].clone();
            }
            let secret_key = SecretKey::from_mpz(&cl, &secret);
            secret_shares.insert(i, secret_key);
            pub_shares.insert(i, PublicKey::from_qfi(&cl, &cl.power_of_h(&secret)));
        }

        (Self { cl, t, n, n_factorial, pk, pub_shares }, secret_shares)
    }

    pub fn lagrange_coeffs(&self, parties: Vec<Id>) -> Option<BTreeMap<Id, Zq>> {
        if parties.len() < self.t as usize {
            return None;
        }

        let mut coeffs = BTreeMap::new();
        for i in &parties {
            let mut num = Zq::from(1u64);
            let mut den = Zq::from(1u64);
            for j in &parties {
                if i != j {
                    num = num * Zq::from(*j as u64);
                    den = den * Zq::from(*j as i32 - *i as i32);
                }
            }
            coeffs.insert(*i, num * den.invert().unwrap());
        }
        Some(coeffs)
    }


    pub fn lagrange_coeffs_times_n_factorial(&self, parties: Vec<Id>) -> Option<BTreeMap<Id, Mpz>> {
        if parties.len() < self.t as usize {
            return None;
        }

        let mut coeffs = BTreeMap::new();

        let mut n_factorial = 1i64;
        for i in 1..=self.n {
            n_factorial *= i as i64;
        }

        for i in &parties {
            let mut result: i64 = n_factorial;
            for j in &parties {
                if i != j {
                    let j = *j as i64;
                    result = result * j / (j - *i as i64);
                }
            }
            coeffs.insert(*i, Mpz::from(result));
        }
        Some(coeffs)
    }

    /// interpolates the constant term of certain points from a point polynomial
    pub fn interpolate_on_curve(&self, points: &BTreeMap<Id, G>) -> Option<G> {
        let lagrange_coeffs = self.lagrange_coeffs(points.keys().cloned().collect())?;
        Some(points
            .iter()
            .map(|(i, point)| point * &lagrange_coeffs[i])
            .sum())
}
}


#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct OnlineSignMsg {
    pub Ui: QFI,
    pub Wi: QFI,
    pub proof: ClassGroup3DleqNizk,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PresignResult {
    pub r: Zq,
    pub phi_ct: CipherText,
    pub kphi_ct: CipherText,
    pub rxphi_ct: CipherText,
    pub Ui: QFI,
}

#[derive(Debug, Error)]
pub enum Error<RecvErr, SendErr> {
    #[error("sending, round 1")]
    Round1Send(#[source] SendErr),
    #[error("receiving, round 1")]
    Round1Recv(#[source] CompleteRoundError<RoundInputError, RecvErr>),
    #[error("sending, round 2")]
    Round2Send(#[source] SendErr),
    #[error("receiving, round 2")]
    Round2Recv(#[source] CompleteRoundError<RoundInputError, RecvErr>),
}

#[derive(Clone, Debug, PartialEq, ProtocolMessage, Serialize, Deserialize)]
pub enum PresignMsg {
    NonceProposal(NonceProposalMsg),
    NonceExtractMask(NonceExtractMaskMsg),
}

pub async fn presign_protocol<M>(
    party: M,
    my_id: Id,
    pp: &ThresholdCLPubParams,
    threshold_pk: &ThresholdPubKey,
    my_cl_sk: &SecretKey,
    x_ciphertext: &CipherText,
    my_x_share: &Zq,
    lazy_verification: bool,
) -> Result<PresignResult, Error<M::ReceiveError, M::SendError>>
where M: Mpc<ProtocolMessage = PresignMsg>
{
    let mut rng = RandGen::new();
    rng.set_seed(&Mpz::from(&Zq::random()));

    // boilerplate
    let MpcParty { delivery, .. } = party.into_party();
    let (incoming, mut outgoing) = delivery.split();

    let i = (my_id - 1) as u16;
    let n = pp.n as u16;

    let mut rounds = RoundsRouter::<PresignMsg>::builder();
    let round1 = rounds.add_round(RoundInput::<NonceProposalMsg>::broadcast(i, n));
    let round2 = rounds.add_round(RoundInput::<NonceExtractMaskMsg>::broadcast(i, n));
    let mut rounds = rounds.listen(incoming);

    // Round 1 interaction
    let my_proposal = NonceProposalMsg::new(pp, &mut rng, &threshold_pk.pk);
    outgoing.send(Outgoing::broadcast(PresignMsg::NonceProposal(my_proposal.clone()))).await.map_err(Error::Round1Send)?;

    let nonce_proposal_messages = rounds.complete(round1).await.map_err(Error::Round1Recv)?;

    let mut ki_ciphertexts = BTreeMap::new();
    let mut Ri_ciphertexts = BTreeMap::new();

    ki_ciphertexts.insert(my_id, my_proposal.ki_ciphertext);
    Ri_ciphertexts.insert(my_id, my_proposal.Ri_ciphertext);

    // Round 1 processing
    let filtered_proposals = nonce_proposal_messages.into_iter_indexed()
        .map(|(inner_id, _, msg)| ((inner_id + 1) as Id, msg))
        .par_bridge()
        .filter(|(_, msg)| lazy_verification || msg.verify(pp, &threshold_pk.pk))
        .collect::<BTreeMap<Id, NonceProposalMsg>>();

    filtered_proposals.into_iter().take(pp.t as usize)
        .for_each(|(i, msg)| {
            ki_ciphertexts.insert(i, msg.ki_ciphertext);
            Ri_ciphertexts.insert(i, msg.Ri_ciphertext);
        });

    let k_ciphertext = ki_ciphertexts.values().cloned().take(pp.t as usize)
        .reduce(| acc, ct | 
            CipherText::new(&acc.c1().compose(&pp.cl, &ct.c1()), 
                         &acc.c2().compose(&pp.cl, &ct.c2()))).unwrap();
    let R_ciphertext = Ri_ciphertexts.values().cloned().take(pp.t as usize)
        .reduce(| acc, ct | 
            ElGamalCiphertext { c1: acc.c1 + ct.c1, c2: acc.c2 + ct.c2 }).unwrap();
    
    // Round 2 interaction
    let my_extract_mask = NonceExtractMaskMsg::new(pp, &mut rng, &threshold_pk.pub_shares[&my_id], &k_ciphertext, 
        x_ciphertext, &R_ciphertext, my_x_share);

    outgoing.send(Outgoing::broadcast(PresignMsg::NonceExtractMask(my_extract_mask.clone()))).await.map_err(Error::Round2Send)?;

    let nonce_extract_mask_messages = rounds.complete(round2).await.map_err(Error::Round2Recv)?;

    let mut R_partial_decs = BTreeMap::new();
    let mut phi_i_ciphertexts = BTreeMap::new();
    let mut kphi_i_ciphertexts = BTreeMap::new();
    let mut xphi_i_ciphertexts = BTreeMap::new();

    R_partial_decs.insert(my_id, my_extract_mask.R_partial_dec.point);
    phi_i_ciphertexts.insert(my_id, my_extract_mask.phi_i_ciphertext);
    kphi_i_ciphertexts.insert(my_id, my_extract_mask.kphi_i_ciphertext);
    xphi_i_ciphertexts.insert(my_id, my_extract_mask.xphi_i_ciphertext);

    // Round 2 processing
    let filtered_ext_mask_messages = nonce_extract_mask_messages.into_iter_indexed()
        .map(|(inner_id, _, msg)| ((inner_id + 1) as Id, msg))
        .par_bridge()
        .filter(|(i, msg)| lazy_verification || msg.verify(pp, &threshold_pk.pub_shares[&i], &R_ciphertext, &k_ciphertext, x_ciphertext))
        .collect::<BTreeMap<Id, NonceExtractMaskMsg>>();

    filtered_ext_mask_messages.into_iter().take(pp.t as usize)
        .for_each(|(i, msg)| {
            R_partial_decs.insert(i, msg.R_partial_dec.point);
            phi_i_ciphertexts.insert(i, msg.phi_i_ciphertext);
            kphi_i_ciphertexts.insert(i, msg.kphi_i_ciphertext);
            xphi_i_ciphertexts.insert(i, msg.xphi_i_ciphertext);
        });

    let phi_ct = phi_i_ciphertexts.values().cloned().take(pp.t as usize)
        .reduce(| acc, ct | 
            CipherText::new(&acc.c1().compose(&pp.cl, &ct.c1()), 
                         &acc.c2().compose(&pp.cl, &ct.c2()))).unwrap();
    
    let R = pp.interpolate_on_curve(&R_partial_decs).unwrap();
    let r = Zq::from_bigint(&R.x_coord().unwrap());

    let rxphi_ct = xphi_i_ciphertexts.values().cloned().take(pp.t as usize)            
        .reduce(| acc, ct | 
            CipherText::new(&acc.c1().compose(&pp.cl, &ct.c1()), 
                         &acc.c2().compose(&pp.cl, &ct.c2()))).unwrap()
        .scal(&pp.cl, &Mpz::from(&r));

    let kphi_ct = kphi_i_ciphertexts.values().cloned().take(pp.t as usize)
        .reduce(| acc, ct | 
            CipherText::new(&acc.c1().compose(&pp.cl, &ct.c1()), 
                         &acc.c2().compose(&pp.cl, &ct.c2()))).unwrap();
    
    let Ui = kphi_ct.c1().exp(&pp.cl, &my_cl_sk.mpz());


    Ok(PresignResult { r, phi_ct, kphi_ct, rxphi_ct, Ui })
}


#[derive(Clone, Debug, PartialEq, ProtocolMessage, Serialize, Deserialize)]
pub enum OnlineSignMsgEnum {
    OnlineSign(OnlineSignMsg),
}

pub async fn online_sign<M>(
    party: M,
    message_hash: Zq,
    my_id: Id,
    pp: &ThresholdCLPubParams,
    threshold_pk: &ThresholdPubKey,
    my_cl_sk: &SecretKey,
    x_ciphertext: &CipherText,
    my_x_share: &Zq,
    presignature: &PresignResult,
    lazy_verification: bool,
) -> Result<ECDSASignature, Error<M::ReceiveError, M::SendError>>
where M: Mpc<ProtocolMessage = OnlineSignMsgEnum> {
    let mut rng = RandGen::new();
    rng.set_seed(&Mpz::from(&Zq::random()));

    // boilerplate
    let MpcParty { delivery, .. } = party.into_party();
    let (incoming, mut outgoing) = delivery.split();

    let i = (my_id - 1) as u16;
    let n = pp.n as u16;

    let mut rounds = RoundsRouter::<OnlineSignMsgEnum>::builder();
    let round1 = rounds.add_round(RoundInput::<OnlineSignMsg>::broadcast(i, n));
    let mut rounds = rounds.listen(incoming);

    let w_ct = {
        let c1 = presignature.phi_ct.c1()
                .exp(&pp.cl, &Mpz::from(&message_hash))
                .compose(&pp.cl, &presignature.rxphi_ct.c1());
        let c2 = presignature.phi_ct.c2()
                .exp(&pp.cl, &Mpz::from(&message_hash))
                .compose(&pp.cl, &presignature.rxphi_ct.c2());
        CipherText::new(&c1, &c2)
    };

    let Wi = w_ct.c1().exp(&pp.cl, &my_cl_sk.mpz());

    let proof = ClassGroup3DleqNizk::prove( pp, &mut rng,
        &pp.cl.h(), &pp.pub_shares[&my_id].elt(),
        &presignature.kphi_ct.c1(), &presignature.Ui,
        &w_ct.c1(), &Wi, &my_cl_sk.mpz() );

    let my_msg = OnlineSignMsg { Ui: presignature.Ui.clone(), Wi, proof };

    // Round 1 interaction

    outgoing.send(Outgoing::broadcast(OnlineSignMsgEnum::OnlineSign(my_msg.clone()))).await.map_err(Error::Round1Send)?;

    let online_sign_messages = rounds.complete(round1).await.map_err(Error::Round1Recv)?;

    // Round 1 processing
    let mut filtered_online_sign_messages = online_sign_messages.into_iter_indexed()
        .map(|(inner_id, _, msg)| ((inner_id + 1) as Id, msg))
        .par_bridge()
        .filter(|(i, msg)| lazy_verification || msg.proof.verify(pp, &pp.cl.h(), &pp.pub_shares[&i].elt(), &presignature.kphi_ct.c1(), &msg.Ui, &w_ct.c1(), &msg.Wi))
        .take_any(pp.t as usize - 1)
        .collect::<BTreeMap<_,_>>();

    filtered_online_sign_messages.insert(my_id, my_msg);
    filtered_online_sign_messages = filtered_online_sign_messages.into_iter().take(pp.t as usize).collect();

    let w_nominator = w_ct.c2().exp(&pp.cl, &pp.n_factorial.pow(3));
    let u_nominator = presignature.kphi_ct.c2().exp(&pp.cl, &pp.n_factorial.pow(3));

    let lagrange_coeffs_times_n_factorial = pp.lagrange_coeffs_times_n_factorial(filtered_online_sign_messages.keys().cloned().collect()).unwrap();

    let w_denominator = filtered_online_sign_messages.iter().take(pp.t as usize)
        .map(|(i, msg)| msg.Ui.exp(&pp.cl, &lagrange_coeffs_times_n_factorial[i]))
        .reduce(| acc, ui | acc.compose(&pp.cl, &ui)).unwrap();

    let u_denominator = filtered_online_sign_messages.iter().take(pp.t as usize)
        .map(|(i, msg)| msg.Wi.exp(&pp.cl, &lagrange_coeffs_times_n_factorial[i]))
        .reduce(| acc, wi | acc.compose(&pp.cl, &wi)).unwrap();

    let f_pow_w = w_nominator.compose(&pp.cl, &w_denominator.exp(&pp.cl, &Mpz::from(-1i64)));
    let f_pow_u = u_nominator.compose(&pp.cl, &u_denominator.exp(&pp.cl, &Mpz::from(-1i64)));
    let w = pp.cl.dlog_in_F(&f_pow_w);
    let u = pp.cl.dlog_in_F(&f_pow_u);
    
    let r = presignature.r.clone();
    let s = Zq::from(BigInt::from_bytes(&w.to_bytes())) * Zq::from(BigInt::from_bytes(&u.to_bytes())).invert().unwrap();
    
    Ok(ECDSASignature { r, s })
}

#[tokio::test]
pub async fn test_signing() {
    let n = 10;
    let t = 9;

    let (pp, secret_keys) = ThresholdCLPubParams::simulate(n, t);
    let (threshold_pk, x_shares, x) = ThresholdPubKey::simulate(n, t);
    
    let mut rng = RandGen::new();
    rng.set_seed(&Mpz::from(&Zq::random()));
    let r = rng.random_mpz(&pp.cl.encrypt_randomness_bound());
    let x_ciphertext = CipherText::new(&pp.cl.power_of_h(&r), &pp.cl.power_of_f(&Mpz::from(&x)).compose(&pp.cl, &pp.pk.exponentiation(&pp.cl, &r)));


    let mut simulation = Simulation::<PresignMsg>::new();
    let mut party_output = vec![];

    let now = Instant::now();

    for i in 1..=pp.n {
        let party = simulation.add_party();
        let result = presign_protocol(party, i, &pp, &threshold_pk, &secret_keys[&i], &x_ciphertext, &x_shares[&i], false);
        party_output.push(result);
    }

    let output = futures::future::try_join_all(party_output).await.unwrap();
    println!("Presign time per party: {:.4?}", now.elapsed() / pp.n as u32);

    let mut simulation = Simulation::<OnlineSignMsgEnum>::new();
    let mut party_output = vec![];

    let message_hash = Zq::random();

    for i in 1..=pp.n {
        let party = simulation.add_party();
        let result = online_sign(party, message_hash.clone(), i, &pp, &threshold_pk, &secret_keys[&i], &x_ciphertext, &x_shares[&i], &output[i as usize -1], false);
        party_output.push(result);
    }

    let output = futures::future::try_join_all(party_output).await.unwrap();
    println!("Total time per party: {:.4?}", now.elapsed() / pp.n as u32);

}