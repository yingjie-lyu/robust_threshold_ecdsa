#![allow(nonstandard_style)]
#![allow(unused_imports)]

use std::collections::BTreeMap;

use class_group::primitives::cl_dl_public_setup::{
    decrypt, encrypt, eval_scal, eval_sum, CLGroup, Ciphertext, PK, SK,
};
use curv::{
    arithmetic::{Converter, Samplable},
    elliptic::curves::{Point, Scalar, Secp256k1},
    BigInt,
};
use futures::SinkExt;
use ni_dkg::{NiDkgMsg, NiDkgOutput};
use round_based::{
    rounds_router::simple_store::RoundInput, rounds_router::RoundsRouter, simulation::Simulation,
    Delivery, Mpc, MpcParty, Outgoing, PartyIndex, ProtocolMessage,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub mod ni_dkg;
pub mod tests;

// Pre-signing phase consists of 3 rounds: NonceGen, MtAwc, & PreSignFinal;
// Besides, the online signing phase has another non-interactive round.

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct NonceGenMsg {
    pub k_dkg_msg: NiDkgMsg, // encrypted_shares have to be present
    pub gamma_dkg_msg: NiDkgMsg,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MtAwcMsg {
    pub parties: Vec<usize>,
    pub encrypted_alphas: BTreeMap<usize, Ciphertext>,
    pub encrypted_mus: BTreeMap<usize, Ciphertext>,
    pub betas_cmt: BTreeMap<usize, Point<Secp256k1>>,
    pub nus_cmt: BTreeMap<usize, Point<Secp256k1>>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PreSignFinalMsg {
    pub parties: Vec<usize>,
    pub delta_shares: BTreeMap<usize, Scalar<Secp256k1>>,
    pub D_i: Point<Secp256k1>,
    pub proof_D_i: ProofDLEQ,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct OnlineSignMsg {
    pub parties: Vec<usize>,
    pub sig_shares: BTreeMap<usize, Scalar<Secp256k1>>,
    pub M_i_j_list: BTreeMap<usize, Point<Secp256k1>>,
    pub proofs_M_i_j: BTreeMap<usize, Proof2DLPC>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PreSignature {
    pub parties: Vec<usize>,
    pub R: Point<Secp256k1>,
    pub k_i: Scalar<Secp256k1>,
    pub mu_i_j_list: BTreeMap<usize, Scalar<Secp256k1>>,
    pub nu_j_i_list: BTreeMap<usize, Scalar<Secp256k1>>,
    pub K_j_list: BTreeMap<usize, Point<Secp256k1>>,
    pub R_j_list: BTreeMap<usize, Point<Secp256k1>>,
    pub N_j_l_list: BTreeMap<(usize, usize), Point<Secp256k1>>,
}

pub struct SignatureECDSA {
    pub r: Scalar<Secp256k1>,
    pub s: Scalar<Secp256k1>,
}

impl MtAwcMsg {
    pub fn new(
        parties: Vec<usize>,
        myid: usize,
        clgroup: CLGroup,
        clpk: &BTreeMap<usize, PK>,
        k_dkg_output: NiDkgOutput,
        gamma_share: Scalar<Secp256k1>,
        x_share: Scalar<Secp256k1>,
    ) -> (
        Self,
        BTreeMap<usize, Scalar<Secp256k1>>,
        BTreeMap<usize, Scalar<Secp256k1>>,
    ) {
        // exclude myself from parties
        let parties: Vec<usize> = parties.into_iter().filter(|j| *j != myid).collect();

        let betas: BTreeMap<usize, Scalar<Secp256k1>> = parties
            .iter()
            .map(|j| (*j, Scalar::<Secp256k1>::random()))
            .collect();

        let nus: BTreeMap<usize, Scalar<Secp256k1>> = parties
            .iter()
            .map(|j| (*j, Scalar::<Secp256k1>::random()))
            .collect();

        let betas_cmt: BTreeMap<usize, Point<Secp256k1>> = betas
            .iter()
            .map(|(j, beta)| (*j, Point::<Secp256k1>::generator() * beta))
            .collect();

        let nus_cmt: BTreeMap<usize, Point<Secp256k1>> = nus
            .iter()
            .map(|(j, nu)| (*j, Point::<Secp256k1>::generator() * nu))
            .collect();

        let encrypted_ks = k_dkg_output.encrypted_shares.clone().unwrap();
        let encrypted_alphas: BTreeMap<usize, Ciphertext> = betas
            .iter()
            .map(|(j, beta)| {
                (
                    *j,
                    eval_sum(
                        &encrypt(&clgroup, &clpk[j], &-beta).0,
                        &eval_scal(
                            &encrypted_ks[j],
                            &gamma_share.to_bigint(),
                        ),
                    ),
                )
            })
            .collect();

        let encrypted_mus: BTreeMap<usize, Ciphertext> = nus
            .iter()
            .map(|(j, nu)| {
                (
                    *j,
                    eval_sum(
                        &encrypt(&clgroup, &clpk[j], &-nu).0,
                        &eval_scal(
                            &encrypted_ks[j],
                            &x_share.to_bigint(),
                        ),
                    ),
                )
            })
            .collect();

        (
            MtAwcMsg {
                parties,
                encrypted_alphas,
                encrypted_mus,
                betas_cmt,
                nus_cmt,
            },
            betas,
            nus,
        )
    }
}

impl PreSignFinalMsg {
    pub fn new(
        parties: Vec<usize>,
        t: usize,
        myid: usize,
        mta_messages: BTreeMap<usize, MtAwcMsg>,
        clgroup: CLGroup,
        myclsk: SK,
        betas: BTreeMap<usize, Scalar<Secp256k1>>,
        nus: BTreeMap<usize, Scalar<Secp256k1>>,
        gamma_dkg_output: NiDkgOutput,
        x_dkg_output: NiDkgOutput, // encrypted_shares needed here
        k_share: Scalar<Secp256k1>,
    ) -> (
        Self,
        BTreeMap<usize, Scalar<Secp256k1>>,
        BTreeMap<usize, Scalar<Secp256k1>>,
    ) {
        let parties: Vec<usize> = parties.into_iter().filter(|&j| j!=myid).collect();
        // first decrypt to get all alphas and mus sent to me by other parties
        let alphas_to_me: BTreeMap<usize, Scalar<Secp256k1>> = mta_messages
            .iter()
            .filter(|(&j, _)| j != myid)
            .map(|(&j, msg)| (j, decrypt(&clgroup, &myclsk, &msg.encrypted_alphas[&myid])))
            .collect();

        let mus_to_me: BTreeMap<usize, Scalar<Secp256k1>> = mta_messages
            .iter()
            .filter(|(&j, _)| j != myid)
            .map(|(&j, msg)| (j, decrypt(&clgroup, &myclsk, &msg.encrypted_mus[&myid])))
            .collect();

        // do MtA step check and build honest set
        let honest_parties: Vec<usize> = parties
            .into_iter()
            .filter(|j| {
                Point::<Secp256k1>::generator() * &alphas_to_me[j]
                    + &mta_messages[j].betas_cmt[&myid]
                    == &gamma_dkg_output.shares_cmt[j] * &k_share
                    && Point::<Secp256k1>::generator() * &mus_to_me[j]
                        + &mta_messages[j].nus_cmt[&myid]
                        == &x_dkg_output.shares_cmt[j] * &k_share
            })
            .collect();

        // end of MtA step check
        // begin of Share Revelation step

        let D_i = &gamma_dkg_output.pk * &k_share;
        let proof_D_i = ProofDLEQ::prove(
            &gamma_dkg_output.pk,
            &D_i,
            &Point::<Secp256k1>::generator(),
            &(Point::<Secp256k1>::generator() * &k_share),
            &k_share,
        );

        // Shamir 0-secret share => {theta_i,j}_j
        let poly_coeffs: Vec<_> = (1..t).map(|_| Scalar::<Secp256k1>::random()).collect();
        let mut theta_shares = BTreeMap::<usize, Scalar<Secp256k1>>::new();

        for j in honest_parties.iter().chain(std::iter::once(&myid)) {
            let theta_j: Scalar<Secp256k1> = poly_coeffs
                .iter()
                .enumerate()
                .map(|(k, a)| {
                    a * Scalar::<Secp256k1>::from((j + 1).pow((k+1).try_into().unwrap()) as u64)
                })
                .sum();
            theta_shares.insert(*j, theta_j);
        }

        // make delta shares: alpha_to_me + beta_i_gave + theta_as_mask when not myself,
        // k_share * gamma_share + theta_as_mask when it's myself
        let mut delta_shares: BTreeMap<usize, Scalar<Secp256k1>> = honest_parties
            .iter()
            .map(|j| (*j, &alphas_to_me[j] + &betas[j] + &theta_shares[j]))
            .collect();

        delta_shares.insert(
            myid,
            k_share * gamma_dkg_output.share + &theta_shares[&myid],
        );

        (
            PreSignFinalMsg {
                parties: honest_parties,
                delta_shares,
                D_i,
                proof_D_i,
            },
            mus_to_me,
            nus, // bad parties not excluded; innocuous and cheap though since passively queried and always local
        )
    }
}

pub fn lagrange_coeff(id: usize, parties: Vec<usize>) -> Scalar<Secp256k1> {
    // as mentioned elsewhere the ids used are 1 more than party numbers passed in, since they're [0..n) by default outside
    let id_scalar = Scalar::<Secp256k1>::from((id + 1) as u64);
    parties
        .into_iter()
        .filter(|&l| l != id)
        .map(|l| Scalar::<Secp256k1>::from((l + 1) as u64))
        .map(|l| &l * ((&l - &id_scalar).invert().unwrap()))
        .reduce(|prod, item| prod * item)
        .unwrap()
}

impl PreSignature {
    pub fn from(
        parties: Vec<usize>,
        myid: usize,
        mta_messages: BTreeMap<usize, MtAwcMsg>,
        presign_final_messages: BTreeMap<usize, PreSignFinalMsg>,
        mus_to_me: BTreeMap<usize, Scalar<Secp256k1>>,
        nus: BTreeMap<usize, Scalar<Secp256k1>>,
        Gamma: Point<Secp256k1>,
        k_dkg_output: NiDkgOutput,
    ) -> Self {
        // first do PreSignFinal (Share Revelation) step check and build honest set
        for j in parties.iter().filter(|&j| *j != myid) {
            let flag = presign_final_messages[j].proof_D_i.verify(
                &Gamma,
                &presign_final_messages[j].D_i,
                &Point::<Secp256k1>::generator(),
                &k_dkg_output.shares_cmt[j],
            );
            assert!(flag); // ok

            let delta_j: Scalar<Secp256k1> = presign_final_messages[j]
                .delta_shares
                .iter()
                .map(|(&l, delta_jl)| lagrange_coeff(l, parties.clone()) * delta_jl)
                .sum();

            let eq_inside: Point<Secp256k1> = presign_final_messages[j]
                .parties
                .iter()
                .filter(|l| *l != j)
                .map(|l| {
                    lagrange_coeff(*l, parties.clone())
                        * (&mta_messages[l].betas_cmt[j] - &mta_messages[j].betas_cmt[l])
                })
                .sum();
            
            let flag: bool = (Point::<Secp256k1>::generator() * delta_j) + eq_inside == presign_final_messages[j].D_i;
            assert!(flag); // ok
        }

        let mut honest_parties = parties;

        // with the honest parties, now reconstruct the delta
        let mut delta_j_list = BTreeMap::<usize, Scalar<Secp256k1>>::new();

        // the first lagrange interpolation
        for j in &honest_parties {
            let delta_j: Scalar<Secp256k1> = presign_final_messages[j]
                .delta_shares
                .iter()
                .filter(|(&l, _)| honest_parties.contains(&l))
                .map(|(&l, delta_jl)| lagrange_coeff(l, honest_parties.clone()) * delta_jl)
                .sum();
            delta_j_list.insert(*j, delta_j);
        }

        // the second lagrange interpolation
        let delta: Scalar<Secp256k1> = delta_j_list
            .iter()
            .map(|(&j, delta_j)| lagrange_coeff(j, honest_parties.clone()) * delta_j)
            .sum();

        // goodies that are now available
        let delta_inv = delta.invert().unwrap();
        let R = &Gamma * &delta_inv;

        // the following are for verification purposes
        let R_j_list: BTreeMap<usize, Point<Secp256k1>> = honest_parties
            .iter()
            .map(|j| (*j, &presign_final_messages[j].D_i * &delta_inv))
            .collect();

        let mut N_j_l_list = BTreeMap::<(usize, usize), Point<Secp256k1>>::new();

        honest_parties.push(myid);
        for l in honest_parties.clone() {
            let _ = &mta_messages[&l].nus_cmt.iter().for_each(|(j, N)| {
                N_j_l_list.insert((*j, l), N.clone());
            });
        }

        PreSignature {
            parties: honest_parties,
            R,
            k_i: k_dkg_output.share,
            mu_i_j_list: mus_to_me,
            nu_j_i_list: nus,
            K_j_list: k_dkg_output.shares_cmt,
            R_j_list,
            N_j_l_list,
        }
    }
}

impl OnlineSignMsg {
    pub fn new(
        msg: impl AsRef<[u8]>,
        parties: Vec<usize>,
        t: usize,
        myid: usize,
        x_dkg_output: NiDkgOutput,
        presignature: PreSignature,
        k_share: Scalar<Secp256k1>,
    ) -> (Self, Scalar<Secp256k1>, Scalar<Secp256k1>) {
        // get m and r
        let mut msg_hash = Sha256::new();
        msg_hash.update(msg);
        let msg_hash = msg_hash.finalize();

        let m = Scalar::<Secp256k1>::from_bigint(&BigInt::from_bytes(&msg_hash[..16]));
        let r = Scalar::<Secp256k1>::from_bigint(&presignature.R.x_coord().unwrap());

        // make shares of m
        let mut poly_coeffs: Vec<_> = (0..t).map(|_| Scalar::<Secp256k1>::random()).collect();
        poly_coeffs[0] = m.clone();
        let mut m_shares = BTreeMap::<usize, Scalar<Secp256k1>>::new();

        for j in parties.iter().chain(std::iter::once(&myid)) {
            let m_share_j: Scalar<Secp256k1> = poly_coeffs
                .iter()
                .enumerate()
                .map(|(k, a)| {
                    a * Scalar::<Secp256k1>::from((j + 1).pow(k.try_into().unwrap()) as u64)
                })
                .sum();
            m_shares.insert(*j, m_share_j);
        }

        // make signature shares
        let mut sig_shares: BTreeMap<usize, Scalar<Secp256k1>> = parties
            .iter()
            .map(|j| {
                (
                    *j,
                    &r * (&presignature.mu_i_j_list[j] + &presignature.nu_j_i_list[j])
                        + &presignature.k_i * &m_shares[j],
                )
            })
            .collect();

        sig_shares.insert(
            myid,
            &r * &presignature.k_i * x_dkg_output.share + &presignature.k_i * &m_shares[&myid],
        );

        // make M_ij's for verification
        let M_i_j_list: BTreeMap<usize, Point<Secp256k1>> = parties
            .iter()
            .map(|j| (*j, &presignature.R * &presignature.mu_i_j_list[j]))
            .collect();

        let proofs_M_i_j: BTreeMap<usize, Proof2DLPC> = parties
            .iter()
            .filter(|&j| *j != myid)
            .map(|j| {
                (
                    *j,
                    Proof2DLPC::prove(
                        &Point::<Secp256k1>::generator(),
                        &(Point::<Secp256k1>::generator() * &k_share),
                        &presignature.R,
                        &M_i_j_list[j],
                        &x_dkg_output.shares_cmt[j],
                        &-Point::<Secp256k1>::generator(),
                        &presignature.N_j_l_list[&(myid, *j)],
                        &k_share,
                        &presignature.mu_i_j_list[j],
                    ),
                )
            })
            .collect();

        (
            OnlineSignMsg {
                parties,
                sig_shares,
                M_i_j_list,
                proofs_M_i_j,
            },
            r,
            m,
        )
    }
}

impl SignatureECDSA {
    fn from(
        parties: Vec<usize>,
        myid: usize,
        online_sign_messages: BTreeMap<usize, OnlineSignMsg>,
        r: Scalar<Secp256k1>,
        m: Scalar<Secp256k1>,
        presignature: PreSignature,
        x_dkg_output: NiDkgOutput,
    ) -> Self {
        // parties should include myself, and online sign messages should include my own.

        // first verify the messages and build honest set (todo)
        let mut honest_parties = vec![];

        for j in parties.iter().filter(|&l| *l != myid) {
            let mut _flag = false;
            // todo: check all nizks

            let is_proof_ok = online_sign_messages[j]
                .proofs_M_i_j
                .iter()
                .all(|(l, proof)| {
                    proof.verify(
                        &Point::<Secp256k1>::generator(),
                        &presignature.K_j_list[j],
                        &presignature.R,
                        &online_sign_messages[j].M_i_j_list[l],
                        &x_dkg_output.shares_cmt[l],
                        &-Point::<Secp256k1>::generator(),
                        &presignature.N_j_l_list[&(*j, *l)],
                    )
                });
            assert!(is_proof_ok); // ok
            let j_parties: Vec<usize> = online_sign_messages[j]
                .parties
                .clone()
                .into_iter()
                .chain(std::iter::once(*j))
                .collect();

            let sig_share_j: Scalar<Secp256k1> = online_sign_messages[j]
                .sig_shares
                .iter()
                .map(|(&l, sig_share_jl)| lagrange_coeff(l, j_parties.clone()) * sig_share_jl)
                .sum();

            // check eq
            let eq_inside: Point<Secp256k1> = parties
                .iter()
                .filter(|&l| l != j)
                .map(|l| {
                    (&online_sign_messages[l].M_i_j_list[j]
                        - &online_sign_messages[j].M_i_j_list[l])
                        * lagrange_coeff(*l, j_parties.clone())
                })
                .sum();

            if (&presignature.R * sig_share_j) + (eq_inside * &r)
                == (&m * &presignature.R_j_list[j]) + (&r * &x_dkg_output.shares_cmt[j])
            {
                _flag = true;
                honest_parties.push(*j);
            }
        }

        assert_ne!(honest_parties.len(), 0); //ok
        let honest_parties = parties;

        let mut sig_share_j_list = BTreeMap::<usize, Scalar<Secp256k1>>::new();

        // first lagrange interpolation
        for j in &honest_parties {
            let sig_share_j: Scalar<Secp256k1> = online_sign_messages[j]
                .sig_shares
                .iter()
                .filter(|(&l, _)| honest_parties.contains(&l))
                .map(|(&l, sig_share_jl)| lagrange_coeff(l, honest_parties.clone()) * sig_share_jl)
                .sum();
            sig_share_j_list.insert(*j, sig_share_j);
        }

        // second lagrange interpolation
        let s: Scalar<Secp256k1> = sig_share_j_list
            .iter()
            .map(|(&j, sig_share_j)| lagrange_coeff(j, honest_parties.clone()) * sig_share_j)
            .sum();

        SignatureECDSA { r, s }
    }
}

// two NIZK proofs, DL-EQ and 2DL-PC

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ProofDLEQ {
    pub u1: Point<Secp256k1>,
    pub u2: Point<Secp256k1>,
    pub z: Scalar<Secp256k1>,
}

impl ProofDLEQ {
    pub fn prove(
        g1: &Point<Secp256k1>,
        h1: &Point<Secp256k1>,
        g2: &Point<Secp256k1>,
        h2: &Point<Secp256k1>,
        x: &Scalar<Secp256k1>,
    ) -> Self {
        let r = Scalar::<Secp256k1>::random();
        let u1 = g1 * &r;
        let u2 = g2 * &r;
        let c_hash = Sha256::new()
            .chain_update(g1.to_bytes(true))
            .chain_update(h1.to_bytes(true))
            .chain_update(g2.to_bytes(true))
            .chain_update(h2.to_bytes(true))
            .chain_update(u1.to_bytes(true))
            .chain_update(u2.to_bytes(true))
            .finalize();
        let c = Scalar::<Secp256k1>::from(BigInt::from_bytes(&c_hash[..16]));
        let z = r + c * x;
        ProofDLEQ { u1, u2, z }
    }

    pub fn verify(
        &self,
        g1: &Point<Secp256k1>,
        h1: &Point<Secp256k1>,
        g2: &Point<Secp256k1>,
        h2: &Point<Secp256k1>,
    ) -> bool {
        let c_hash = Sha256::new()
            .chain_update(g1.to_bytes(true))
            .chain_update(h1.to_bytes(true))
            .chain_update(g2.to_bytes(true))
            .chain_update(h2.to_bytes(true))
            .chain_update(self.u1.to_bytes(true))
            .chain_update(self.u2.to_bytes(true))
            .finalize();
        let c = Scalar::<Secp256k1>::from(BigInt::from_bytes(&c_hash[..16]));
        &self.z * g1 == &self.u1 + &c * h1 && &self.z * g2 == &self.u2 + c * h2
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Proof2DLPC {
    pub u1: Point<Secp256k1>,
    pub u2: Point<Secp256k1>,
    pub u3: Point<Secp256k1>,
    pub z1: Scalar<Secp256k1>,
    pub z2: Scalar<Secp256k1>,
}

impl Proof2DLPC {
    pub fn prove(
        g1: &Point<Secp256k1>,
        h1: &Point<Secp256k1>,
        g2: &Point<Secp256k1>,
        h2: &Point<Secp256k1>,
        a: &Point<Secp256k1>,
        b: &Point<Secp256k1>,
        m: &Point<Secp256k1>,
        x1: &Scalar<Secp256k1>,
        x2: &Scalar<Secp256k1>,
    ) -> Self {
        let r1 = Scalar::<Secp256k1>::random();
        let r2 = Scalar::<Secp256k1>::random();
        let u1 = g1 * &r1;
        let u2 = g2 * &r2;
        let u3 = a * &r1 + b * &r2;
        let c_hash = Sha256::new()
            .chain_update(g1.to_bytes(true))
            .chain_update(h1.to_bytes(true))
            .chain_update(g2.to_bytes(true))
            .chain_update(h2.to_bytes(true))
            .chain_update(a.to_bytes(true))
            .chain_update(b.to_bytes(true))
            .chain_update(m.to_bytes(true))
            .chain_update(u1.to_bytes(true))
            .chain_update(u2.to_bytes(true))
            .finalize();

        let c = Scalar::<Secp256k1>::from(BigInt::from_bytes(&c_hash[..16]));
        let z1 = r1 + &c * x1;
        let z2 = r2 + &c * x2;

        Proof2DLPC { u1, u2, u3, z1, z2 }
    }

    pub fn verify(
        &self,
        g1: &Point<Secp256k1>,
        h1: &Point<Secp256k1>,
        g2: &Point<Secp256k1>,
        h2: &Point<Secp256k1>,
        a: &Point<Secp256k1>,
        b: &Point<Secp256k1>,
        m: &Point<Secp256k1>,
    ) -> bool {
        let c_hash = Sha256::new()
            .chain_update(g1.to_bytes(true))
            .chain_update(h1.to_bytes(true))
            .chain_update(g2.to_bytes(true))
            .chain_update(h2.to_bytes(true))
            .chain_update(a.to_bytes(true))
            .chain_update(b.to_bytes(true))
            .chain_update(m.to_bytes(true))
            .chain_update(self.u1.to_bytes(true))
            .chain_update(self.u2.to_bytes(true))
            .finalize();
        let c = Scalar::<Secp256k1>::from(BigInt::from_bytes(&c_hash[..16]));
        &self.z1 * g1 == &self.u1 + h1 * &c
            && &self.z2 * g2 == &self.u2 + h2 * &c
            && &self.z1 * a + &self.z2 * b == &self.u3 + m * c
    }
}
