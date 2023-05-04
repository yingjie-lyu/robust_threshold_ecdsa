#![allow(nonstandard_style)]

use std::collections::BTreeMap;

use class_group::primitives::cl_dl_public_setup::{
    decrypt, encrypt, eval_scal, eval_sum, CLGroup, Ciphertext, PK, SK,
};
use curv::{
    elliptic::curves::{Point, Scalar, Secp256k1},
    BigInt, arithmetic::Samplable,
};
use futures::SinkExt;
use ni_dkg::{NiDkgMsg, NiDkgOutput};
use round_based::{
    rounds_router::simple_store::RoundInput, rounds_router::RoundsRouter, simulation::Simulation,
    Delivery, Mpc, MpcParty, Outgoing, PartyIndex, ProtocolMessage,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub mod ni_dkg;

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
    //    proof_D_i: ProofDlEq
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct OnlineSignMsg {
    pub parties: Vec<usize>,
    pub sig_shares: Vec<BigInt>,
    pub M_i_j_list: Vec<Point<Secp256k1>>,
    //    proofs_M_i_j: Vec<Proof2DlPc>
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

pub struct SigECDSA {
    pub r: BigInt,
    pub s: BigInt,
}

impl MtAwcMsg {
    // `parties` should include ids of online nodes other than myself
    pub fn new(
        parties: Vec<usize>,
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

        let encrypted_alphas: BTreeMap<usize, Ciphertext> = betas
            .iter()
            .map(|(j, beta)| {
                (
                    *j,
                    eval_sum(
                        &encrypt(&clgroup, &clpk[j], &-beta).0,
                        &eval_scal(
                            &k_dkg_output.encrypted_shares.clone().unwrap()[j],
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
                            &k_dkg_output.encrypted_shares.clone().unwrap()[j],
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
        // first decrypt to get all alphas and mus sent to me by other parties
        let alphas_to_me: BTreeMap<usize, Scalar<Secp256k1>> = mta_messages
            .iter()
            .map(|(&j, msg)| (j, decrypt(&clgroup, &myclsk, &msg.encrypted_alphas[&myid])))
            .collect();

        let mus_to_me: BTreeMap<usize, Scalar<Secp256k1>> = mta_messages
            .iter()
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

        let D_i = gamma_dkg_output.pk * &k_share;
        // todo: nizk proof of DL-EQ that D_i is well-formed

        // Shamir 0-secret share => {theta_i,j}_j
        let poly_coeffs: Vec<_> = (1..t).map(|_| Scalar::<Secp256k1>::random()).collect();
        let mut theta_shares = BTreeMap::<usize, Scalar<Secp256k1>>::new();

        for j in honest_parties.iter().chain(std::iter::once(&myid)) {
            let theta_j: Scalar<Secp256k1> = poly_coeffs
                .iter()
                .enumerate()
                .map(|(k, a)| {
                    a * Scalar::<Secp256k1>::from((j + 1).pow((k + 1).try_into().unwrap()) as u64)
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
                D_i, // todo: NIZK proof
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
        .filter(|l| *l != id)
        .map(|l| Scalar::<Secp256k1>::from((l + 1) as u64))
        .map(|l| &l * (&l - &id_scalar).invert().unwrap())
        .reduce(|prod, item| prod * item)
        .unwrap()
}

impl PreSignature {
    pub fn from(
        parties: Vec<usize>,
        mta_messages: BTreeMap<usize, MtAwcMsg>,
        presign_final_messages: BTreeMap<usize, PreSignFinalMsg>,
        mus_to_me: BTreeMap<usize, Scalar<Secp256k1>>,
        nus: BTreeMap<usize, Scalar<Secp256k1>>,
        Gamma: Point<Secp256k1>,
        k_dkg_output: NiDkgOutput,
    ) -> Self {
        // first do PreSignFinal (Share Revelation) step check and build honest set
        // TODO
        let honest_parties = parties;

        // with the honest parties, now reconstruct the delta
        let mut delta_j_list = BTreeMap::<usize, Scalar<Secp256k1>>::new();

        // the first lagrange interpolation
        for j in &honest_parties {
            let delta_j: Scalar<Secp256k1> = presign_final_messages[&j]
                .delta_shares
                .iter()
                .filter(|(&l, _)| honest_parties.clone().contains(&l))
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
        let R = Gamma * &delta_inv;

        // the following are for verification purposes
        let R_j_list: BTreeMap<usize, Point<Secp256k1>> = honest_parties
            .iter()
            .map(|j| (*j, &presign_final_messages[j].D_i * &delta_inv))
            .collect();

        let mut N_j_l_list = BTreeMap::<(usize, usize), Point<Secp256k1>>::new();

        for l in honest_parties.clone() {
            let _ = &mta_messages[&l].nus_cmt.iter().for_each(|(j, N)| {
                N_j_l_list.insert((*j, l), N.clone());
            });
        }

        PreSignature {
            parties: honest_parties.clone(),
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

// below are for testing

#[derive(Clone, Debug, PartialEq, ProtocolMessage, Serialize, Deserialize)]
pub enum Msg {
    NiDkgMsg(NiDkgMsg),
    NonceGenMsg(NonceGenMsg),
    MtAwcMsg(MtAwcMsg),
    PreSignFinalMsg(PreSignFinalMsg),
}

#[derive(Debug, Error)]
pub enum Error<RecvErr, SendErr> {
    Round1Send(SendErr),
    Round1Receive(RecvErr),
}

pub async fn protocol_dkg_presign<M>(
    party: M,
    myid: PartyIndex,
    t: usize,
    n: usize,
    clgroup: CLGroup,
    clpk: BTreeMap<usize, PK>,
    mysk: SK,
) -> Result<PreSignature, Error<M::ReceiveError, M::SendError>>
where
    M: Mpc<ProtocolMessage = Msg>,
{
    let parties: Vec<usize> = (0..n).collect();
    let parties_excl_myself: Vec<usize> = (0..n).filter(|j| *j != (myid as usize)).collect();

    let n_u16 = u16::try_from(n).unwrap();
    let MpcParty { delivery, .. } = party.into_party();
    let (incoming, mut outgoing) = delivery.split();
    let mut rounds = RoundsRouter::<Msg>::builder();
    let round0 = rounds.add_round(RoundInput::<NiDkgMsg>::broadcast(myid, n_u16));
    let round1 = rounds.add_round(RoundInput::<NonceGenMsg>::broadcast(myid, n_u16));
    let round2 = rounds.add_round(RoundInput::<MtAwcMsg>::broadcast(myid, n_u16));
    let round3 = rounds.add_round(RoundInput::<PreSignFinalMsg>::broadcast(myid, n_u16));
    let mut rounds = rounds.listen(incoming);

    // Step 0: DKG of x
    let my_ni_dkg_msg = NiDkgMsg::new(t, parties.clone(), clgroup.clone(), clpk.clone());

    outgoing
        .send(Outgoing::broadcast(Msg::NiDkgMsg(my_ni_dkg_msg.clone())))
        .await
        .unwrap();

    let x_dkg_messages = rounds
        .complete(round0)
        .await
        .unwrap()
        .into_vec_including_me(my_ni_dkg_msg);

    let x_dkg_output = NiDkgOutput::from_combining(
        parties.clone(),
        &x_dkg_messages,
        myid.into(),
        clgroup.clone(),
        false,
        clpk.clone(),
        &mysk,
    );

    // Step 1: Generation of nonces k and gamma
    let my_nonce_gen_msg = NonceGenMsg {
        k_dkg_msg: NiDkgMsg::new(t, parties.clone(), clgroup.clone(), clpk.clone()),
        gamma_dkg_msg: NiDkgMsg::new(t, parties.clone(), clgroup.clone(), clpk.clone()),
    };

    outgoing
        .send(Outgoing::broadcast(Msg::NonceGenMsg(
            my_nonce_gen_msg.clone(),
        )))
        .await
        .unwrap();

    let nonce_gen_messages = rounds
        .complete(round1)
        .await
        .unwrap()
        .into_vec_including_me(my_nonce_gen_msg);

    // Step 1->2 transition: prepare input from output
    let (k_dkg_messages, gamma_dkg_messages): (Vec<_>, Vec<_>) = nonce_gen_messages
        .into_iter()
        .map(|msg| (msg.k_dkg_msg, msg.gamma_dkg_msg))
        .unzip();

    let k_dkg_output = NiDkgOutput::from_combining(
        parties.clone(),
        &k_dkg_messages,
        myid.into(),
        clgroup.clone(),
        true,
        clpk.clone(),
        &mysk,
    );

    let gamma_dkg_output = NiDkgOutput::from_combining(
        parties.clone(),
        &gamma_dkg_messages,
        myid.into(),
        clgroup.clone(),
        false,
        clpk.clone(),
        &mysk,
    );

    // Step 2: Nonce conversion, or MtAwc
    let (my_mta_msg, betas, nus) = MtAwcMsg::new(
        parties_excl_myself.clone(),
        clgroup.clone(),
        &clpk,
        k_dkg_output.clone(),
        gamma_dkg_output.clone().share,
        x_dkg_output.clone().share,
    );

    outgoing
        .send(Outgoing::broadcast(Msg::MtAwcMsg(my_mta_msg.clone())))
        .await
        .unwrap();

    // we want MtA messages, excluding myself's, to be arranged into a BTreeMap for Step 3
    let mta_messages: BTreeMap<usize, MtAwcMsg> = rounds
        .complete(round2)
        .await
        .unwrap()
        .into_iter_indexed()
        .map(|(j, _, msg)| (j.into(), msg))
        .collect();

    // Step 3: PreSign final round aka Share Revelation
    let (my_presign_final_msg, mus_to_me, nus) = PreSignFinalMsg::new(
        parties_excl_myself.clone(),
        t,
        myid.into(),
        mta_messages.clone(),
        clgroup.clone(),
        mysk,
        betas,
        nus,
        gamma_dkg_output.clone(),
        x_dkg_output,
        k_dkg_output.clone().share,
    );

    outgoing
        .send(Outgoing::broadcast(Msg::PreSignFinalMsg(
            my_presign_final_msg.clone(),
        )))
        .await
        .unwrap();

    let presign_final_messages: BTreeMap<usize, PreSignFinalMsg> = rounds
        .complete(round3)
        .await
        .unwrap()
        .into_iter_indexed()
        .map(|(j, _, msg)| (j.into(), msg))
        .collect();

    // and finally you may follow me; farewell he said
    let presignature = PreSignature::from(
        parties_excl_myself,
        mta_messages,
        presign_final_messages,
        mus_to_me,
        nus,
        gamma_dkg_output.pk,
        k_dkg_output,
    );

    Ok(presignature)
}

#[tokio::test]
async fn test_dkg_presign() {
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
        let output = protocol_dkg_presign(party, i, t, n.into(), clgroup.clone(), clpk.clone(), mysk);
        party_output.push(output);
    }

    let _output = futures::future::try_join_all(party_output).await.unwrap();
}
