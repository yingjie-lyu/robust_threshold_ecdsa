use bicycl::{CL_HSMqk, Mpz, RandGen, SecretKey};
use curv::{arithmetic::Converter, BigInt};
use futures::SinkExt;
use rayon::iter::{ParallelBridge, ParallelIterator};
use serde::{Deserialize, Serialize};
use std::time::Instant;
use std::{collections::BTreeMap, iter};

use crate::utils::*;

use round_based::{
    rounds_router::{
        simple_store::{RoundInput, RoundInputError},
        CompleteRoundError, RoundsRouter,
    },
    simulation::Simulation,
};
use round_based::{Delivery, Mpc, MpcParty, Outgoing, ProtocolMessage};
use thiserror::Error;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PvssMsg {
    dealing: PvssDealing,
    proof: PvssNizk,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct OpenPowerMsg {
    pub point: G,
    pub proof: DleqNizk,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ThresholdPubKey {
    pub pk: G,
    pub pub_shares: BTreeMap<Id, G>,
}

impl ThresholdPubKey {
    pub fn simulate(n: Id, t: Id) -> (Self, BTreeMap<Id, Zq>, Zq) {
        let coeffs: Vec<_> = (0..t).map(|_| Zq::random()).collect();
        let x = coeffs[0].clone();

        let polynomial = Polynomial { coeffs };
        let curve_polynomial = CurvePolynomial::from_exp(&polynomial, &G::generator());

        let threshold_pk = ThresholdPubKey {
            pk: curve_polynomial.coeffs[0].clone(),
            pub_shares: (1..=n)
                .map(|i| (i, curve_polynomial.eval(&Zq::from(i as u64))))
                .collect(),
        };

        let x_shares: BTreeMap<Id, Zq> = (1..=n)
            .map(|i| (i, polynomial.eval(&Zq::from(i as u64))))
            .collect();

        (threshold_pk, x_shares, x)
    }
}

impl PvssMsg {
    pub fn random(pp: &PubParams, rng: &mut RandGen, curve_generator: &G) -> Self {
        let (dealing, r, _, shares) = PvssDealing::random(pp, rng, curve_generator);
        let proof = PvssNizk::prove(pp, &dealing, &r, &shares, rng, curve_generator);

        PvssMsg { dealing, proof }
    }
}

impl OpenPowerMsg {
    pub fn new(secret: &Zq, gen1: &G, pow1: &G, gen2: &G) -> Self {
        let point = gen2 * secret;
        let proof = DleqNizk::prove(gen1, pow1, gen2, &point, secret);

        OpenPowerMsg { point, proof }
    }
}

#[derive(Clone, Debug, PartialEq, ProtocolMessage, Serialize, Deserialize)]
pub enum DkgMsg {
    Pvss(PvssMsg),
    PowOpen(OpenPowerMsg),
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

pub async fn dkg<M>(
    party: M,
    my_id: Id, // in the range 1..=n, subtract one before use
    pp: &PubParams,
    h: &G,
    my_cl_sk: &SecretKey,
    lazy_verification: bool,
) -> Result<ThresholdPubKey, Error<M::ReceiveError, M::SendError>>
where
    M: Mpc<ProtocolMessage = DkgMsg>,
{
    let mut rng = RandGen::new();
    rng.set_seed(&Mpz::from(&Zq::random()));

    // boilerplate
    let MpcParty { delivery, .. } = party.into_party();
    let (incoming, mut outgoing) = delivery.split();

    let i = (my_id - 1) as u16;
    let n = pp.n as u16;

    let mut rounds = RoundsRouter::<DkgMsg>::builder();
    let round1 = rounds.add_round(RoundInput::<PvssMsg>::broadcast(i, n));
    let round2 = rounds.add_round(RoundInput::<OpenPowerMsg>::broadcast(i, n));
    let mut rounds = rounds.listen(incoming);

    // Round 1 interaction
    let pvss_msg = PvssMsg::random(pp, &mut rng, h);
    outgoing
        .send(Outgoing::broadcast(DkgMsg::Pvss(pvss_msg.clone())))
        .await
        .map_err(Error::Round1Send)?;

    let pvss_messages = rounds.complete(round1).await.map_err(Error::Round1Recv)?;

    // Round 1 processing
    let mut pvss_dealings = BTreeMap::new();
    pvss_dealings.insert(my_id, pvss_msg.dealing);

    pvss_messages
        .into_iter_indexed()
        .map(|(inner_id, _, msg)| ((inner_id + 1) as Id, msg))
        .filter(|(_, msg)| lazy_verification || msg.proof.verify(&msg.dealing, pp, h))
        .take(pp.t as usize)
        .for_each(|(j, msg)| {
            pvss_dealings.insert(j, msg.dealing);
        });

    let pvss_result = JointPvssResult::new(
        pp,
        pvss_dealings
            .values()
            .take(pp.t as usize)
            .cloned()
            .collect(),
    );

    let my_share = pvss_result
        .shares_ciphertext
        .decrypt_mine(&pp.cl, my_id, my_cl_sk);

    let my_pub_share = G::generator() * &my_share;

    let dleq_proof = DleqNizk::prove(
        h,
        &pvss_result.curve_macs[&my_id],
        &G::generator(),
        &my_pub_share,
        &my_share,
    );

    let open_power_msg = OpenPowerMsg {
        point: my_pub_share,
        proof: dleq_proof,
    };

    // Round 2 interaction
    outgoing
        .send(Outgoing::broadcast(DkgMsg::PowOpen(open_power_msg.clone())))
        .await
        .map_err(Error::Round2Send)?;

    let open_power_messages = rounds.complete(round2).await.map_err(Error::Round2Recv)?;

    // Round 2 processing
    let mut pub_shares = BTreeMap::new();
    pub_shares.insert(my_id, open_power_msg.point);

    open_power_messages
        .into_iter_indexed()
        .map(|(inner_id, _, msg)| ((inner_id + 1) as Id, msg))
        .filter(|(id, msg)| {
            msg.proof
                .verify(h, &pvss_result.curve_macs[id], &G::generator(), &msg.point)
        })
        .for_each(|(j, msg)| {
            pub_shares.insert(j, msg.point);
        });

    let pk = pp.interpolate_on_curve(&pub_shares).unwrap();

    // todo: interpolate the missing public shares.

    Ok(ThresholdPubKey { pk, pub_shares })
}

pub fn simulate_pp(n: Id, t: Id) -> (PubParams, BTreeMap<Id, SecretKey>) {
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

    let mut secret_keys = BTreeMap::new();
    let mut cl_keyring = BTreeMap::new();

    for i in 1..=n {
        let sk = cl.secret_key_gen(&mut rng);
        cl_keyring.insert(i, cl.public_key_gen(&sk));
        secret_keys.insert(i, sk);
    }

    (
        PubParams {
            n,
            t,
            cl,
            cl_keyring,
        },
        secret_keys,
    )
}

#[tokio::test]
pub async fn test_dkg() {
    let (pp, secret_keys) = simulate_pp(10, 5);
    let h = G::base_point2();

    let mut simulation = Simulation::<DkgMsg>::new();
    let mut party_output = vec![];

    let now = Instant::now();

    for i in 1..=pp.n {
        let party = simulation.add_party();
        let result = dkg(party, i, &pp, h, &secret_keys[&i], false);
        party_output.push(result);
    }

    let _ = futures::future::try_join_all(party_output).await.unwrap();
    let elapsed = now.elapsed();
    println!("Elapsed: {:.2?}", elapsed);
}

/// Code for the presigning and signing protocol.

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DuoPvssMsg {
    pub k_pvss: PvssMsg,
    pub phi_pvss: PvssMsg,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MtaMsg {
    pub dealing: MtaDealing,
    pub proof: MtaNizk,
}

impl MtaMsg {
    pub fn new(
        pp: &PubParams,
        my_id: Id,
        rng: &mut RandGen,
        pvss_result: &JointPvssResult,
        scalar: &Zq,
        mac_base: &G,
        pub_base: &G,
    ) -> (Self, BTreeMap<Id, Zq>) {
        let (dealing, pairwise_shares) = MtaDealing::new(pp, my_id, pvss_result, scalar, mac_base);
        let proof = MtaNizk::prove(
            pp,
            my_id,
            pvss_result,
            &dealing,
            mac_base,
            pub_base,
            rng,
            scalar,
            &pairwise_shares,
        );

        let negated_shares = pairwise_shares
            .iter()
            .map(|(&j, share)| (j, -share))
            .collect();

        (MtaMsg { dealing, proof }, negated_shares)
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ConvMsg {
    pub open_R: OpenPowerMsg,
    pub k_phi_mta: MtaMsg,
    pub x_phi_mta: MtaMsg,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct OnlineSignMsg {
    pub fragments_u: BTreeMap<Id, Zq>,
    pub fragments_w: BTreeMap<Id, Zq>,
    pub open_Ui: OpenPowerMsg,
    pub open_Vi: OpenPowerMsg,
}

#[derive(Clone, Debug, PartialEq, ProtocolMessage, Serialize, Deserialize)]
pub enum OnlineSignMsgEnum {
    OnlineSign(OnlineSignMsg),
}

#[derive(Clone, Debug, PartialEq, ProtocolMessage, Serialize, Deserialize)]
pub enum PresignMsg {
    DuoPvss(DuoPvssMsg),
    Conv(ConvMsg),
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PresignResult {
    pub r: Zq,
    pub fragments_u: BTreeMap<Id, Zq>,
    pub fragments_w: BTreeMap<Id, Zq>,
    pub open_Ui: OpenPowerMsg,
    pub open_Vi: OpenPowerMsg,
    pub phi_i: Zq,
    pub k_pvss_result: JointPvssResult,
    pub phi_pvss_result: JointPvssResult,
    pub kphi_dealings: BTreeMap<Id, MtaDealing>,
    pub xphi_dealings: BTreeMap<Id, MtaDealing>,
    pub R_contributions: BTreeMap<Id, G>,
}


pub async fn presign_protocol<M>(
    party: M,
    my_id: Id, // in the range 1..=n, subtract one before use
    pp: &PubParams,
    mac_base: &G,
    threshold_pk: &ThresholdPubKey,
    my_cl_sk: &SecretKey,
    my_x_share: &Zq,
    lazy_verification: bool,
) -> Result<PresignResult, Error<M::ReceiveError, M::SendError>>
where
    M: Mpc<ProtocolMessage = PresignMsg>,
{
    let mut rng = RandGen::new();
    rng.set_seed(&Mpz::from(&Zq::random()));

    let mut rng2 = RandGen::new();
    rng2.set_seed(&Mpz::from(&Zq::random()));

    // boilerplate
    let MpcParty { delivery, .. } = party.into_party();
    let (incoming, mut outgoing) = delivery.split();

    let i = (my_id - 1) as u16;
    let n = pp.n as u16;

    let mut rounds = RoundsRouter::<PresignMsg>::builder();
    let round1 = rounds.add_round(RoundInput::<DuoPvssMsg>::broadcast(i, n));
    let round2 = rounds.add_round(RoundInput::<ConvMsg>::broadcast(i, n));
    let mut rounds = rounds.listen(incoming);

    // Round 1 interaction
    let (my_k_pvss, my_phi_pvss) = rayon::join(
        || PvssMsg::random(pp, &mut rng, mac_base),
        || PvssMsg::random(pp, &mut rng2, mac_base),
    );

    outgoing
        .send(Outgoing::broadcast(PresignMsg::DuoPvss(DuoPvssMsg {
            k_pvss: my_k_pvss.clone(),
            phi_pvss: my_phi_pvss.clone(),
        })))
        .await
        .map_err(Error::Round1Send)?;

    let duo_pvss_messages = rounds.complete(round1).await.map_err(Error::Round1Recv)?;

    // Round 1 filtering
    let mut k_dealings = BTreeMap::new();
    let mut phi_dealings = BTreeMap::new();

    k_dealings.insert(my_id, my_k_pvss.dealing);
    phi_dealings.insert(my_id, my_phi_pvss.dealing);

    let filtered_duo_pvss_messages = duo_pvss_messages
        .into_iter_indexed()
        .par_bridge()
        .map(|(inner_id, _, msg)| ((inner_id + 1) as Id, msg))
        .filter(|(_, msg)| {
            lazy_verification || {
                msg.k_pvss.proof.verify(&msg.k_pvss.dealing, pp, mac_base)
                    && msg
                        .phi_pvss
                        .proof
                        .verify(&msg.phi_pvss.dealing, pp, mac_base)
            }
        })
        .collect::<BTreeMap<Id, DuoPvssMsg>>();

    filtered_duo_pvss_messages
        .iter()
        .take(pp.t as usize)
        .for_each(|(&j, msg)| {
            k_dealings.insert(j, msg.k_pvss.dealing.clone());
            phi_dealings.insert(j, msg.phi_pvss.dealing.clone());
        });

    let k_pvss_result = JointPvssResult::new(
        pp,
        k_dealings.values().take(pp.t as usize).cloned().collect(),
    );
    let phi_pvss_result = JointPvssResult::new(
        pp,
        phi_dealings.values().take(pp.t as usize).cloned().collect(),
    );

    // Round 1 processing
    let Phi = phi_pvss_result.curve_polynomial.coeffs[0].clone();

    let (ki, phi_i) = rayon::join(
        || k_pvss_result.shares_ciphertext.decrypt_mine(&pp.cl, my_id, my_cl_sk),
        || phi_pvss_result.shares_ciphertext.decrypt_mine(&pp.cl, my_id, my_cl_sk),
    );

    let Ri = G::generator() * &ki;
    let dleq_proof = DleqNizk::prove(
        mac_base,
        &k_pvss_result.curve_macs[&my_id],
        &G::generator(),
        &Ri,
        &ki,
    );
    let open_R = OpenPowerMsg {
        point: Ri.clone(),
        proof: dleq_proof,
    };

    let ((my_kphi_mta, my_betas), (my_xphi_mta, my_nus)) = rayon::join(|| MtaMsg::new(
        pp,
        my_id,
        &mut rng,
        &phi_pvss_result,
        &ki,
        mac_base,
        mac_base,
    ), 
    || MtaMsg::new(
        pp,
        my_id,
        &mut rng2,
        &phi_pvss_result,
        my_x_share,
        mac_base,
        &G::generator(),
    ));

    // Round 2 interaction
    outgoing
        .send(Outgoing::broadcast(PresignMsg::Conv(ConvMsg {
            open_R,
            k_phi_mta: my_kphi_mta.clone(),
            x_phi_mta: my_xphi_mta.clone(),
        })))
        .await
        .map_err(Error::Round2Send)?;

    let conv_messages = rounds.complete(round2).await.map_err(Error::Round2Recv)?;

    // Round 2 filtering
    let mut R_contributions = BTreeMap::new();
    R_contributions.insert(my_id, Ri.clone());
    let mut kphi_dealings = BTreeMap::new();
    let mut xphi_dealings = BTreeMap::new();

    let filtered_messages = conv_messages
        .into_iter_indexed()
        .par_bridge()
        .map(|(inner_id, _, msg)| ((inner_id + 1) as Id, msg.clone()))
        .filter(|(id, msg)| {
            lazy_verification || {
                let Ki = &k_pvss_result.curve_macs[id];
                msg.open_R
                    .proof
                    .verify(mac_base, Ki, &G::generator(), &msg.open_R.point)
                    && msg.k_phi_mta.proof.verify(
                        pp,
                        *id,
                        &phi_pvss_result,
                        &msg.k_phi_mta.dealing,
                        mac_base,
                        mac_base,
                        Ki,
                    )
                    && msg.x_phi_mta.proof.verify(
                        pp,
                        *id,
                        &phi_pvss_result,
                        &msg.x_phi_mta.dealing,
                        mac_base,
                        &G::generator(),
                        &threshold_pk.pub_shares[id],
                    )
            }
        })
        .collect::<BTreeMap<Id, ConvMsg>>();

    filtered_messages.into_iter().for_each(|(j, msg)| {
        R_contributions.insert(j, msg.open_R.point);
        kphi_dealings.insert(j, msg.k_phi_mta.dealing);
        xphi_dealings.insert(j, msg.x_phi_mta.dealing);
    });

    // Round 2 processing (including some online signing pre-processing)
    let R = pp.interpolate_on_curve(&R_contributions).unwrap(); // assumes enough parties are honest
    let r = Zq::from_bigint(&R.x_coord().unwrap());

    let mask_polynomial = Polynomial {
        coeffs: iter::once(Zq::zero())
            .chain((1..pp.t).map(|_| Zq::random()))
            .collect(),
    };

    let mut fragments_u = kphi_dealings
        .iter()
        .par_bridge()
        .map(|(j, dealing)| {
            let alpha_from_j = dealing
                .shares_ciphertext
                .decrypt_mine(&pp.cl, my_id, my_cl_sk);
            let u_j = alpha_from_j + &my_betas[j] + mask_polynomial.eval(&Zq::from(*j as u64));
            (*j, u_j)
        })
        .collect::<BTreeMap<Id, Zq>>();

    let mut fragments_w = xphi_dealings
        .iter()
        .par_bridge()
        .map(|(j, dealing)| {
            let mu_from_j = dealing
                .shares_ciphertext
                .decrypt_mine(&pp.cl, my_id, my_cl_sk);
            let v_j = (mu_from_j + &my_nus[j]) * &r;
            (*j, v_j)
        })
        .collect::<BTreeMap<Id, Zq>>();

    fragments_u.insert(
        my_id,
        &ki * &phi_i + mask_polynomial.eval(&Zq::from(my_id as u64)),
    );
    fragments_w.insert(my_id, &r * my_x_share * &phi_i);

    let open_Ui = OpenPowerMsg::new(&ki, &G::generator(), &Ri, &Phi);
    let open_Vi = OpenPowerMsg::new(
        my_x_share,
        &G::generator(),
        &threshold_pk.pub_shares[&my_id],
        &Phi,
    );

    kphi_dealings.insert(my_id, my_kphi_mta.dealing);
    xphi_dealings.insert(my_id, my_xphi_mta.dealing);

    Ok(PresignResult {
        r,
        fragments_u,
        fragments_w,
        open_Ui,
        open_Vi,
        phi_i,
        k_pvss_result,
        phi_pvss_result,
        kphi_dealings,
        xphi_dealings,
        R_contributions,
    })
}

#[tokio::test]
pub async fn test_spdz_signing() {
    simulate_spdz_signing(3, 2).await;
}

pub async fn simulate_spdz_signing(n: Id, t: Id) {
    let (pp, secret_keys) = simulate_pp(n, t);
    let h = G::base_point2();

    let (threshold_pk, x_shares, _) = ThresholdPubKey::simulate(n, t);

    let mut simulation = Simulation::<PresignMsg>::new();
    let mut party_output = vec![];

    let message_hash = Zq::random();

    let now = Instant::now();

    for i in 1..=pp.n {
        let party = simulation.add_party();
        let result = presign_protocol(
            party,
            i,
            &pp,
            h,
            &threshold_pk,
            &secret_keys[&i],
            &x_shares[&i],
            false,
        );
        party_output.push(result);
    }

    let output = futures::future::try_join_all(party_output).await.unwrap();
    println!(
        "Presign time per party: {:.4?}",
        now.elapsed() / pp.n as u32
    );

    let mut simulation = Simulation::<OnlineSignMsgEnum>::new();
    let mut party_output = vec![];

    for i in 1..=pp.n {
        let party = simulation.add_party();
        let result = online_sign_protocol(
            party,
            message_hash.clone(),
            i,
            &pp,
            h,
            output[i as usize - 1].clone(),
            &threshold_pk,
            false,
        );
        party_output.push(result);
    }
    let _ = futures::future::try_join_all(party_output).await.unwrap();
    println!("Total time per party: {:.4?}", now.elapsed() / pp.n as u32);
}

pub async fn online_sign_protocol<M>(
    party: M,
    message_hash: Zq,
    my_id: Id, // in the range 1..=n, subtract one before use
    pp: &PubParams,
    h: &G,
    presignature: PresignResult,
    threshold_pk: &ThresholdPubKey,
    lazy_verification: bool,
) -> Result<ECDSASignature, Error<M::ReceiveError, M::SendError>>
where
    M: Mpc<ProtocolMessage = OnlineSignMsgEnum>,
{
    // boilerplate
    let MpcParty { delivery, .. } = party.into_party();
    let (incoming, mut outgoing) = delivery.split();

    let i = (my_id - 1) as u16;
    let n = pp.n as u16;

    let mut rounds = RoundsRouter::<OnlineSignMsgEnum>::builder();
    let round1 = rounds.add_round(RoundInput::<OnlineSignMsg>::broadcast(i, n));
    let mut rounds = rounds.listen(incoming);

    // Computation
    let mask_polynomial = Polynomial {
        coeffs: iter::once(message_hash.clone())
            .chain((1..pp.t).map(|_| Zq::random()))
            .collect(),
    };

    let fragments_w = presignature
        .fragments_w
        .iter()
        .map(|(j, w)| {
            (
                *j,
                w + mask_polynomial.eval(&Zq::from(*j as u64)) * &presignature.phi_i,
            )
        })
        .collect();

    let my_msg = OnlineSignMsg {
        fragments_u: presignature.fragments_u.clone(),
        fragments_w,
        open_Ui: presignature.open_Ui.clone(),
        open_Vi: presignature.open_Vi.clone(),
    };

    // Round 1 interaction
    outgoing
        .send(Outgoing::broadcast(OnlineSignMsgEnum::OnlineSign(
            my_msg.clone(),
        )))
        .await
        .map_err(Error::Round1Send)?;

    let online_sign_messages = rounds.complete(round1).await.map_err(Error::Round1Recv)?;

    // Round 1 filtering
    let mut filtered_messages = online_sign_messages
        .into_iter_indexed()
        .par_bridge()
        .map(|(inner_id, _, msg)| ((inner_id + 1) as Id, msg))
        .filter(|(i, msg)| {
            lazy_verification || {
                let Phi = presignature.phi_pvss_result.curve_polynomial.coeffs[0].clone();
                msg.open_Ui.proof.verify(
                    &G::generator(),
                    &presignature.R_contributions[i],
                    &Phi,
                    &msg.open_Ui.point,
                ) && msg.open_Vi.proof.verify(
                    &G::generator(),
                    &threshold_pk.pub_shares[i],
                    &Phi,
                    &msg.open_Vi.point,
                ) && {
                    let h_pow_interpolated = h * pp.interpolate(&msg.fragments_u).unwrap();
                    let A_mac_diffs = msg
                        .fragments_u
                        .keys()
                        .map(|l| {
                            if l == i {
                                (*l, G::zero())
                            } else {
                                (
                                    *l,
                                    &presignature.kphi_dealings[i].curve_macs[l]
                                        - &presignature.kphi_dealings[l].curve_macs[i],
                                )
                            }
                        })
                        .collect();
                    let A_mac_diffs_interpolated = pp.interpolate_on_curve(&A_mac_diffs).unwrap();
                    h_pow_interpolated + A_mac_diffs_interpolated == msg.open_Ui.point
                } && {
                    let h_pow_interpolated = h * pp.interpolate(&msg.fragments_w).unwrap();
                    let M_mac_diffs = msg
                        .fragments_w
                        .keys()
                        .map(|l| {
                            if l == i {
                                (*l, G::zero())
                            } else {
                                (
                                    *l,
                                    &presignature.xphi_dealings[i].curve_macs[l]
                                        - &presignature.xphi_dealings[l].curve_macs[i],
                                )
                            }
                        })
                        .collect();
                    let M_mac_diffs_interpolated =
                        pp.interpolate_on_curve(&M_mac_diffs).unwrap() * &presignature.r;
                    h_pow_interpolated + M_mac_diffs_interpolated
                        == &msg.open_Vi.point * &presignature.r
                            + &presignature.phi_pvss_result.curve_macs[i] * &message_hash
                }
            }
        })
        .collect::<BTreeMap<Id, OnlineSignMsg>>();

    filtered_messages.insert(my_id, my_msg);

    let mut u_shares = BTreeMap::new();
    let mut w_shares = BTreeMap::new();

    filtered_messages.iter().for_each(|(j, msg)| {
        let fragments_u_filtered = msg
            .fragments_u
            .clone()
            .into_iter()
            .filter(|(l, _)| filtered_messages.contains_key(l))
            .collect();
        if let Some(u_j) = pp.interpolate(&fragments_u_filtered) {
            u_shares.insert(*j, u_j);
        }

        let fragments_w_filtered = msg
            .fragments_w
            .clone()
            .into_iter()
            .filter(|(l, _)| filtered_messages.contains_key(l))
            .collect();
        if let Some(w_j) = pp.interpolate(&fragments_w_filtered) {
            w_shares.insert(*j, w_j);
        }
    });

    let u = pp.interpolate(&u_shares).unwrap();
    let w = pp.interpolate(&w_shares).unwrap();
    let s = w * u.invert().unwrap();

    Ok(ECDSASignature {
        r: presignature.r,
        s,
    })
}
