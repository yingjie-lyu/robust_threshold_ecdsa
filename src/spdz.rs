use bicycl::{CL_HSMqk, CipherText, ClearText, Mpz, PublicKey, RandGen, SecretKey, QFI};
use curv::{arithmetic::Converter, BigInt};
use ecdsa::Signature;
use futures::{stream::{futures_unordered::Iter, once}, SinkExt};
use rayon::iter::{ParallelBridge, ParallelIterator, MapWith};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, iter};
use std::time::Instant;

use crate::utils::*;

use round_based::{
    rounds_router::{
        simple_store::{RoundInput, RoundInputError},
        CompleteRoundError, RoundsRouter,
    },
    simulation::Simulation,
};
use round_based::{Delivery, Mpc, MpcParty, MsgId, Outgoing, PartyIndex, ProtocolMessage};
use thiserror::Error;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PvssMsg {
    dealing: PvssDealing,
    proof: PvssNizk,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct OpenPowerMsg {
    point: G,
    proof: DleqNizk,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ThresholdPubKey {
    pk: G,
    pub_shares: BTreeMap<Id, G>,
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

    let my_share = pvss_result.shares_ciphertext.decrypt_mine(&pp.cl, my_id, my_cl_sk);

    let my_pub_share = G::generator() * &my_share;

    let dleq_proof = DleqNizk::prove(
        &h,
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
                .verify(&h, &pvss_result.curve_macs[id], &G::generator(), &msg.point)
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
        let result = dkg(party, i, &pp, &h, &secret_keys[&i], false);
        party_output.push(result);
    }

    let output = futures::future::try_join_all(party_output).await.unwrap();
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
        rng: &mut RandGen,
        pvss_result: &JointPvssResult,
        scalar: &Zq,
        mac_base: &G,
        pub_base: &G,
    ) -> (Self, BTreeMap<Id, Zq>) {
        let (dealing, pairwise_shares) = MtaDealing::new(pp, pvss_result, scalar, mac_base);
        let proof = MtaNizk::prove(
            pp,
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
pub enum PresignMsg {
    DuoPvss(DuoPvssMsg),
    Conv(ConvMsg),
}


/// Note: there are quite a few temporaries so we refrain from splitting
///  the presigning and signing protocols into separate functions.
pub async fn presign_protocol<M>(
    party: M,
    my_id: Id, // in the range 1..=n, subtract one before use
    pp: &PubParams,
    h: &G,
    threshold_pk: &ThresholdPubKey,
    my_cl_sk: &SecretKey,
    my_x_share: &Zq,
    lazy_verification: bool,
) -> Result<(), Error<M::ReceiveError, M::SendError>>
// Result<Signature<Secp256k1>, Error<M::ReceiveError, M::SendError>>
where
    M: Mpc<ProtocolMessage = PresignMsg>,
{
    let mut rng = RandGen::new();
    rng.set_seed(&Mpz::from(&Zq::random()));

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
    let my_k_pvss = PvssMsg::random(pp, &mut rng, h);
    let my_phi_pvss = PvssMsg::random(pp, &mut rng, h);

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
                msg.k_pvss.proof.verify(&msg.k_pvss.dealing, pp, h)
                    && msg.phi_pvss.proof.verify(&msg.phi_pvss.dealing, pp, h)
            }
        })
        .collect::<BTreeMap<Id, DuoPvssMsg>>();

    filtered_duo_pvss_messages.iter().take(pp.t as usize)
        .for_each(|(&j, msg)| {
            k_dealings.insert(j, msg.k_pvss.dealing.clone());
            phi_dealings.insert(j, msg.phi_pvss.dealing.clone());
        });

    let k_pvss_result = JointPvssResult::new(pp,k_dealings.values().take(pp.t as usize).cloned().collect());
    let phi_pvss_result = JointPvssResult::new(pp,phi_dealings.values().take(pp.t as usize).cloned().collect());

    // Round 1 processing
    let Phi = phi_pvss_result.curve_polynomial.coeffs[0].clone();

    let ki = k_pvss_result.shares_ciphertext.decrypt_mine(&pp.cl, my_id, my_cl_sk);
    let phi_i = phi_pvss_result.shares_ciphertext.decrypt_mine(&pp.cl, my_id, my_cl_sk);

    let Ri = G::generator() * &ki;
    let dleq_proof = DleqNizk::prove(&h, &k_pvss_result.curve_macs[&my_id], &G::generator(), &Ri, &ki);
    let open_R = OpenPowerMsg { point: Ri.clone(), proof: dleq_proof };

    let (my_kphi_mta, my_betas) = MtaMsg::new(pp, &mut rng, &phi_pvss_result, &ki, h, h);
    let (my_xphi_mta, my_nus) = MtaMsg::new(pp, &mut rng, &phi_pvss_result, my_x_share, h, &G::generator());

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
                msg.open_R.proof.verify( h,Ki,&G::generator(),&msg.open_R.point)
                 && msg.k_phi_mta.proof.verify(pp,&phi_pvss_result,&msg.k_phi_mta.dealing,h,h, Ki)
                 && msg.x_phi_mta.proof.verify(pp,&phi_pvss_result,&msg.x_phi_mta.dealing,h, &G::generator(),&threshold_pk.pub_shares[id])
            }
        })
        .collect::<BTreeMap<Id, ConvMsg>>();

    filtered_messages.iter().for_each(|(&j, msg)| {
        R_contributions.insert(j, msg.open_R.point.clone());
        kphi_dealings.insert(j, msg.k_phi_mta.dealing.clone());
        xphi_dealings.insert(j, msg.x_phi_mta.dealing.clone());
    });

    // Round 2 processing
    let R = pp.interpolate_on_curve(&R_contributions).unwrap();  // assumes enough parties are honest
    let r = Zq::from_bigint(&R.x_coord().unwrap());

    let mut fragments_u = BTreeMap::new();
    let mut fragments_w = BTreeMap::new();
    
    let mask_polynomial = Polynomial {coeffs: iter::once(Zq::zero()).chain( (1..pp.t).map(|_| Zq::random())).collect()};
    kphi_dealings.iter().for_each(|(j, dealing)| {
        let alpha_from_j = dealing.shares_ciphertext.decrypt_mine(&pp.cl, my_id, my_cl_sk);
        let u_j = alpha_from_j + &my_betas[j] + mask_polynomial.eval(&Zq::from(*j as u64));
        fragments_u.insert(j, u_j);
    });

    xphi_dealings.iter().for_each(|(j, dealing)| {
        let mu_from_j = dealing.shares_ciphertext.decrypt_mine(&pp.cl, my_id, my_cl_sk);
        let v_j = (mu_from_j + &my_nus[j]) * &r;
        fragments_w.insert(j, v_j);
    });

    fragments_u.insert(&my_id, &ki * &phi_i + mask_polynomial.eval(&Zq::from(my_id as u64)));
    fragments_w.insert(&my_id, &r * my_x_share * &phi_i);

    let open_Ui = OpenPowerMsg::new(&ki, &G::generator(), &Ri, &Phi );
    let open_Vi = OpenPowerMsg::new(&my_x_share, &G::generator(), &threshold_pk.pk,&Phi);


    kphi_dealings.insert(my_id, my_kphi_mta.dealing);
    xphi_dealings.insert(my_id, my_xphi_mta.dealing);

    Ok(())
}



// #[tokio::test]
pub async fn test_presign_protocol() {
    let (pp, secret_keys) = simulate_pp(10, 9);
    let h = G::base_point2();

    // simulate threshold public & secret keys
    let coeffs = (0..pp.t).map(|_| Zq::random()).collect();
    let polynomial = Polynomial { coeffs };
    let curve_polynomial = CurvePolynomial::from_exp(&polynomial, &G::generator());

    let threshold_pk = ThresholdPubKey {
        pk: curve_polynomial.coeffs[0].clone(),
        pub_shares: (1..=pp.n).map(|i| (i, curve_polynomial.eval(&Zq::from(i as u64)))).collect(),
    };

    let x_shares: BTreeMap<Id, Zq> = (1..=pp.n).map(|i| (i, polynomial.eval(&Zq::from(i as u64)))).collect();


    let mut simulation = Simulation::<PresignMsg>::new();
    let mut party_output = vec![];

    let now = Instant::now();

    for i in 1..=pp.n {
        let party = simulation.add_party();
        let result = presign_protocol(
            party,
            i,
            &pp,
            &h,
            &threshold_pk,
            &secret_keys[&i],
            &x_shares[&i],
            false,
        );
        party_output.push(result);
    }

    let output = futures::future::try_join_all(party_output).await.unwrap();
    let elapsed = now.elapsed();
    println!("Elapsed: {:.2?}", elapsed);
}