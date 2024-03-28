use bicycl::{CL_HSMqk, CipherText, ClearText, Mpz, PublicKey, RandGen, SecretKey, QFI};
use curv::{arithmetic::Converter, BigInt};
use futures::SinkExt;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
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
    pub fn new(secret: &Zq, gen1: &G, gen2: &G, pow1: &G) -> Self {
        let point = gen2 * secret;
        let proof = DleqNizk::prove(gen1, gen2, pow1, &point, secret);

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
    let start = Instant::now();
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

    let my_ciphertext = CipherText::new(
        &pvss_result.shares_ciphertext.randomness,
        &pvss_result.shares_ciphertext.encryption[&my_id],
    );

    let my_share = Zq::from(BigInt::from_bytes(
        &pp.cl.decrypt(my_cl_sk, &my_ciphertext).mpz().to_bytes(),
    ));

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

    let lagrange_coeffs = pp
        .lagrange_coeffs(pub_shares.keys().copied().collect())
        .unwrap();
    let pk = pub_shares
        .iter()
        .map(|(i, share)| &lagrange_coeffs[i] * share)
        .sum();

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
    let (pp, secret_keys) = simulate_pp(3, 2);
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
