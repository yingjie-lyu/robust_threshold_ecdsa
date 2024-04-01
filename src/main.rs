use std::{
    collections::BTreeMap, io,
};
use bicycl::{CL_HSMqk, Mpz, PublicKey, RandGen, SecretKey};
use curv::elliptic::curves::{Secp256k1, Point};
use futures::SinkExt;
// use round_optimal_robust_threshold_ecdsa::{
//     *,
//     ni_dkg::{PvssDealing, NiDkgOutput},
//     tests::{Msg, Error},
// };
use round_based::{
    rounds_router::simple_store::RoundInput, rounds_router::RoundsRouter, simulation::Simulation,
    Delivery, Mpc, MpcParty, Outgoing, PartyIndex,
};

use robust_threshold_ecdsa::spdz;

// mod tests;

#[tokio::main]
async fn main() {
    // println!("Hello, world!");
    // spdz::test_presign_protocol().await;
}


// #[tokio::main]
// async fn main() {
//     let n: u16 = 3;
//     let t: usize = 2;

//     let mut simulation = Simulation::<Msg>::new();
//     let mut party_output = vec![];

//     let seed = Mpz::from(chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default());
//     let mut rand_gen = RandGen::new();
//     rand_gen.set_seed(&seed);

//     let q = Mpz::from("115792089237316195423570985008687907852837564279074904382605163141518161494337");
//     let clgroup = CL_HSMqk::with_rand_gen(&q, 1, 150, &mut rand_gen, &Mpz::from(0i64), false);

//     let mut clsk = BTreeMap::<usize, SecretKey>::new();
//     let mut clpk = BTreeMap::<usize, PublicKey>::new();

//     println!("Please enter a message to be signed:");
//     let mut message = String::new();
//     io::stdin().read_line(&mut message)
//         .expect("Failed to read line");
//     message = message.trim().to_string();

//     for i in 0..n {
//         let sk_i = clgroup.secret_key_gen(&mut rand_gen);
//         let pk_i = clgroup.public_key_gen(&sk_i);
//         // clgroup.gq
//         clsk.insert(i.into(), sk_i);
//         clpk.insert(i.into(), pk_i);
//     }

//     for i in 0..n {
//         let party = simulation.add_party();
//         let mysk = clsk[&(i as usize)].clone();

//         let mut rand = RandGen::new();
//         rand.set_seed(&rand_gen.random_mpz(&clgroup.encrypt_randomness_bound()));

//         let output =
//             protocol_dkg_presign_sign(message.clone(), party, i, t, n.into(), clgroup.clone(), rand, clpk.clone(), mysk);
//         party_output.push(output);
//     }

//     let _output = futures::future::try_join_all(party_output).await.unwrap();
//     for (sig, pk) in &_output {
//         println!("-----------------------------------");
//         println!("SignatureECDSA = {}", sig);
//         if let (Some(x), Some(y)) = (pk.x_coord(), pk.y_coord()) {
//             println!("Public key = {{\n\tx = {},\n\ty = {}\n}}", x, y);
//         }
//     }
//     println!("-----------------------------------");
//     let failed_count = _output.iter().filter(|(sig, pk)| !sig.verify(pk, &message)).count();
//     if failed_count == 0 {
//         println!("All signatures verified passed!");
//     } else {
//         println!("Partial signature verification failed!!");
//     }
// }

// pub async fn protocol_dkg_presign_sign<M>(
//     msg: String,
//     party: M,
//     myid: PartyIndex,
//     t: usize,
//     n: usize,
//     clgroup: CL_HSMqk,
//     mut rand_gen: RandGen,
//     clpk: BTreeMap<usize, PublicKey>,
//     mysk: SecretKey,
// ) -> Result<(SignatureECDSA, Point<Secp256k1>), Error<M::SendError, M::ReceiveError>>
//     where
//         M: Mpc<ProtocolMessage=Msg>,
// {
//     let parties: Vec<usize> = (0..n).collect();
//     let parties_excl_myself: Vec<usize> = (0..n).filter(|j| *j != (myid as usize)).collect();

//     let n_u16 = u16::try_from(n).unwrap();
//     let MpcParty { delivery, .. } = party.into_party();
//     let (incoming, mut outgoing) = delivery.split();
//     let mut rounds = RoundsRouter::<Msg>::builder();
//     let round0 = rounds.add_round(RoundInput::<PvssDealing>::broadcast(myid, n_u16));
//     let round1 = rounds.add_round(RoundInput::<NonceGenMsg>::broadcast(myid, n_u16));
//     let round2 = rounds.add_round(RoundInput::<MtAwcMsg>::broadcast(myid, n_u16));
//     let round3 = rounds.add_round(RoundInput::<PreSignFinalMsg>::broadcast(myid, n_u16));
//     let round4 = rounds.add_round(RoundInput::<OnlineSignMsg>::broadcast(myid, n_u16));
//     let mut rounds = rounds.listen(incoming);

//     // Step 0: DKG of x
//     let my_ni_dkg_msg = PvssDealing::new(t, parties.clone(), &clgroup, &mut rand_gen, &clpk);

//     outgoing
//         .send(Outgoing::broadcast(Msg::NiDkgMsg(my_ni_dkg_msg.clone())))
//         .await
//         .unwrap();

//     let x_dkg_messages = rounds
//         .complete(round0)
//         .await
//         .unwrap()
//         .into_vec_including_me(my_ni_dkg_msg);

//     let x_dkg_output = NiDkgOutput::from_combining(
//         parties.clone(),
//         &x_dkg_messages,
//         myid.into(),
//         clgroup.clone(),
//         &mut rand_gen,
//         false,
//         clpk.clone(),
//         &mysk,
//     );

//     // Step 1: Generation of nonces k and gamma
//     let my_nonce_gen_msg = NonceGenMsg {
//         k_dkg_msg: PvssDealing::new(t, parties.clone(), &clgroup, &mut rand_gen, &clpk),
//         gamma_dkg_msg: PvssDealing::new(t, parties.clone(), &clgroup, &mut rand_gen, &clpk),
//     };

//     outgoing
//         .send(Outgoing::broadcast(Msg::NonceGenMsg(
//             my_nonce_gen_msg.clone(),
//         )))
//         .await
//         .unwrap();

//     let nonce_gen_messages = rounds
//         .complete(round1)
//         .await
//         .unwrap()
//         .into_vec_including_me(my_nonce_gen_msg);

//     // Step 1->2 transition: prepare input from output
//     let (k_dkg_messages, gamma_dkg_messages): (Vec<_>, Vec<_>) = nonce_gen_messages
//         .into_iter()
//         .map(|msg| (msg.k_dkg_msg, msg.gamma_dkg_msg))
//         .unzip();

//     let k_dkg_output = NiDkgOutput::from_combining(
//         x_dkg_output.parties.clone(),
//         &k_dkg_messages,
//         myid.into(),
//         clgroup.clone(),
//         &mut rand_gen,
//         true,
//         clpk.clone(),
//         &mysk,
//     );

//     let gamma_dkg_output = NiDkgOutput::from_combining(
//         x_dkg_output.parties.clone(),
//         &gamma_dkg_messages,
//         myid.into(),
//         clgroup.clone(),
//         &mut rand_gen,
//         false,
//         clpk.clone(),
//         &mysk,
//     );

//     // Step 2: Nonce conversion, or MtAwc
//     let (my_mta_msg, betas, nus) = MtAwcMsg::new(
//         parties_excl_myself.clone(),
//         myid.into(),
//         clgroup.clone(),
//         &mut rand_gen,
//         &clpk,
//         k_dkg_output.clone(),
//         gamma_dkg_output.clone().share,
//         x_dkg_output.clone().share,
//     );

//     outgoing
//         .send(Outgoing::broadcast(Msg::MtAwcMsg(my_mta_msg.clone())))
//         .await
//         .unwrap();

//     // we want MtA messages, excluding myself's, to be arranged into a BTreeMap for Step 3
//     let mut mta_messages: BTreeMap<usize, MtAwcMsg> = rounds
//         .complete(round2)
//         .await
//         .unwrap()
//         .into_iter_indexed()
//         .map(|(j, _, msg)| (j.into(), msg))
//         .collect();
//     mta_messages.insert(myid.into(), my_mta_msg);


//     // Step 3: PreSign final round aka Share Revelation
//     let (my_presign_final_msg, mus_to_me, nus) = PreSignFinalMsg::new(
//         parties_excl_myself.clone(),
//         t,
//         myid.into(),
//         mta_messages.clone(),
//         clgroup.clone(),
//         &mut rand_gen,
//         mysk,
//         betas,
//         nus,
//         gamma_dkg_output.clone(),
//         x_dkg_output.clone(),
//         k_dkg_output.clone().share,
//     );

//     outgoing
//         .send(Outgoing::broadcast(Msg::PreSignFinalMsg(
//             my_presign_final_msg.clone(),
//         )))
//         .await
//         .unwrap();

//     let mut presign_final_messages: BTreeMap<usize, PreSignFinalMsg> = rounds
//         .complete(round3)
//         .await
//         .unwrap()
//         .into_iter_indexed()
//         .map(|(j, _, msg)| (j.into(), msg))
//         .collect();
//     presign_final_messages.insert(myid.into(), my_presign_final_msg);

//     // and finally you may follow me; farewell he said
//     let presignature = PreSignature::from(
//         parties.clone(),
//         myid.into(),
//         mta_messages,
//         presign_final_messages,
//         mus_to_me,
//         nus,
//         gamma_dkg_output.pk,
//         k_dkg_output.clone(),
//     );

//     // Step 4: Online Signing
//     let (my_online_sign_msg, r, m) = OnlineSignMsg::new(
//         msg,
//         parties_excl_myself,
//         t,
//         myid.into(),
//         x_dkg_output.clone(),
//         presignature.clone(),
//         k_dkg_output.share.clone(),
//     );

//     outgoing
//         .send(Outgoing::broadcast(Msg::OnlineSignMsg(
//             my_online_sign_msg.clone(),
//         )))
//         .await
//         .unwrap();

//     let mut online_sign_messages: BTreeMap<usize, OnlineSignMsg> = rounds
//         .complete(round4)
//         .await
//         .unwrap()
//         .into_iter_indexed()
//         .map(|(j, _, msg)| (j.into(), msg))
//         .collect();
//     online_sign_messages.insert(myid.into(), my_online_sign_msg);

//     let pk = x_dkg_output.pk.clone();

//     let signature = SignatureECDSA::from(
//         parties,
//         myid.into(),
//         online_sign_messages,
//         r,
//         m,
//         presignature,
//         x_dkg_output.clone(),
//     );

//     // let tt = x_dkg_output.pk.x_coord();
//     // if let Some(xx) = x_dkg_output.pk.x_coord() {
//     //     println!("ddd = {}", xx);
//     // }


//     Ok((signature, pk))
// }
