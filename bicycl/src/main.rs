
mod lib;
use lib::*;

fn main() {
    let timestamp = chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default();
    println!("seed = {}", timestamp);
    let seed = Mpz::from(timestamp);
    println!("seed Mpz = {}", seed.str_value());

    let mut randgen = RandGen::new();

    randgen.set_seed(&seed);

    check(&mut randgen, 50, 1, 150);
}

fn check(randgen: &mut RandGen, q_nbits: usize, k: usize, delta_ok_nbits: usize) {
    let fud_factor: Mpz = Mpz::from(0i64);
    let mut c = CL_HSMqk::with_qnbits_rand_gen(q_nbits, k, delta_ok_nbits, randgen, &fud_factor, false);

    println!("****************************************");
    cl_hsmqk_encrypt(&mut c, randgen);
    println!("****************************************");
    cl_hsmqk_CL_zkaok_encrypt(&mut c, randgen);
    println!("****************************************");
}

fn cl_hsmqk_encrypt(c: &mut CL_HSMqk, randgen: &mut RandGen) {
    let sk = c.secret_key_gen(randgen);
    let pk = c.public_key_gen(&sk);
    let m = ClearText::with_rand_gen(&c, randgen);
    println!("ClearText m = {}", m.str_value());
    let m1 = ClearText::with_mpz(&c, &Mpz::from(5i64));
    println!("ClearText m1 = {}", m1.str_value());

    let ct = c.encrypt(&pk, &m, randgen);
    let ct1 = c.encrypt(&pk, &m1, randgen);

    let ct_add = c.add_ciphertexts(&pk, &ct, &ct1, randgen);

    let clear_add = c.decrypt(&sk, &ct_add);
    println!("ClearText clear_add = {}", clear_add.str_value());
}

fn cl_hsmqk_CL_zkaok_encrypt(c: &mut CL_HSMqk, randgen: &mut RandGen) {

    let zk = CL_HSMqk_ZKAoK::with_rand_gen(c, randgen);

    let sk = zk.secret_key_gen(randgen);
    let pk = zk.public_key_gen(&sk);

    let m = ClearText::with_rand_gen(&c, randgen);
    println!("ClearText m = {}", m.str_value());
    let r = randgen.random_mpz(&zk.encrypt_randomness_bound());
    let ct = zk.encrypt(&pk, &m, randgen);
    let proof = zk.noninteractive_proof(&pk, &ct, &m, &r, randgen);

    println!("Proof result = {}", proof.verify(&zk, &pk, &ct));
    println!("Proof result = {}", zk.noninteractive_verify(&pk, &ct, &proof));
}

