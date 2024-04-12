use robust_threshold_ecdsa::{cdn, spdz};
use std::env;

#[tokio::main]
async fn main() {
    // read the arguments
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        println!("Usage: {} <parties> <repeats>", args[0]);
        return;
    }

    // parse the number
    let n: u8 = match args[1].parse() {
        Ok(n) => n,
        Err(_) => {
            println!("Error: invalid number");
            return;
        }
    };

    // parse the number
    let r: u8 = match args[2].parse() {
        Ok(r) => r,
        Err(_) => {
            println!("Error: invalid number");
            return;
        }
    };

    // repeat the experiment
    for _ in 0..r {
        // run the experiment
        let (presign, online) = spdz::simulate_spdz_signing(n, n).await;
        println!("{}, {}, {}", n, presign, online);
    }
}
