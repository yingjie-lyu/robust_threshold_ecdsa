# Round-Optimal[^1] Robust Threshold ECDSA

A Thesis Project at Shandong University.

Warning: the source code is research-grade and should not be used in production!

Building the binaries requires a Rust installation and is tested on Linux.
```
cd ROR-TECDSA
cargo build
cargo test -- --test-threads=1
```
[^1]: As of the time of writing, i.e. May 22, 2023. This scheme consists of 3 rounds of pre-signing (on the happy path) and one round of online signing; shortly after that, a new scheme with a total of 3 rounds is proposed at ia.cr/2023/765.
