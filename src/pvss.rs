use bicycl::{QFI, CipherText, PublicKey, SecretKey, CL_HSMqk, Mpz, RandGen, ClearText};
use std::ops::{Add, Mul};

pub struct Polynomial<Coeff, Scalar>
 where Coeff: Mul<Rhs = Scalar> {
    pub coeffs: Vec<Coeff>
}

impl Polynomial {
    
}
