use std::fmt::{Debug, Formatter};
use std::iter::Sum;
use std::ops::{Add, Mul};
use autocxx::prelude::*;
include_cpp! {
    #include "bicycl.h"
    safety!(unsafe_ffi)
    generate!("BICYCL::QFI")
    generate!("BICYCL::Mpz")
    generate!("BICYCL::RandGen")
    generate!("BICYCL::CL_HSMqk")
    generate!("BICYCL::CL_HSMqk_ZKAoK")
    generate!("BICYCL::CL_HSMqk_ZKAoK_Proof")
    generate!("BICYCL::CL_HSMqk_ClearText")
    generate!("BICYCL::CL_HSMqk_SecretKey")
    generate!("BICYCL::CL_HSMqk_PublicKey")
    generate!("BICYCL::CL_HSMqk_CipherText")
    generate!("BICYCL::CL_HSMqk_ClearText")
    generate!("BICYCL::ClassGroup")
}

use std::pin::Pin;
use crate::ffi::BICYCL;
use autocxx::{c_long, c_ulong};
use cxx::{CxxString, let_cxx_string};
use serde::{Serialize, Deserialize, Serializer, Deserializer};

pub struct Mpz {
    mpz: Pin<Box<BICYCL::Mpz>>,
}

impl From<i64> for Mpz {
    fn from(value: i64) -> Self {
        Mpz {
            mpz: BICYCL::Mpz::new4(c_long(value)).within_box()
        }
    }
}

impl From<u64> for Mpz {
    fn from(value: u64) -> Self {
        Mpz {
            mpz: BICYCL::Mpz::new3(c_ulong(value)).within_box()
        }
    }
}

impl<'a> From<&'a str> for Mpz {
    fn from(value: &'a str) -> Self {
        let_cxx_string!(t = value);
        Mpz {
            mpz: BICYCL::Mpz::new5(&t).within_box()
        }
    }
}

impl Mul for Mpz {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        let mut r = BICYCL::Mpz::new().within_box();
        BICYCL::Mpz::mul(r.as_mut(), &*self.mpz, &*rhs.mpz);
        Mpz {
            mpz: r,
        }
    }
}

impl<'a> Mul<&'a Mpz> for Mpz {
    type Output = Mpz;

    fn mul(self, rhs: &'a Mpz) -> Mpz {
        let mut r = BICYCL::Mpz::new().within_box();
        BICYCL::Mpz::mul(r.as_mut(), &*self.mpz, &*rhs.mpz);
        Mpz {
            mpz: r,
        }
    }
}

impl Sum for Mpz {
    fn sum<I: Iterator<Item=Self>>(iter: I) -> Self {
        let mut result = BICYCL::Mpz::new3(c_ulong::from(0)).within_box();
        for item in iter {
            let temp = BICYCL::Mpz::copy_from(&*result).within_box();
            BICYCL::Mpz::add(result.as_mut(), &*temp, &*item.mpz);
        }
        Mpz {
            mpz: result
        }
    }
}

impl Add for Mpz {
    type Output = Mpz;

    fn add(self, rhs: Mpz) -> Mpz {
        let mut result = BICYCL::Mpz::new().within_box();
        BICYCL::Mpz::add(result.as_mut(), &*self.mpz, &*rhs.mpz);
        Mpz {
            mpz: result
        }
    }
}

impl<'a> Add<Mpz> for &'a Mpz {
    type Output = Mpz;

    fn add(self, rhs: Mpz) -> Mpz {
        let mut result = BICYCL::Mpz::new().within_box();
        BICYCL::Mpz::add(result.as_mut(), &*self.mpz, &*rhs.mpz);
        Mpz {
            mpz: result
        }
    }
}

// TODO: @wangshuchao `*const u8` cannot be sent between threads safely
unsafe impl Send for Mpz {
}

impl Clone for Mpz {
    fn clone(&self) -> Self {
        Mpz {
            mpz: BICYCL::Mpz::copy_from(&*self.mpz).within_box(),
        }
    }
}

impl Debug for Mpz {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Mpz {{ mpz: {} }}", self.to_string())
    }
}

impl PartialEq for Mpz {
    fn eq(&self, other: &Self) -> bool {
        self.mpz.is_equal(&*other.mpz)
    }
}

impl ToString for Mpz {
    fn to_string(&self) -> String {
        self.mpz.str_value().to_string()
    }
}

impl Mpz {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Mpz {
            mpz: Mpz::bicycl_mpz_with_vec(&bytes.to_vec())
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut vec = cxx::CxxVector::<u8>::new();
        self.mpz.to_bytes(vec.pin_mut());

        vec.as_slice().to_vec()
    }

    fn bicycl_mpz_with_vec(vec: &Vec<u8>) -> Pin<Box<BICYCL::Mpz>> {
        // TODO: ugly
        let mut cxx_vec = cxx::CxxVector::<u8>::new();
        for byte in vec {
            cxx_vec.pin_mut().push(*byte);
        }
        BICYCL::Mpz::new8(&*cxx_vec, cxx_vec.len() * 8).within_box()
    }

    pub fn pow(&self, exponent: u64) -> Self {
        let mut res = BICYCL::Mpz::new().within_box();
        BICYCL::Mpz::pow(res.as_mut(), &*self.mpz, c_ulong::from(exponent));
        Mpz {
            mpz: res
        }
    }
}

#[derive(Serialize, Deserialize)]
struct SerializableMpz {
    bytes: Vec<u8>,
}

impl From<&BICYCL::Mpz> for SerializableMpz {
    fn from(mpz: &BICYCL::Mpz) -> Self {
        let mut vec = cxx::CxxVector::<u8>::new();
        mpz.to_bytes(vec.pin_mut());

        SerializableMpz {
            bytes: vec.as_slice().to_vec(),
        }
    }
}

impl Serialize for Mpz {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error> where S: Serializer {
        let se_mpz = SerializableMpz::from(&*self.mpz);

        se_mpz.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Mpz {

    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error> where D: Deserializer<'de> {
        let se_mpz = SerializableMpz::deserialize(deserializer)?;

        Ok(Mpz {
            mpz: Mpz::bicycl_mpz_with_vec(&se_mpz.bytes)
        })
    }
}

pub struct RandGen {
    rand_gen: Pin<Box<BICYCL::RandGen>>,
}

impl Clone for RandGen {
    fn clone(&self) -> Self {
        RandGen {
            rand_gen: self.rand_gen.copy().within_box()
        }
    }
}

impl RandGen {
    pub fn new() -> RandGen {
        RandGen {
            rand_gen: BICYCL::RandGen::new().within_box(),
        }
    }

    pub fn set_seed(&mut self, seed: &Mpz) {
        self.rand_gen.as_mut().set_seed(&seed.mpz);
    }

    pub fn random_mpz(&mut self, m: &Mpz) -> Mpz {
        Mpz {
            mpz: self.rand_gen.as_mut().random_mpz(&*m.mpz).within_box()
        }
    }
}

pub struct QFI {
    qfi: Pin<Box<BICYCL::QFI>>,
}

impl QFI {
    pub fn from_mpz(a: &Mpz, b: &Mpz, c: &Mpz) -> Self {
        QFI {
            qfi: BICYCL::QFI::new1(&*a.mpz, &*b.mpz, &*c.mpz, true).within_box()
        }
    }

    pub fn a(&self) -> Mpz {
        Mpz {
            mpz: BICYCL::Mpz::copy_from(self.qfi.a()).within_box(),
        }
    }
    pub fn b(&self) -> Mpz {
        Mpz {
            mpz: BICYCL::Mpz::copy_from(self.qfi.b()).within_box(),
        }
    }
    pub fn c(&self) -> Mpz {
        Mpz {
            mpz: BICYCL::Mpz::copy_from(self.qfi.c()).within_box(),
        }
    }

    pub fn compose(&self, c: &CL_HSMqk, qf2: &QFI) -> Self {
        let mut result = BICYCL::QFI::new().within_box();
        c.c.Cl_G().nucomp(result.as_mut(), &*self.qfi, &*qf2.qfi);
        QFI {
            qfi: result
        }
    }

    pub fn exp(&self, c: &CL_HSMqk, n: &Mpz) -> Self {
        let mut result = BICYCL::QFI::new().within_box();
        c.c.Cl_G().nupow(result.as_mut(), &*self.qfi, &*n.mpz);
        QFI {
            qfi: result
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut a_vec = self.a().to_bytes();
        let b_vec = self.b().to_bytes();
        let c_vec = self.c().to_bytes();
        a_vec.extend_from_slice(&b_vec[..]);
        a_vec.extend_from_slice(&c_vec[..]);
        a_vec
    }
}

// TODO: @wangshuchao `*const u8` cannot be sent between threads safely
unsafe impl Send for QFI {
}

impl Clone for QFI {
    fn clone(&self) -> Self {
        QFI {
            qfi: BICYCL::QFI::copy_from(&*self.qfi).within_box(),
        }
    }
}

impl Debug for QFI {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "QFI {{ a: {}, b: {}, c: {} }}", self.a().to_string(), self.b().to_string(), self.c().to_string())
    }
}

impl PartialEq for QFI {
    fn eq(&self, other: &Self) -> bool {
        self.qfi.is_equal(&*other.qfi)
    }
}

#[derive(Serialize, Deserialize)]
struct SerializableQFI {
    a: Vec<u8>,
    b: Vec<u8>,
    c: Vec<u8>,
}

impl From<&BICYCL::QFI> for SerializableQFI {
    fn from(qfi: &BICYCL::QFI) -> Self {
        let mut vec_a = cxx::CxxVector::<u8>::new();
        qfi.a().to_bytes(vec_a.pin_mut());
        let mut vec_b = cxx::CxxVector::<u8>::new();
        qfi.b().to_bytes(vec_b.pin_mut());
        let mut vec_c = cxx::CxxVector::<u8>::new();
        qfi.c().to_bytes(vec_c.pin_mut());

        SerializableQFI {
            a: vec_a.as_slice().to_vec(),
            b: vec_b.as_slice().to_vec(),
            c: vec_c.as_slice().to_vec(),
        }
    }
}

impl Serialize for QFI {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error> where S: Serializer {
        let se_qfi = SerializableQFI::from(&*self.qfi);

        se_qfi.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for QFI {

    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error> where D: Deserializer<'de> {
        let se_qfi = SerializableQFI::deserialize(deserializer)?;

        let mpz_a = Mpz::bicycl_mpz_with_vec(&se_qfi.a);
        let mpz_b = Mpz::bicycl_mpz_with_vec(&se_qfi.b);
        let mpz_c = Mpz::bicycl_mpz_with_vec(&se_qfi.c);

        Ok(QFI {
            qfi: BICYCL::QFI::new1(&*mpz_a, &*mpz_b, &*mpz_c, false).within_box()
        })
    }
}

pub struct CL_HSMqk {
    c: Pin<Box<BICYCL::CL_HSMqk>>,
}

impl Clone for CL_HSMqk {
    fn clone(&self) -> Self {
        CL_HSMqk {
            c: BICYCL::CL_HSMqk::copy_from(&*self.c).within_box()
        }
    }
}

impl CL_HSMqk {
    pub fn new(q: &Mpz, k: usize, p: &Mpz, fud_factor: &Mpz, compact_variant: bool) -> Self {
        CL_HSMqk {
            c: BICYCL::CL_HSMqk::new(&*q.mpz, k, &*p.mpz, &*fud_factor.mpz, compact_variant).within_box()
        }
    }

    pub fn with_rand_gen(q: &Mpz, k: usize, delta_k_nbits: usize, rand_gen: &mut RandGen, fud_factor: &Mpz, compact_variant: bool) -> Self {
        CL_HSMqk {
            c: BICYCL::CL_HSMqk::new5(&*q.mpz, k, delta_k_nbits, rand_gen.rand_gen.as_mut(), &*fud_factor.mpz, compact_variant).within_box()
        }
    }

    pub fn with_qnbits_rand_gen(q_nbits: usize, k: usize, delta_k_nbits: usize, rand_gen: &mut RandGen, fud_factor: &Mpz, compact_variant: bool) -> Self {
        CL_HSMqk {
            c: BICYCL::CL_HSMqk::new6(q_nbits, k, delta_k_nbits, rand_gen.rand_gen.as_mut(), &*fud_factor.mpz, compact_variant).within_box()
        }
    }

    pub fn secret_key_gen(&self, rand_gen: &mut RandGen) -> SecretKey {
        SecretKey {
            sk: self.c.keygen(rand_gen.rand_gen.as_mut()).within_box()
        }
    }

    pub fn public_key_gen(&self, secret_key: &SecretKey) -> PublicKey {
        PublicKey {
            pk: self.c.keygen1(&*secret_key.sk).within_box(),
        }
    }

    pub fn encrypt(&self, pk: &PublicKey, clear_text: &ClearText, rand_gen: &mut RandGen) -> CipherText {
        CipherText {
            ct: self.c.encrypt(&*pk.pk, &*clear_text.clear_text, rand_gen.rand_gen.as_mut()).within_box(),
        }
    }

    pub fn encrypt_with_r(&self, pk: &PublicKey, clear_text: &ClearText, r: &Mpz) -> CipherText {
        CipherText {
            ct: self.c.encrypt1(&*pk.pk, &*clear_text.clear_text, &*r.mpz).within_box(),
        }
    }

    pub fn decrypt(&self, sk: &SecretKey, ct: &CipherText) -> ClearText {
        ClearText {
            clear_text: self.c.decrypt(&*sk.sk, &*ct.ct).within_box()
        }
    }

    pub fn h(&self) -> QFI {
        QFI {
            qfi: BICYCL::QFI::copy_from(self.c.h()).within_box(),
        }
    }

    pub fn q(&self) -> Mpz {
        Mpz {
            mpz: BICYCL::Mpz::copy_from(self.c.q()).within_box(),
        }
    }

    pub fn power_of_h(&self, e: &Mpz) -> QFI {
        let mut result = BICYCL::QFI::new().within_box();
        self.c.power_of_h(result.as_mut(), &*e.mpz);
        QFI {
            qfi: result
        }
    }

    pub fn power_of_f(&self, m: &Mpz) -> QFI {
        QFI {
            qfi: self.c.power_of_f(&*m.mpz).within_box(),
        }
    }

    pub fn add_ciphertexts(&self, pk: &PublicKey, ca: &CipherText, cb: &CipherText, rand_gen: &mut RandGen) -> CipherText {
        CipherText {
            ct: self.c.add_ciphertexts(&*pk.pk, &*ca.ct, &*cb.ct, rand_gen.rand_gen.as_mut()).within_box(),
        }
    }

    pub fn scal_ciphertexts(&self, pk: &PublicKey, c: &CipherText, s: &Mpz, rand_gen: &mut RandGen) -> CipherText {
        CipherText {
            ct: self.c.scal_ciphertexts(&*pk.pk, &*c.ct, &*s.mpz, rand_gen.rand_gen.as_mut()).within_box(),
        }
    }

    pub fn encrypt_randomness_bound(&self) -> Mpz {
        Mpz {
            mpz: BICYCL::Mpz::copy_from(self.c.encrypt_randomness_bound()).within_box(),
        }
    }
}

pub struct SecretKey {
    sk: Pin<Box<BICYCL::CL_HSMqk_SecretKey>>,
}

impl SecretKey {
    pub fn from_mpz(cl_hsmqk: &CL_HSMqk, mpz: &Mpz) -> Self {
        SecretKey {
            sk: BICYCL::CL_HSMqk_SecretKey::new(&*cl_hsmqk.c, &*mpz.mpz).within_box(),
        }
    }

    pub fn mpz(&self) -> Mpz {
        Mpz {
            mpz: BICYCL::CL_HSMqk_SecretKey::to_mpz(&*self.sk).within_box(),
        }
    }
}

impl Clone for SecretKey {
    fn clone(&self) -> Self {
        SecretKey {
            sk: self.sk.copy().within_box()
        }
    }
}

pub struct PublicKey {
    pk: Pin<Box<BICYCL::CL_HSMqk_PublicKey>>,
}

impl Clone for PublicKey {
    fn clone(&self) -> Self {
        PublicKey {
            pk: self.pk.copy().within_box()
        }
    }
}

impl PublicKey {
    pub fn from_qfi(c: &CL_HSMqk, qfi: &QFI) -> Self {
        PublicKey {
            pk: BICYCL::CL_HSMqk_PublicKey::new1(&*c.c, &*qfi.qfi).within_box(),
        }
    }

    pub fn elt(&self) -> QFI {
        QFI {
            qfi: BICYCL::QFI::copy_from(self.pk.elt()).within_box(),
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.elt().to_bytes()
    }

    pub fn exponentiation(&self, c: &CL_HSMqk, n: &Mpz) -> QFI {
        let mut r = BICYCL::QFI::new().within_box();
        self.pk.exponentiation(&*c.c, r.as_mut(), &*n.mpz);
        QFI {
            qfi: r
        }
    }
}

pub struct ClearText {
    clear_text: Pin<Box<BICYCL::CL_HSMqk_ClearText>>,
}

impl ClearText {
    pub fn with_mpz(c: &CL_HSMqk, v: &Mpz) -> Self {
        ClearText {
            clear_text: BICYCL::CL_HSMqk_ClearText::new(&*c.c, &*v.mpz).within_box(),
        }
    }
    pub fn with_rand_gen(c: &CL_HSMqk, r: &mut RandGen) -> Self {
        ClearText {
            clear_text: BICYCL::CL_HSMqk_ClearText::new1(&*c.c, r.rand_gen.as_mut()).within_box(),
        }
    }
    pub fn with_sk_ct(c: &CL_HSMqk, sk: &SecretKey, ct: &CipherText) -> Self {
        ClearText {
            clear_text: BICYCL::CL_HSMqk_ClearText::new2(&*c.c, &*sk.sk, &*ct.ct).within_box(),
        }
    }
    pub fn with_clears(c: &CL_HSMqk, ma: &ClearText, mb: &ClearText) -> Self {
        ClearText {
            clear_text: BICYCL::CL_HSMqk_ClearText::new3(&*c.c, &*ma.clear_text, &*mb.clear_text).within_box(),
        }
    }
    pub fn with_clear_mpz(c: &CL_HSMqk, m: &ClearText, s: &Mpz) -> Self {
        ClearText {
            clear_text: BICYCL::CL_HSMqk_ClearText::new4(&*c.c, &*m.clear_text, &*s.mpz).within_box(),
        }
    }

    pub fn str_value(&self) -> String {
        return self.clear_text.str_value().to_string();
    }

    pub fn mpz(&self) -> Mpz {
        Mpz {
            mpz: BICYCL::CL_HSMqk_ClearText::to_mpz(&*self.clear_text).within_box(),
        }
    }
}

pub struct CipherText {
    ct: Pin<Box<BICYCL::CL_HSMqk_CipherText>>,
}

impl CipherText {
    pub fn new(c1: &QFI, c2: &QFI) -> Self {
        CipherText {
            ct: BICYCL::CL_HSMqk_CipherText::new3(&*c1.qfi, &*c2.qfi).within_box(),
        }
    }

    pub fn c1(&self) -> QFI {
        QFI {
            qfi: BICYCL::QFI::copy_from(self.ct.c1()).within_box()
        }
    }

    pub fn c2(&self) -> QFI {
        QFI {
            qfi: BICYCL::QFI::copy_from(self.ct.c2()).within_box()
        }
    }
}

// TODO: @wangshuchao `*const u8` cannot be sent between threads safely
unsafe impl Send for CipherText {
}

impl Clone for CipherText {
    fn clone(&self) -> Self {
        CipherText {
            ct: BICYCL::CL_HSMqk_CipherText::new3(self.ct.c1(), self.ct.c2()).within_box(),
        }
    }
}

impl Debug for CipherText {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "CipherText {{ ct: Not implemented }}")
    }
}

impl PartialEq for CipherText {
    fn eq(&self, other: &Self) -> bool {
        self.ct.is_equal(&*other.ct)
    }
}

#[derive(Serialize, Deserialize)]
struct SerializableCipherText {
    c1: SerializableQFI,
    c2: SerializableQFI,
}

impl Serialize for CipherText {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error> where S: Serializer {
        let se_ct = SerializableCipherText {
            c1: SerializableQFI::from(self.ct.c1()),
            c2: SerializableQFI::from(self.ct.c2())
        };

        se_ct.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for CipherText {

    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error> where D: Deserializer<'de> {
        let se_ct = SerializableCipherText::deserialize(deserializer)?;

        let c1 = BICYCL::QFI::new1(&*Mpz::bicycl_mpz_with_vec(&se_ct.c1.a),
                                   &*Mpz::bicycl_mpz_with_vec(&se_ct.c1.b),
                                   &*Mpz::bicycl_mpz_with_vec(&se_ct.c1.c),
                                   false).within_box();
        let c2 = BICYCL::QFI::new1(&*Mpz::bicycl_mpz_with_vec(&se_ct.c2.a),
                                   &*Mpz::bicycl_mpz_with_vec(&se_ct.c2.b),
                                   &*Mpz::bicycl_mpz_with_vec(&se_ct.c2.c),
                                   false).within_box();

        Ok(CipherText {
            ct: BICYCL::CL_HSMqk_CipherText::new3(&*c1, &*c2).within_box(),
        })
    }
}

pub struct CL_HSMqk_ZKAoK {
    c: Pin<Box<BICYCL::CL_HSMqk_ZKAoK>>,
}

impl CL_HSMqk_ZKAoK {
    pub fn with_exp2_mpz(c: &CL_HSMqk, c_exp2: usize, t: &Mpz) -> Self {
        CL_HSMqk_ZKAoK {
            c: BICYCL::CL_HSMqk_ZKAoK::new(&*c.c, c_exp2, &*t.mpz).within_box(),
        }
    }

    pub fn with_exp2_rand_gen(c: &CL_HSMqk, c_exp2: usize, rand_gen: &mut RandGen) -> Self {
        CL_HSMqk_ZKAoK {
            c: BICYCL::CL_HSMqk_ZKAoK::new1(&*c.c, c_exp2, rand_gen.rand_gen.as_mut()).within_box(),
        }
    }

    pub fn with_rand_gen(c: &CL_HSMqk, rand_gen: &mut RandGen) -> Self {
        CL_HSMqk_ZKAoK {
            c: BICYCL::CL_HSMqk_ZKAoK::new2(&*c.c, rand_gen.rand_gen.as_mut()).within_box(),
        }
    }

    pub fn noninteractive_proof(&self, pk: &PublicKey, ct: &CipherText, a: &ClearText, r: &Mpz, rand_gen: &mut RandGen) -> Proof {
        Proof {
            proof: self.c.noninteractive_proof(&*pk.pk, &*ct.ct, &*a.clear_text, &*r.mpz, rand_gen.rand_gen.as_mut()).within_box(),
        }
    }

    pub fn noninteractive_verify(&self, pk: &PublicKey, ct: &CipherText, proof: &Proof) -> bool {
        return self.c.noninteractive_verify(&*pk.pk, &*ct.ct, &*proof.proof);
    }

    pub fn secret_key_gen(&self, rand_gen: &mut RandGen) -> SecretKey {
        SecretKey {
            sk: self.c.keygen(rand_gen.rand_gen.as_mut()).within_box()
        }
    }

    pub fn public_key_gen(&self, secret_key: &SecretKey) -> PublicKey {
        PublicKey {
            pk: self.c.keygen1(&*secret_key.sk).within_box(),
        }
    }

    pub fn encrypt(&self, pk: &PublicKey, clear_text: &ClearText, rand_gen: &mut RandGen) -> CipherText {
        CipherText {
            ct: self.c.encrypt(&*pk.pk, &*clear_text.clear_text, rand_gen.rand_gen.as_mut()).within_box(),
        }
    }

    pub fn decrypt(&self, sk: &SecretKey, ct: &CipherText) -> ClearText {
        ClearText {
            clear_text: self.c.decrypt(&*sk.sk, &*ct.ct).within_box()
        }
    }

    pub fn encrypt_randomness_bound(&self) -> Mpz {
        Mpz {
            mpz: BICYCL::Mpz::copy_from(self.c.encrypt_randomness_bound()).within_box(),
        }
    }
}

pub struct Proof {
    proof: Pin<Box<BICYCL::CL_HSMqk_ZKAoK_Proof>>,
}

impl Proof {
    pub fn new(c: &CL_HSMqk_ZKAoK, pk: &PublicKey, ct: &CipherText, a: &ClearText, r: &Mpz, rand_gen: &mut RandGen) -> Self {
        Proof {
            proof: BICYCL::CL_HSMqk_ZKAoK_Proof::new(&*c.c, &*pk.pk, &*ct.ct, &*a.clear_text, &*r.mpz, rand_gen.rand_gen.as_mut()).within_box(),
        }
    }

    pub fn verify(&self, c: &CL_HSMqk_ZKAoK, pk: &PublicKey, ct: &CipherText) -> bool {
        return self.proof.verify(&*c.c, &*pk.pk, &*ct.ct);
    }
}

