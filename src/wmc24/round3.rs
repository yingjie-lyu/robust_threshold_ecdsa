use super::*;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Round3 {
    pub pd_gammak: BTreeMap<u8, BTreeMap<u8, CipherText>>,
    pub pd_ggamma: BTreeMap<u8, BTreeMap<u8, ElGamalCiphertext>>,
}


impl Round3 {
    pub fn new(
        pp: &ThresholdCLPubParams,
        threshold_pk: &ThresholdPubKey,
        x_shares: &BTreeMap<Id, Zq>,
        round1: &Round1,
        rng: &mut RandGen,
    ) -> Self {
        Self { pd_gammak: todo!(), pd_ggamma: todo!() }
    }
}