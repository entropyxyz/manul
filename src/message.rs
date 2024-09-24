use crate::round::{DirectMessage, EchoBroadcast, RoundId};

#[derive(Debug, Clone)]
pub struct SignedDirectMessage<I> {
    pub signature: I,
    pub message: DirectMessage,
}

impl<I: PartialEq> SignedDirectMessage<I> {
    pub fn verify(self, id: &I) -> Option<DirectMessage> {
        if &self.signature == id {
            Some(self.message)
        } else {
            None
        }
    }
}

#[derive(Debug, Clone)]
pub struct SignedEchoBroadcast<I> {
    pub signature: I,
    pub message: EchoBroadcast,
}

impl<I: PartialEq> SignedEchoBroadcast<I> {
    pub fn verify(self, id: &I) -> Option<EchoBroadcast> {
        if &self.signature == id {
            Some(self.message)
        } else {
            None
        }
    }
}

#[derive(Clone, Debug)]
pub struct MessageBundle<I> {
    pub round_id: RoundId,
    pub direct_message: SignedDirectMessage<I>,
    pub echo_broadcast: Option<SignedEchoBroadcast<I>>,
}
