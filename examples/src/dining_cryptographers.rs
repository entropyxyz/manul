//! Dining Cryptographers Protocol, see https://en.wikipedia.org/wiki/Dining_cryptographers_problem
//!
//! In cryptography, the dining cryptographers problem studies how to perform a secure multi-party computation of the
//! boolean-XOR function. David Chaum first proposed this problem in the early 1980s and used it as an illustrative
//! example to show that it was possible to send anonymous messages with unconditional sender and recipient
//! untraceability. Anonymous communication networks based on this problem are often referred to as DC-nets (where DC
//! stands for "dining cryptographers").
//!
//! ## Description
//!
//! Three cryptographers gather around a table for dinner. The waiter informs them that the meal has been paid for by
//! someone, who could be one of the cryptographers or the National Security Agency (NSA). The cryptographers respect
//! each other's right to make an anonymous payment, but want to find out whether the NSA paid. So they decide to
//! execute a two-stage protocol.
//!
//! In the first stage, every two cryptographers establish a shared one-bit secret, say by tossing a coin behind a menu
//! so that only two cryptographers see the outcome in turn for each two cryptographers. Suppose, for example, that
//! after the coin tossing, cryptographer A and B share a secret bit 1, A and C share 0, and B and C share 1.
//!
//! In the second stage, each cryptographer publicly announces a bit, which is:
//!
//! - if they didn't pay for the meal, the exclusive OR (XOR) of the two shared bits they hold with their two
//!   neighbours,
//! - if they did pay for the meal, the opposite of that XOR.
//!
//! Supposing none of the cryptographers paid, then A announces 1⨁0 = 1, B announces 1⨁1 = 0, and C announces 0⨁1 = 1.
//! On the other hand, if A paid, she announces ¬(1⨁0) = 0.
//!
//! The three public announcements combined reveal the answer to their question. One simply computes the XOR of the
//! three bits announced. If the result is 0, it implies that none of the cryptographers paid (so the NSA must have paid
//! the bill). Otherwise, one of the cryptographers paid, but their identity remains unknown to the other
//! cryptographers.
//!
//! ## Implementation
//!
//! Prep:
//! 	State is "I paid yes/no" and "ordered list of diners".
//! Round 1:
//! 	Each diner DMs their neighbour their cointoss.
//!     Outcome: the state of each diner is their own cointoss and the bit they received as a DM, i.e. two bits, one
//!     private and the other shared with their neighbour diner.
//! Round 2:
//! 	Each diner broadcasts one bit: the XOR (if they didn't pay) or ¬XOR (if they paid) of their two bits.
//! 	Outcome: each diner has a set of bits, one for each diner.
//! Post:
//! 	Everyone XORs all bits together and interpret the result: 0 => NSA paid; 1 => one of the diners paid.

#![allow(dead_code, unused, unused_imports)]
use core::fmt::Debug;
use std::collections::{BTreeMap, BTreeSet};

use manul::{
    dev::{run_sync, BinaryFormat, TestHasher, TestVerifier},
    digest,
    // TODO: this is lot of imports, perhaps we should have a "prelude" and have users do `use manul::prelude::*`?
    protocol::{
        Artifact, BoxedFormat, BoxedRound, CommunicationInfo, DirectMessage, EchoBroadcast, EntryPoint,
        FinalizeOutcome, LocalError, MessageValidationError, NormalBroadcast, PartyId, Payload, Protocol,
        ProtocolError, ProtocolMessage, ProtocolMessagePart, ProtocolValidationError, ReceiveError,
        RequiredMessageParts, RequiredMessages, Round, RoundId, TransitionInfo,
    },
    session::SessionParameters,
    signature::{self, Keypair},
};
use rand_core::{CryptoRngCore, OsRng};
use serde::{Deserialize, Serialize};
use tracing::{debug, info};

#[derive(Debug)]
pub struct DiningCryptographersProtocol;
#[derive(displaydoc::Display, Debug, Clone, Serialize, Deserialize)]
/// bla
pub enum DiningError {
    /// bla
    R1Err,
    /// bla
    R2Err,
}
// TODO: for protocols that do not have "provable errors" we should have a shortcut and/or blanket impls.
// TODO: Why does ProtocolError require Display?
impl<Id> ProtocolError<Id> for DiningError {
    type AssociatedData = ();
    fn required_messages(&self) -> RequiredMessages {
        match self {
            DiningError::R1Err => RequiredMessages::new(RequiredMessageParts::direct_message(), None, None),
            DiningError::R2Err => RequiredMessages::new(RequiredMessageParts::direct_message(), None, None),
        }
    }

    fn verify_messages_constitute_error(
        &self,
        format: &BoxedFormat,
        guilty_party: &Id,
        shared_randomness: &[u8],
        associated_data: &Self::AssociatedData,
        message: ProtocolMessage,
        previous_messages: BTreeMap<RoundId, ProtocolMessage>,
        combined_echos: BTreeMap<RoundId, BTreeMap<Id, EchoBroadcast>>,
    ) -> Result<(), ProtocolValidationError> {
        match self {
            DiningError::R1Err => Ok(()),
            DiningError::R2Err => Ok(()),
        }
    }
}

impl<Id> Protocol<Id> for DiningCryptographersProtocol {
    // TODO: Is this the right place for the final outcome of the protocol?
    // XOR/¬XOR of the two bits of the diners (one their own cointoss, the other shared with their neighbour).
    type Result = bool;

    type ProtocolError = DiningError;

    // TODO: Having blanket impls for these methods would cut down on the boilerplate a bit.
    fn verify_direct_message_is_invalid(
        format: &BoxedFormat,
        round_id: &RoundId,
        message: &DirectMessage,
    ) -> Result<(), MessageValidationError> {
        Ok(())
    }

    fn verify_echo_broadcast_is_invalid(
        format: &BoxedFormat,
        round_id: &RoundId,
        message: &EchoBroadcast,
    ) -> Result<(), MessageValidationError> {
        Ok(())
    }

    fn verify_normal_broadcast_is_invalid(
        format: &BoxedFormat,
        round_id: &RoundId,
        message: &NormalBroadcast,
    ) -> Result<(), MessageValidationError> {
        Ok(())
    }
}

pub struct Round1<Id> {
    id: Id,
}
// TODO: impl `Round` for `Round2`.

#[derive(Debug, Serialize, Deserialize)]
pub struct Round1Message {
    pub cointoss: bool,
}
pub struct Round2<Id> {
    id: Id,
}
// TODO: impl `Round` for `Round2`.

#[derive(Debug, Serialize, Deserialize)]
pub struct Round2Message {
    // TODO: better name for this, maybe `reveal`?
    pub xor: bool,
}

#[derive(Debug, Clone)]
struct DiningEntryPoint<Id> {
    diners: BTreeSet<Id>,
}
impl<Id: PartyId> DiningEntryPoint<Id> {
    pub fn new(diners: BTreeSet<Id>) -> Self {
        Self { diners }
    }
}

impl<Id: PartyId> EntryPoint<Id> for DiningEntryPoint<Id> {
    type Protocol = DiningCryptographersProtocol;

    fn entry_round_id() -> RoundId {
        1.into()
    }

    fn make_round(
        self,
        _rng: &mut dyn CryptoRngCore,
        _shared_randomness: &[u8],
        id: &Id,
    ) -> Result<BoxedRound<Id, Self::Protocol>, LocalError> {
        todo!()
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, Ord, PartialOrd, Eq, PartialEq)]
// TODO Need to store the id of the diner and whether they paid or not.
pub struct Diner(u8);
impl Diner {
    fn new(id: u8) -> Self {
        Self(id)
    }
}

// TODO: I don't understand why there needs to be a Signer and a Verifier type. Suspect it's a CGGMP "contamination" and that they are not needed at all for this protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Verifier(u8);

// TODO: same here, why do we need a signature type?
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct DinerSignature {
    signed_by: u8,
    randomness: u64,
}

// TODO: this feels like boilerplate.
impl<D: digest::Digest> signature::RandomizedDigestSigner<D, DinerSignature> for Diner {
    fn try_sign_digest_with_rng(
        &self,
        rng: &mut impl CryptoRngCore,
        _digest: D,
    ) -> Result<DinerSignature, signature::Error> {
        Ok(DinerSignature {
            signed_by: self.0,
            randomness: rng.next_u64(),
        })
    }
}
// TODO: this feels like boilerplate.
impl signature::Keypair for Diner {
    type VerifyingKey = Verifier;

    fn verifying_key(&self) -> Self::VerifyingKey {
        Verifier(self.0)
    }
}
// TODO: this feels like boilerplate.
impl<D: digest::Digest> signature::DigestVerifier<D, DinerSignature> for Verifier {
    fn verify_digest(&self, _digest: D, signature: &DinerSignature) -> Result<(), signature::Error> {
        if self.0 == signature.signed_by {
            Ok(())
        } else {
            Err(signature::Error::new())
        }
    }
}
#[derive(Debug, Clone, Copy)]
pub struct DiningSessionParams;

impl SessionParameters for DiningSessionParams {
    type Signer = Diner;
    type Verifier = Verifier;
    type Signature = DinerSignature;
    type Digest = TestHasher;
    type WireFormat = BinaryFormat;
}

fn main() {
    tracing_subscriber::fmt::init();
    info!("Dining Cryptographers Protocol Example");
    let diners = (0..3).map(Diner::new).collect::<Vec<_>>();
    let all_diners = diners
        .iter()
        .map(|diner| diner.verifying_key())
        .collect::<BTreeSet<_>>();

    let entry_points = diners
        .into_iter()
        .map(|diner| (diner, DiningEntryPoint::new(all_diners.clone())))
        .collect::<Vec<_>>();

    let results = run_sync::<_, DiningSessionParams>(&mut OsRng, entry_points)
        .unwrap()
        .results()
        .unwrap();

    // `results` should contain 3 booleans, which, when XORed together, should be 0 if the NSA paid, or 1 if one of the diners paid.
    for (_id, result) in results {
        info!("Result: {:?}", result);
    }
}
