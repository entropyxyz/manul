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
//! 	Everyone XORs all bits together and interprets the result: 0 => NSA paid; 1 => one of the diners paid.

#![allow(dead_code, unused, unused_imports)]
use core::fmt::Debug;
use std::collections::{BTreeMap, BTreeSet};

use manul::{
    dev::{run_sync, BinaryFormat, TestHasher, TestVerifier},
    digest,
    // TODO: this is lot of imports, perhaps we should have a "prelude" and have users do `use manul::prelude::*`?
    protocol::{
        Artifact, BoxedFormat, BoxedRound, CommunicationInfo, DirectMessage, EchoBroadcast, EchoRoundParticipation,
        EntryPoint, FinalizeOutcome, LocalError, MessageValidationError, NormalBroadcast, PartyId, Payload, Protocol,
        ProtocolError, ProtocolMessage, ProtocolMessagePart, ProtocolValidationError, ReceiveError,
        RequiredMessageParts, RequiredMessages, Round, RoundId, TransitionInfo,
    },
    session::SessionParameters,
    signature::{self, Keypair},
};
use rand_core::{CryptoRngCore, OsRng};
use serde::{Deserialize, Serialize};
use tracing::{debug, info, trace};

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
    // XOR/¬XOR of the two bits of the diners (one is their own cointoss, the other shared with their neighbour).
    type Result = (bool, bool, bool);

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

#[derive(Debug, Clone, Serialize)]
pub struct Round1 {
    diner_id: Verifier,
}

#[derive(Debug, Clone, Serialize)]
pub struct Round2 {
    diner_id: Verifier,
}

impl Round<Verifier> for Round1 {
    type Protocol = DiningCryptographersProtocol;

    fn transition_info(&self) -> TransitionInfo {
        TransitionInfo::new_linear(1.into())
    }

    fn communication_info(&self) -> CommunicationInfo<Verifier> {
        let mut message_destinations = BTreeSet::new();
        let mut expecting_messages_from = BTreeSet::new();
        // diner 0 sends a message to diner 1 (0+1 mod 3 = 1)
        // diner 1 sends a message to diner 2 (1+1 mod 3 = 2)
        // diner 2 sends a message to diner 0 (2+1 mod 3 = 0)
        message_destinations.insert(Verifier((self.diner_id.0 + 1) % 3));
        // diner 0 expects a bit from diner 2 (0+2 mod 3 = 2)
        // diner 1 expects a bit from diner 0 (1+2 mod 3 = 0)
        // diner 2 expects a bit from diner 1 (2+2 mod 3 = 1)
        expecting_messages_from.insert(Verifier((self.diner_id.0 + 2) % 3));
        CommunicationInfo {
            message_destinations,
            expecting_messages_from,
            // Participate in echo broadcasts
            echo_round_participation: EchoRoundParticipation::Default,
        }
    }

    fn make_direct_message(
        &self,
        rng: &mut dyn CryptoRngCore,
        format: &BoxedFormat,
        destination: &Verifier,
    ) -> Result<(DirectMessage, Option<Artifact>), LocalError> {
        // This is called when this diner prepares to send a bit to their neighbour.
        info!(
            "[Round1, make_direct_message] from {:?} to {destination:?}",
            self.diner_id
        );
        let msg = Round1Message {
            cointoss: rng.next_u64() % 2 == 0,
        };
        let dm = DirectMessage::new(format, msg)?;
        // TODO: do I need to propagate the state in an Artifact here perhaps?
        Ok((dm, None))
    }

    fn receive_message(
        &self,
        format: &BoxedFormat,
        from: &Verifier,
        message: ProtocolMessage,
    ) -> Result<Payload, ReceiveError<Verifier, Self::Protocol>> {
        // This is called when this diner receives a bit from their neighbour.
        debug!("[Round1, receive_message] from {from:?} to {:?}", self.diner_id);
        // trace!("[Round1, receive_message] message: {:?}", message);
        let dm = message.direct_message.deserialize::<Round1Message>(format)?;
        trace!("[Round1, receive_message] message (deserialized dm): {:?}", dm);
        Ok(Payload::empty())
    }

    fn finalize(
        self: Box<Self>,
        rng: &mut dyn CryptoRngCore,
        payloads: BTreeMap<Verifier, Payload>,
        artifacts: BTreeMap<Verifier, Artifact>,
    ) -> Result<FinalizeOutcome<Verifier, Self::Protocol>, LocalError> {
        Ok(FinalizeOutcome::AnotherRound(BoxedRound::new_dynamic(Round2 {
            diner_id: self.diner_id,
        })))
    }
}

impl Round<Verifier> for Round2 {
    type Protocol = DiningCryptographersProtocol;

    fn transition_info(&self) -> TransitionInfo {
        TransitionInfo::new_linear_terminating(2.into())
    }

    fn communication_info(&self) -> CommunicationInfo<Verifier> {
        // This is kind of noisy, maybe we can have a utility method for this.
        let everyone_else = [0, 1, 2]
            .iter()
            .filter_map(|id| {
                if id != &self.diner_id.0 {
                    Some(Verifier(*id))
                } else {
                    None
                }
            })
            .collect::<BTreeSet<_>>();

        CommunicationInfo {
            message_destinations: everyone_else.clone(),
            expecting_messages_from: everyone_else,
            echo_round_participation: EchoRoundParticipation::Default,
        }
    }

    fn make_normal_broadcast(
        &self,
        #[allow(unused_variables)] rng: &mut dyn CryptoRngCore,
        #[allow(unused_variables)] format: &BoxedFormat,
    ) -> Result<NormalBroadcast, LocalError> {
        // This is called for this diner to broadcast their secret bit XORed with their shared bit.
        debug!(
            "[Round2, make_normal_broadcast] {:?} broadcasts to everyone else",
            self.diner_id
        );
        // TODO: this is where the diner should broadcast their XORed bit (or it's negation if they paid).
        let msg = Round2Message {
            xor: false, // 0
        };
        let bcast = NormalBroadcast::new(format, msg)?;
        Ok(bcast)
    }

    // This is called from `Session::process_message` as part of the message delivery loop. If we get here, it means that message preprocessing was successful.
    fn receive_message(
        &self,
        format: &BoxedFormat,
        from: &Verifier,
        message: ProtocolMessage,
    ) -> Result<Payload, ReceiveError<Verifier, Self::Protocol>> {
        debug!("[Round2, receive_message] from {from:?} to {:?}", self.diner_id);
        trace!("[Round2, receive_message] message: {:?}", message); //TODO: this is empty, need to impl something to ensure Round 2 broadcast is sent.
        let bcast = message.normal_broadcast.deserialize::<Round2Message>(format)?;
        trace!("[Round2, receive_message] message (deserialized bcast): {:?}", bcast);
        // TODO: What should go into the Payload? Is this "kept" and propagated to the final outcome?
        let payload = Payload::new(bcast.xor);
        Ok(payload)
    }

    fn finalize(
        self: Box<Self>,
        rng: &mut dyn CryptoRngCore,
        payloads: BTreeMap<Verifier, Payload>,
        artifacts: BTreeMap<Verifier, Artifact>,
    ) -> Result<FinalizeOutcome<Verifier, Self::Protocol>, LocalError> {
        debug!(
            "[Round2, finalize] {:?}\n\tpayloads: {payloads:?}\n\tartifacts: {artifacts:?}",
            self.diner_id
        );

        let mut bits = payloads
            .into_values()
            .map(|p| p.downcast())
            .collect::<Result<Vec<bool>, _>>()?;
        // TODO: How do I access the bit of this diner?, i.e. my own state?
        let my_bit = true;
        bits.push(my_bit);
        assert!(bits.len() == 3, "Expected 3 diners and 3 bits, instead got {bits:?}");
        Ok(FinalizeOutcome::Result((bits[0], bits[1], bits[2])))
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Round1Message {
    pub cointoss: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Round2Message {
    // TODO: better name for this, maybe `reveal`?
    pub xor: bool,
}

#[derive(Debug, Clone)]
struct DiningEntryPoint {
    diners: BTreeSet<u8>,
}
impl DiningEntryPoint {
    pub fn new() -> Self {
        let diners = [0, 1, 2u8].into_iter().collect::<BTreeSet<u8>>();
        Self { diners }
    }
}

impl EntryPoint<Verifier> for DiningEntryPoint {
    type Protocol = DiningCryptographersProtocol;

    fn entry_round_id() -> RoundId {
        1.into()
    }

    // Called as part of the session initialization, specifically in [`Session::new`].
    // Each `EntryPoint` creates one `Session`.
    fn make_round(
        self,
        _rng: &mut dyn CryptoRngCore,
        _shared_randomness: &[u8],
        id: &Verifier,
    ) -> Result<BoxedRound<Verifier, Self::Protocol>, LocalError> {
        let round = Round1 { diner_id: id.clone() };
        let round = BoxedRound::new_dynamic(round);
        Ok(round)
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, Ord, PartialOrd, Eq, PartialEq)]
// TODO Need to store the id of the diner and whether they paid or not.
pub struct Diner {
    id: u8,
    paid: bool,
}
impl Diner {
    fn new(id: u8, paid: bool) -> Self {
        Self { id, paid }
    }
}

// TODO: I don't understand why there needs to be a Signer and a Verifier type.
// Suspect it's a CGGMP "contamination" and that they are not needed at all for this protocol.
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
            signed_by: self.id,
            randomness: rng.next_u64(),
        })
    }
}
// TODO: this feels like boilerplate.
impl signature::Keypair for Diner {
    type VerifyingKey = Verifier;

    fn verifying_key(&self) -> Self::VerifyingKey {
        Verifier(self.id)
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
    let diners = (0..=2).map(|id| Diner::new(id, false)).collect::<Vec<_>>();

    let all_diners = diners
        .iter()
        .map(|diner| diner.verifying_key())
        .collect::<BTreeSet<_>>();

    let entry_points = diners
        .into_iter()
        .map(|diner| (diner, DiningEntryPoint::new()))
        .collect::<Vec<_>>();

    assert!(entry_points.len() == 3);
    let results = run_sync::<_, DiningSessionParams>(&mut OsRng, entry_points)
        .unwrap()
        .results()
        .unwrap();

    // `results` should contain 3 booleans, which, when XORed together, should be 0 if the NSA paid, or 1 if one of the diners paid.
    for (_id, result) in results {
        info!("Result: {:?}", result);
    }
}
