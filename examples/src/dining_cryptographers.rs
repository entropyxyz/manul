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
//!     they sent to one neighbour and the other received by their other neighbour diner.
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
        EntryPoint, FinalizeOutcome, LocalError, MessageValidationError, NoProtocolErrors, NormalBroadcast, PartyId,
        Payload, Protocol, ProtocolError, ProtocolMessage, ProtocolMessagePart, ProtocolValidationError, ReceiveError,
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

impl<Id> Protocol<Id> for DiningCryptographersProtocol {
    // XOR/¬XOR of the two bits of the diners (one is their own cointoss, the other shared with their neighbour).
    type Result = (bool, bool, bool);

    type ProtocolError = NoProtocolErrors;

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
    diner_id: DinerId,
    own_toss: bool,
    paid: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct Round2 {
    diner_id: DinerId,
    own_toss: bool,
    neighbour_toss: bool,
    paid: bool,
}

impl Round<DinerId> for Round1 {
    type Protocol = DiningCryptographersProtocol;

    // Used to define the possible paths to and from this round. This protocol is very simple, it's simply Round 1 ->
    // Round 2, so we can use the "linear" utility method to set this up.
    fn transition_info(&self) -> TransitionInfo {
        TransitionInfo::new_linear(1.into())
    }

    // Where are we sending messages, and what messages are we expecting to receive?
    // For this protocol we will send one message to the neighbour diner, and expect to receive one message from the
    // other neighbour diner.
    fn communication_info(&self) -> CommunicationInfo<DinerId> {
        let mut message_destinations = BTreeSet::new();
        let mut expecting_messages_from = BTreeSet::new();
        // diner 0 sends a message to diner 1 (0+1 mod 3 = 1)
        // diner 1 sends a message to diner 2 (1+1 mod 3 = 2)
        // diner 2 sends a message to diner 0 (2+1 mod 3 = 0)
        message_destinations.insert(DinerId((self.diner_id.0 + 1) % 3));
        // diner 0 expects a bit from diner 2 (0+2 mod 3 = 2)
        // diner 1 expects a bit from diner 0 (1+2 mod 3 = 0)
        // diner 2 expects a bit from diner 1 (2+2 mod 3 = 1)
        expecting_messages_from.insert(DinerId((self.diner_id.0 + 2) % 3));
        CommunicationInfo {
            message_destinations,
            expecting_messages_from,
            // Participate in echo broadcasts
            echo_round_participation: EchoRoundParticipation::Default,
        }
    }

    // This is called when this diner prepares to share a random bit with their neighbour.
    fn make_direct_message(
        &self,
        rng: &mut dyn CryptoRngCore,
        format: &BoxedFormat,
        destination: &DinerId,
    ) -> Result<(DirectMessage, Option<Artifact>), LocalError> {
        info!(
            "[Round1, make_direct_message] from {:?} to {destination:?}",
            self.diner_id
        );
        let msg = Round1Message { toss: self.own_toss };
        let dm = DirectMessage::new(format, msg)?;

        Ok((dm, None))
    }

    // This is called when this diner receives a bit from their neighbour.
    fn receive_message(
        &self,
        format: &BoxedFormat,
        from: &DinerId,
        message: ProtocolMessage,
    ) -> Result<Payload, ReceiveError<DinerId, Self::Protocol>> {
        let dm = message.direct_message.deserialize::<Round1Message>(format)?;
        debug!(
            "[Round1, receive_message] {:?} was dm'd by {from:?}: {dm:?}",
            self.diner_id
        );
        let payload = Payload::new(dm.toss);
        Ok(payload)
    }

    fn finalize(
        self: Box<Self>,
        rng: &mut dyn CryptoRngCore,
        payloads: BTreeMap<DinerId, Payload>,
        artifacts: BTreeMap<DinerId, Artifact>,
    ) -> Result<FinalizeOutcome<DinerId, Self::Protocol>, LocalError> {
        trace!(
            "[Round1, finalize] {:?}, payloads len: {}, artifacts len: {}",
            self.diner_id,
            payloads.len(),
            artifacts.len()
        );
        let artifacts_d = downcast_artifacts::<bool>(artifacts)?;
        let payloads_d = downcast_payloads::<bool>(payloads)?;
        debug!(
            "[Round1, finalize] {:?} has access to: \n\tpayloads: {payloads_d:?}\n\tartifacts: {artifacts_d:?}",
            self.diner_id
        );
        let neighbour_toss = *payloads_d
            .first_key_value()
            .ok_or_else(|| return LocalError::new("No payloads found"))?
            .1;

        info!(
            "[Round1, finalize] {:?} is finalizing to Round 2. Own cointoss: {}, neighbour cointoss: {neighbour_toss}",
            self.diner_id, self.own_toss
        );
        Ok(FinalizeOutcome::AnotherRound(BoxedRound::new_dynamic(Round2 {
            diner_id: self.diner_id,
            own_toss: self.own_toss,
            neighbour_toss,
            paid: self.paid,
        })))
    }
}

impl Round<DinerId> for Round2 {
    type Protocol = DiningCryptographersProtocol;

    fn transition_info(&self) -> TransitionInfo {
        TransitionInfo::new_linear_terminating(2.into())
    }

    fn communication_info(&self) -> CommunicationInfo<DinerId> {
        let everyone_else = [0, 1, 2]
            .iter()
            .filter_map(|id| {
                if id != &self.diner_id.0 {
                    Some(DinerId(*id))
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
        debug!(
            "[Round2, make_normal_broadcast] {:?} broadcasts to everyone else",
            self.diner_id
        );
        // This diner broadcasts their XORed bit (or it's negation if they paid).
        let reveal = if self.paid {
            !self.own_toss ^ self.neighbour_toss
        } else {
            self.own_toss ^ self.neighbour_toss
        };
        let msg = Round2Message { reveal };
        let bcast = NormalBroadcast::new(format, msg)?;
        Ok(bcast)
    }

    // This is called from `Session::process_message` as part of the message delivery loop. If we get here, it means
    // that message pre-processing was successful.
    fn receive_message(
        &self,
        format: &BoxedFormat,
        from: &DinerId,
        message: ProtocolMessage,
    ) -> Result<Payload, ReceiveError<DinerId, Self::Protocol>> {
        debug!("[Round2, receive_message] from {from:?} to {:?}", self.diner_id);
        let bcast = message.normal_broadcast.deserialize::<Round2Message>(format)?;
        trace!("[Round2, receive_message] message (deserialized bcast): {:?}", bcast);
        // The payload is kept and delivered in the `finalize` method.
        let payload = Payload::new(bcast.reveal);
        Ok(payload)
    }

    fn finalize(
        self: Box<Self>,
        rng: &mut dyn CryptoRngCore,
        payloads: BTreeMap<DinerId, Payload>,
        artifacts: BTreeMap<DinerId, Artifact>,
    ) -> Result<FinalizeOutcome<DinerId, Self::Protocol>, LocalError> {
        let artifacts_d = downcast_artifacts::<bool>(artifacts)?;
        let payloads_d = downcast_payloads::<bool>(payloads)?;
        debug!(
            "[Round2, finalize] {:?}\n\tpayloads: {payloads_d:?}\n\tartifacts: {artifacts_d:?}",
            self.diner_id
        );
        let bits = payloads_d.values().cloned().collect::<Vec<_>>();
        let mut own_reveal = self.own_toss ^ self.neighbour_toss;
        if self.paid {
            own_reveal = !own_reveal;
        }
        assert!(
            bits.len() + 1 == 3,
            "Expected 3 diners and 3 bits, instead got {bits:?}"
        );
        Ok(FinalizeOutcome::Result((bits[0], bits[1], own_reveal)))
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Round1Message {
    // The cointoss of this diner, which is shared with their neighbour.
    toss: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Round2Message {
    // The result of XORing the two bits: own cointoss and that of their neighbour.
    reveal: bool,
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

impl EntryPoint<DinerId> for DiningEntryPoint {
    type Protocol = DiningCryptographersProtocol;

    fn entry_round_id() -> RoundId {
        // We start at Round 1
        1.into()
    }

    // Called as part of the session initialization, specifically in [`Session::new`].
    // Each `EntryPoint` creates one `Session`.
    // TODO: Can this ever NOT create the first round? Would a rename to "make_first_round" be appropriate?
    fn make_round(
        self,
        rng: &mut dyn CryptoRngCore,
        _shared_randomness: &[u8],
        id: &DinerId,
    ) -> Result<BoxedRound<DinerId, Self::Protocol>, LocalError> {
        let paid = id.0 == 0 && rng.next_u32() % 2 == 0;
        let round = Round1 {
            diner_id: id.clone(),
            own_toss: rng.next_u32() % 2 == 0,
            paid,
        };
        trace!(
            "[DiningEntryPoint, make_round] diner {id:?} tossed: {:?} (paid? {paid})",
            round.own_toss
        );
        let round = BoxedRound::new_dynamic(round);
        Ok(round)
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, Ord, PartialOrd, Eq, PartialEq)]
// TODO: this type is not used at all. It'd be the natural place for things like "paid for dinner" and other similar
// state, but I don't see how to access a `Diner` from inside the protocol, without doing nasty stuff like having a
// global "state" thingy (standing in for a database).
pub struct Diner {
    id: u8,
}
impl Diner {
    fn new(id: u8) -> Self {
        Self { id }
    }
}

// TODO: I don't understand why there needs to be a Signer and a Verifier type.
// Suspect it's a CGGMP "contamination" and that they are not needed at all for this protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct DinerId(u8);

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
    type VerifyingKey = DinerId;

    fn verifying_key(&self) -> Self::VerifyingKey {
        DinerId(self.id)
    }
}
// TODO: this feels like boilerplate.
impl<D: digest::Digest> signature::DigestVerifier<D, DinerSignature> for DinerId {
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
    type Verifier = DinerId;
    type Signature = DinerSignature;
    type Digest = TestHasher;
    type WireFormat = BinaryFormat;
}

// TODO: would be nice to have `downcast_all` from `synedrion`.
fn downcast_payloads<T: 'static>(map: BTreeMap<DinerId, Payload>) -> Result<BTreeMap<DinerId, T>, LocalError> {
    map.into_iter()
        .map(|(id, payload)| payload.downcast::<T>().map(|p| (id, p)))
        .collect()
}
fn downcast_artifacts<T: 'static>(map: BTreeMap<DinerId, Artifact>) -> Result<BTreeMap<DinerId, T>, LocalError> {
    map.into_iter()
        .map(|(id, artifact)| artifact.downcast::<T>().map(|p| (id, p)))
        .collect()
}

fn main() {
    tracing_subscriber::fmt::init();
    info!("Dining Cryptographers Protocol Example");
    let diners = (0..=2).map(|id| Diner::new(id)).collect::<Vec<_>>();

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

    // `results` contains 3 booleans, which, when XORed together, make `true` if one of the diners paid, or `false` if the NSA paid.
    for (id, result) in results {
        let who_paid = if result.0 ^ result.1 ^ result.2 {
            "one of the diners"
        } else {
            "the NSA"
        };
        info!(
            "Diner {id:?} got result: {:?}; they conclude that {who_paid} paid for dinner!",
            result
        );
    }
}
