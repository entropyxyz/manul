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
//!
//! ## Running the example
//!
//! Run the example with `RUST_LOG=trace cargo run dining-cryptographers`.

#![allow(dead_code, unused, unused_imports)]
use core::fmt::Debug;
use std::collections::{BTreeMap, BTreeSet};

use manul::{
    dev::{run_sync, BinaryFormat, TestHasher, TestVerifier},
    digest,
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

// The [`Protocol`] is used to group `Round` impls together and in serious protocols it plays a major role in setting up
// error handling and misbehaviour reporting. Another important feature involving [`Protocol`] is when chaining and
// combining sub-protocols together.
// For this simple protocol it's mostly boiler plate, with the exception of the `Result` associated type: it defines
// what the final outcome of a protocol run actually is.
#[derive(Debug)]
pub struct DiningCryptographersProtocol;

// TODO: I guess the protocol (e.g. `DiningCryptographersProtocol`) is a place where one could store arbitrary
// state/context/config data that is local to one participant? We don't do that much in `synedrion` but would it be a
// good idea to do so?
impl<Id> Protocol<Id> for DiningCryptographersProtocol {
    // XOR/¬XOR of the two bits of each of the three diners (one is their own cointoss, the other shared with their
    // neighbour).
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

// HELP: Keeping state in the round like this is a bit weird. Is this the intended way to do it? It would have been
// natural to use the `Diner` type to store state, but it's not clear how to access a `Diner` from inside the various
// `manul` types/methods.
// TODO: clearly explain (where?) that the only data that hits the wire are the message types defined in the protocol:
// types that impl `Round` (or are part of such types, e.g. a `Round15MessagePayload`).
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

    // At the end of round 1 we construct the next one, Round 2, and return a [`FinalizeOutcome::AnotherRound`].
    fn finalize(
        self: Box<Self>,
        rng: &mut dyn CryptoRngCore,
        payloads: BTreeMap<DinerId, Payload>,
        artifacts: BTreeMap<DinerId, Artifact>,
    ) -> Result<FinalizeOutcome<DinerId, Self::Protocol>, LocalError> {
        let payloads = downcast_payloads::<bool>(payloads)?;
        debug!("[Round1, finalize] {:?} sees payloads: {payloads:?}", self.diner_id);

        let neighbour_toss = *payloads
            .first_key_value()
            .ok_or_else(|| return LocalError::new("No payloads found"))?
            .1;

        info!(
            "[Round1, finalize] {:?} is finalizing to Round 2. Own cointoss: {}, neighbour cointoss: {neighbour_toss}",
            self.diner_id, self.own_toss
        );
        Ok(FinalizeOutcome::AnotherRound(BoxedRound::new(Round2 {
            diner_id: self.diner_id,
            own_toss: self.own_toss,
            neighbour_toss,
            paid: self.paid,
        })))
    }
}

impl Round<DinerId> for Round2 {
    type Protocol = DiningCryptographersProtocol;

    // This round is the last in the protocol so we can terminate here.
    fn transition_info(&self) -> TransitionInfo {
        TransitionInfo::new_linear_terminating(2.into())
    }

    // In round 2 each participant broadcasts one bit, so we set up the destinations as "everyone" and expect to receive
    // messages from "everyone". This method is only concerned with who this participant sends to and receives from. The
    // fact that the round is going to make a broadcast (as opposed to direct messages, like in Round 1) is expressed by
    // choosing which message constructing methods to implement.
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

    // Implementing this method means that Round 2 will make a broadcast (without echoes).
    fn make_normal_broadcast(
        &self,
        _rng: &mut dyn CryptoRngCore,
        format: &BoxedFormat,
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

    // Called once for each diner as messages are delivered to it. Here we deserialize the message using the configured
    // [`SessionParameters::WireFormat`] and construct the [`Payload`] that we want to make available to the `finalize`
    // method below.
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

    // The `finalize` method has access to all the [`Payload`]s that were sent to this diner. This protocol does not use
    // [`Artifact`]s, but when used, they are also available here.
    // This is the last round in the protocol, so we return a [`FinalizeOutcome::Result`] with the result of the
    // protocol from this participant's point of view.
    fn finalize(
        self: Box<Self>,
        rng: &mut dyn CryptoRngCore,
        payloads: BTreeMap<DinerId, Payload>,
        _artifacts: BTreeMap<DinerId, Artifact>,
    ) -> Result<FinalizeOutcome<DinerId, Self::Protocol>, LocalError> {
        // XOR/¬XOR the two bits of this diner, depending on whether they paid or not.
        let mut own_reveal = self.own_toss ^ self.neighbour_toss;
        if self.paid {
            own_reveal = !own_reveal;
        }
        // Extract the payloads from the other participants so we can produce a [`Protocol::Result`]. In this case it is
        // a tuple of 3 booleans.
        let payloads_d = downcast_payloads::<bool>(payloads)?;
        let bits = payloads_d.values().cloned().collect::<Vec<_>>();
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

impl signature::Keypair for Diner {
    type VerifyingKey = DinerId;

    fn verifying_key(&self) -> Self::VerifyingKey {
        DinerId(self.id)
    }
}

impl<D: digest::Digest> signature::DigestVerifier<D, DinerSignature> for DinerId {
    fn verify_digest(&self, _digest: D, signature: &DinerSignature) -> Result<(), signature::Error> {
        Ok(())
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

fn downcast_payloads<T: 'static>(map: BTreeMap<DinerId, Payload>) -> Result<BTreeMap<DinerId, T>, LocalError> {
    map.into_iter()
        .map(|(id, payload)| payload.downcast::<T>().map(|p| (id, p)))
        .collect()
}

fn main() {
    tracing_subscriber::fmt::init();
    info!("Dining Cryptographers Protocol Example");

    // Set up participants. This protocol only works for 3 participants!
    let diners = (0..=2).map(|id| Diner::new(id)).collect::<Vec<_>>();

    // Each diner crates an `EntryPoint` for themselves. This constitutes the starting point for the protocol.
    // In a production setting where each diner runs the protocol on their own computer, they'd each create their own
    // `EntryPoint` and run the protocol independently.
    let entry_points = diners
        .into_iter()
        .map(|diner| (diner, DiningEntryPoint::new()))
        .collect::<Vec<_>>();

    // Run the protocol as configured by the `DiningEntryPoint` and `DiningSessionParams`. Calling
    // [`ExecutionResult::results`] collects the [`SessionOutcome`]s for all sessions in a map keyed by the diner ID (aka
    // "verifier").
    let results = run_sync::<_, DiningSessionParams>(&mut OsRng, entry_points)
        .expect("Failed to run the protocol")
        .results()
        .expect("The protocol executed but failed to produce results");

    // `results` contains 3 booleans, which, when XORed together, make `true` if one of the diners paid, or `false` if
    // the NSA paid. All participants should reach the same conclusion.
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
