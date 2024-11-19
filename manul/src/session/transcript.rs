use alloc::{
    collections::{btree_map::Entry, BTreeMap, BTreeSet},
    format,
    string::String,
    vec::Vec,
};
use core::fmt::Debug;

use super::{evidence::Evidence, message::SignedMessagePart, session::SessionParameters, LocalError, RemoteError};
use crate::protocol::{DirectMessage, EchoBroadcast, NormalBroadcast, Protocol, RoundId};

#[derive(Debug)]
pub(crate) struct Transcript<P: Protocol, SP: SessionParameters> {
    echo_broadcasts: BTreeMap<RoundId, BTreeMap<SP::Verifier, SignedMessagePart<EchoBroadcast>>>,
    normal_broadcasts: BTreeMap<RoundId, BTreeMap<SP::Verifier, SignedMessagePart<NormalBroadcast>>>,
    direct_messages: BTreeMap<RoundId, BTreeMap<SP::Verifier, SignedMessagePart<DirectMessage>>>,
    provable_errors: BTreeMap<SP::Verifier, Evidence<P, SP>>,
    unprovable_errors: BTreeMap<SP::Verifier, RemoteError>,
    missing_messages: BTreeMap<RoundId, BTreeSet<SP::Verifier>>,
}

impl<P, SP> Transcript<P, SP>
where
    P: Protocol,
    SP: SessionParameters,
{
    pub fn new() -> Self {
        Self {
            echo_broadcasts: BTreeMap::new(),
            normal_broadcasts: BTreeMap::new(),
            direct_messages: BTreeMap::new(),
            provable_errors: BTreeMap::new(),
            unprovable_errors: BTreeMap::new(),
            missing_messages: BTreeMap::new(),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn update(
        self,
        round_id: &RoundId,
        echo_broadcasts: BTreeMap<SP::Verifier, SignedMessagePart<EchoBroadcast>>,
        normal_broadcasts: BTreeMap<SP::Verifier, SignedMessagePart<NormalBroadcast>>,
        direct_messages: BTreeMap<SP::Verifier, SignedMessagePart<DirectMessage>>,
        provable_errors: BTreeMap<SP::Verifier, Evidence<P, SP>>,
        unprovable_errors: BTreeMap<SP::Verifier, RemoteError>,
        missing_messages: BTreeSet<SP::Verifier>,
    ) -> Result<Self, LocalError> {
        let mut all_echo_broadcasts = self.echo_broadcasts;
        match all_echo_broadcasts.entry(round_id.clone()) {
            Entry::Vacant(entry) => entry.insert(echo_broadcasts),
            Entry::Occupied(_) => {
                return Err(LocalError::new(format!(
                    "An echo-broadcasts entry for {round_id:?} already exists"
                )))
            }
        };

        let mut all_normal_broadcasts = self.normal_broadcasts;
        match all_normal_broadcasts.entry(round_id.clone()) {
            Entry::Vacant(entry) => entry.insert(normal_broadcasts),
            Entry::Occupied(_) => {
                return Err(LocalError::new(format!(
                    "A normal-broadcasts entry for {round_id:?} already exists"
                )))
            }
        };

        let mut all_direct_messages = self.direct_messages;
        match all_direct_messages.entry(round_id.clone()) {
            Entry::Vacant(entry) => entry.insert(direct_messages),
            Entry::Occupied(_) => {
                return Err(LocalError::new(format!(
                    "A direct messages entry for {round_id:?} already exists"
                )))
            }
        };

        let mut all_provable_errors = self.provable_errors;
        for (verifier, error) in provable_errors {
            if all_provable_errors.insert(verifier.clone(), error).is_some() {
                return Err(LocalError::new(format!(
                    "A provable errors entry for {verifier:?} already exists"
                )));
            }
        }

        let mut all_unprovable_errors = self.unprovable_errors;
        for (verifier, error) in unprovable_errors {
            if all_unprovable_errors.insert(verifier.clone(), error).is_some() {
                return Err(LocalError::new(format!(
                    "An unprovable errors entry for {verifier:?} already exists"
                )));
            }
        }

        let mut all_missing_messages = self.missing_messages;
        match all_missing_messages.entry(round_id.clone()) {
            Entry::Vacant(entry) => entry.insert(missing_messages),
            Entry::Occupied(_) => {
                return Err(LocalError::new(format!(
                    "A missing messages entry for {round_id:?} already exists"
                )))
            }
        };

        Ok(Self {
            echo_broadcasts: all_echo_broadcasts,
            normal_broadcasts: all_normal_broadcasts,
            direct_messages: all_direct_messages,
            provable_errors: all_provable_errors,
            unprovable_errors: all_unprovable_errors,
            missing_messages: all_missing_messages,
        })
    }

    pub fn get_echo_broadcast(
        &self,
        round_id: RoundId,
        from: &SP::Verifier,
    ) -> Result<SignedMessagePart<EchoBroadcast>, LocalError> {
        self.echo_broadcasts
            .get(&round_id)
            .ok_or_else(|| LocalError::new(format!("No echo broadcasts registered for {round_id:?}")))?
            .get(from)
            .cloned()
            .ok_or_else(|| LocalError::new(format!("No echo broadcasts registered for {from:?} in {round_id:?}")))
    }

    pub fn get_normal_broadcast(
        &self,
        round_id: RoundId,
        from: &SP::Verifier,
    ) -> Result<SignedMessagePart<NormalBroadcast>, LocalError> {
        self.normal_broadcasts
            .get(&round_id)
            .ok_or_else(|| LocalError::new(format!("No normal broadcasts registered for {round_id:?}")))?
            .get(from)
            .cloned()
            .ok_or_else(|| LocalError::new(format!("No normal broadcasts registered for {from:?} in {round_id:?}")))
    }

    pub fn get_direct_message(
        &self,
        round_id: RoundId,
        from: &SP::Verifier,
    ) -> Result<SignedMessagePart<DirectMessage>, LocalError> {
        self.direct_messages
            .get(&round_id)
            .ok_or_else(|| LocalError::new(format!("No direct messages registered for {round_id:?}")))?
            .get(from)
            .cloned()
            .ok_or_else(|| LocalError::new(format!("No direct messages registered for {from:?} in {round_id:?}")))
    }

    pub fn is_banned(&self, from: &SP::Verifier) -> bool {
        self.provable_errors.contains_key(from) || self.unprovable_errors.contains_key(from)
    }

    pub fn echo_broadcasts(
        &self,
        round_id: RoundId,
    ) -> Result<BTreeMap<SP::Verifier, SignedMessagePart<EchoBroadcast>>, LocalError> {
        self.echo_broadcasts
            .get(&round_id)
            .cloned()
            .ok_or_else(|| LocalError::new(format!("Echo-broadcasts for {round_id:?} are not in the transcript")))
    }
}

/// Possible outcomes of running a session.
#[derive(Debug)]
pub enum SessionOutcome<P: Protocol> {
    /// The protocol successfully produced a result.
    Result(P::Result),
    /// The execution stalled because of an unattributable error,
    /// but the protocol created a proof that this node performed its duties correctly.
    ///
    /// This proof is supposed to be passed to a third party for adjudication,
    /// along with the proofs from the other nodes.
    StalledWithProof(P::CorrectnessProof),
    /// The execution stalled because not enough messages were received to finalize the round.
    NotEnoughMessages,
    /// The execution was terminated by the user.
    Terminated,
}

impl<P> SessionOutcome<P>
where
    P: Protocol,
{
    /// Returns a brief description of the outcome.
    pub fn brief(&self) -> String {
        match self {
            Self::Result(result) => format!("Success ({result:?})"),
            Self::NotEnoughMessages => "Not enough messages to finalize, terminated".into(),
            Self::Terminated => "Terminated by the user".into(),
            Self::StalledWithProof(_) => "Unattributable failure during finalization".into(),
        }
    }
}

/// The report of a session execution.
#[derive(Debug)]
pub struct SessionReport<P: Protocol, SP: SessionParameters> {
    /// The session outcome.
    pub outcome: SessionOutcome<P>,
    /// The provable errors collected during the execution, as the evidences that can be published to prove them.
    pub provable_errors: BTreeMap<SP::Verifier, Evidence<P, SP>>,
    /// The unprovable errors collected during the execution.
    pub unprovable_errors: BTreeMap<SP::Verifier, RemoteError>,
    /// The nodes that did not send their messages in time for the corresponding round.
    pub missing_messages: BTreeMap<RoundId, BTreeSet<SP::Verifier>>,
}

impl<P, SP> SessionReport<P, SP>
where
    P: Protocol,
    SP: SessionParameters,
{
    pub(crate) fn new(outcome: SessionOutcome<P>, transcript: Transcript<P, SP>) -> Self {
        Self {
            outcome,
            provable_errors: transcript.provable_errors,
            unprovable_errors: transcript.unprovable_errors,
            missing_messages: transcript.missing_messages,
        }
    }

    /// Returns the protocol result if the session outcome contains it, otherwise `None`.
    pub fn result(self) -> Option<P::Result> {
        match self.outcome {
            SessionOutcome::Result(result) => Some(result),
            _ => None,
        }
    }

    /// Returns a brief description of report.
    pub fn brief(&self) -> String {
        let provable_errors = self
            .provable_errors
            .iter()
            .map(|(id, evidence)| format!("  {:?}: {}", id, evidence.description()))
            .collect::<Vec<_>>();
        let unprovable_errors = self
            .unprovable_errors
            .iter()
            .map(|(id, error)| format!("  {:?}: {}", id, error))
            .collect::<Vec<_>>();
        let missing_messages = self
            .missing_messages
            .iter()
            .map(|(id, parties)| format!("  {:?}: {:?}", id, parties))
            .collect::<Vec<_>>();

        format!(
            "Result: {}\nProvable errors:\n{}\nUnprovable errors:\n{}\nMissing_messages:\n{}",
            self.outcome.brief(),
            provable_errors.join("\n"),
            unprovable_errors.join("\n"),
            missing_messages.join("\n")
        )
    }
}
