use alloc::{
    collections::{BTreeMap, BTreeSet},
    format,
    string::String,
};
use core::{fmt::Debug, marker::PhantomData};

use serde::{Deserialize, Serialize};

use super::{
    errors::LocalError,
    message::{DirectMessage, EchoBroadcast, NormalBroadcast, ProtocolMessagePart},
    round::{PartyId, Protocol, Round},
    round_id::{GroupNum, RoundId, RoundNum},
    wire_format::BoxedFormat,
};

/// Describes provable errors triggered by an incoming message during protocol execution.
///
/// Provable here means that we can create an evidence object entirely of messages signed by some party,
/// which proves the party's malicious actions.
pub trait ProtocolError<Id>: 'static + Debug + Clone + Send + Sync + Serialize + for<'de> Deserialize<'de> {
    /// The round where the described errors occur.
    type Round: Round<Id, ProtocolError = Self>;

    /// A short description of the error, for logging purposes.
    fn description(&self) -> String;

    /// Specifies the messages of the guilty party that need to be stored as the evidence
    /// to prove its malicious behavior.
    fn required_messages(&self, round_id: &RoundId) -> RequiredMessages;

    /// Returns `Ok(())` if the attached messages indeed prove that a malicious action happened.
    ///
    /// The signatures and metadata of the messages will be checked internally before this method is called,
    /// the responsibility of this method is just to check the message contents.
    ///
    /// `messages` gives access to messages stored as the evidence; these include the parts
    /// of the message that triggered the error, and possibly earlier messages
    /// (if defined by [`ProtocolError::required_messages`]).
    fn verify_evidence(
        &self,
        round_id: &RoundId,
        from: &Id,
        shared_randomness: &[u8],
        shared_data: &<<Self::Round as Round<Id>>::Protocol as Protocol<Id>>::SharedData,
        messages: EvidenceMessages<'_, Id, Self::Round>,
    ) -> Result<(), EvidenceError>;
}

#[derive(Debug)]
pub(crate) struct EvidenceProtocolMessage {
    pub(crate) direct_message: Option<DirectMessage>,
    pub(crate) normal_broadcast: Option<NormalBroadcast>,
    pub(crate) echo_broadcast: Option<EchoBroadcast>,
}

/// The messages from the guilty party collected as an evidence of a provable error.
///
/// The contents depend on what was defined by [`ProtocolError::required_messages`].
#[derive(Debug)]
pub struct EvidenceMessages<'a, Id, R: Round<Id>> {
    message: EvidenceProtocolMessage,
    previous_messages: BTreeMap<RoundId, EvidenceProtocolMessage>,
    combined_echos: BTreeMap<RoundId, BTreeMap<Id, EchoBroadcast>>,
    format: &'a BoxedFormat,
    phantom: PhantomData<fn() -> R>,
}

impl<'a, Id, R> EvidenceMessages<'a, Id, R>
where
    R: Round<Id>,
{
    pub(crate) fn new(
        format: &'a BoxedFormat,
        message: EvidenceProtocolMessage,
        previous_messages: BTreeMap<RoundId, EvidenceProtocolMessage>,
        combined_echos: BTreeMap<RoundId, BTreeMap<Id, EchoBroadcast>>,
    ) -> Self {
        Self {
            format,
            message,
            previous_messages,
            combined_echos,
            phantom: PhantomData,
        }
    }
}

impl<'a, Id, R> EvidenceMessages<'a, Id, R>
where
    Id: PartyId,
    R: Round<Id>,
{
    /// Returns a stored echo broadcast from a previous round.
    pub fn previous_echo_broadcast<PR: Round<Id>>(
        &self,
        round_num: RoundNum,
    ) -> Result<PR::EchoBroadcast, EvidenceError> {
        // TODO (#123): we can check here that the RoundInfo corresponding to `round_num` is of a correct type.
        let message_parts = self.previous_messages.get(&RoundId::new(round_num)).ok_or_else(|| {
            EvidenceError::InvalidEvidence(format!(
                "Message parts for round {round_num} are not included in the evidence"
            ))
        })?;
        message_parts
            .echo_broadcast
            .as_ref()
            .ok_or_else(|| {
                EvidenceError::InvalidEvidence(format!(
                    "Echo broadcast for round {round_num} is not included in the evidence"
                ))
            })?
            .deserialize::<PR::EchoBroadcast>(self.format)
            .map_err(|error| {
                EvidenceError::InvalidEvidence(format!(
                    "Failed to deserialize an echo broadcast for round {round_num}: {error}",
                ))
            })
    }

    /// Returns a stored normal broadcast from a previous round.
    pub fn previous_normal_broadcast<PR: Round<Id>>(
        &self,
        round_num: RoundNum,
    ) -> Result<PR::NormalBroadcast, EvidenceError> {
        // TODO (#123): we can check here that the RoundInfo corresponding to `round_num` is of a correct type.
        let message_parts = self.previous_messages.get(&RoundId::new(round_num)).ok_or_else(|| {
            EvidenceError::InvalidEvidence(format!(
                "Message parts for round {round_num} are not included in the evidence"
            ))
        })?;
        message_parts
            .normal_broadcast
            .as_ref()
            .ok_or_else(|| {
                EvidenceError::InvalidEvidence(format!(
                    "Normal broadcast for round {round_num} is not included in the evidence"
                ))
            })?
            .deserialize::<PR::NormalBroadcast>(self.format)
            .map_err(|error| {
                EvidenceError::InvalidEvidence(format!(
                    "Failed to deserialize a normal broadcast for round {round_num}: {error}",
                ))
            })
    }

    /// Returns a stored direct message from a previous round.
    pub fn previous_direct_message<PR: Round<Id>>(
        &self,
        round_num: RoundNum,
    ) -> Result<PR::DirectMessage, EvidenceError> {
        // TODO (#123): we can check here that the RoundInfo corresponding to `round_num` is of a correct type.
        let message_parts = self.previous_messages.get(&RoundId::new(round_num)).ok_or_else(|| {
            EvidenceError::InvalidEvidence(format!(
                "Message parts for round {round_num} are not included in the evidence"
            ))
        })?;
        message_parts
            .direct_message
            .as_ref()
            .ok_or_else(|| {
                EvidenceError::InvalidEvidence(format!(
                    "Direct message for round {round_num} is not included in the evidence"
                ))
            })?
            .deserialize::<PR::DirectMessage>(self.format)
            .map_err(|error| {
                EvidenceError::InvalidEvidence(format!(
                    "Failed to deserialize a normal broadcast for round {round_num}: {error}",
                ))
            })
    }

    /// Returns a map with echoed broadcasts from a previous round.
    pub fn combined_echos<PR: Round<Id>>(
        &self,
        round_num: RoundNum,
    ) -> Result<BTreeMap<Id, PR::EchoBroadcast>, EvidenceError> {
        let combined_echos = self
            .combined_echos
            .get(&RoundId::new(round_num))
            .ok_or_else(|| EvidenceError::InvalidEvidence(format!("Combined echos for round {round_num} not found")))?;
        combined_echos
            .iter()
            .map(|(id, echo_broadcast)| {
                echo_broadcast
                    .deserialize::<PR::EchoBroadcast>(self.format)
                    .map_err(|error| {
                        EvidenceError::InvalidEvidence(format!(
                            "Failed to deserialize a direct message for round {round_num}: {error}",
                        ))
                    })
                    .map(|echo_broadcast| (id.clone(), echo_broadcast))
            })
            .collect()
    }

    /// Returns the stored direct message from the round that triggered the error.
    pub fn direct_message(&self) -> Result<R::DirectMessage, EvidenceError> {
        self.message
            .direct_message
            .as_ref()
            .ok_or_else(|| EvidenceError::InvalidEvidence("Direct message is not included in the evidence".into()))?
            .deserialize::<R::DirectMessage>(self.format)
            .map_err(|err| EvidenceError::InvalidEvidence(format!("Error deserializing direct message: {err}")))
    }

    /// Returns the stored echo broadcast from the round that triggered the error.
    pub fn echo_broadcast(&self) -> Result<R::EchoBroadcast, EvidenceError> {
        self.message
            .echo_broadcast
            .as_ref()
            .ok_or_else(|| EvidenceError::InvalidEvidence("Echo broadcast is not included in the evidence".into()))?
            .deserialize::<R::EchoBroadcast>(self.format)
            .map_err(|err| EvidenceError::InvalidEvidence(format!("Error deserializing echo broadcast: {err}")))
    }

    /// Returns the stored normal broadcast from the round that triggered the error.
    pub fn normal_broadcast(&self) -> Result<R::NormalBroadcast, EvidenceError> {
        self.message
            .normal_broadcast
            .as_ref()
            .ok_or_else(|| EvidenceError::InvalidEvidence("Normal broadcast is not included in the evidence".into()))?
            .deserialize::<R::NormalBroadcast>(self.format)
            .map_err(|err| EvidenceError::InvalidEvidence(format!("Error deserializing normal broadcast: {err}")))
    }

    pub(crate) fn into_round<NR>(self) -> EvidenceMessages<'a, Id, NR>
    where
        NR: Round<
            Id,
            EchoBroadcast = R::EchoBroadcast,
            NormalBroadcast = R::NormalBroadcast,
            DirectMessage = R::DirectMessage,
        >,
    {
        EvidenceMessages::<Id, NR> {
            message: self.message,
            previous_messages: self.previous_messages,
            combined_echos: self.combined_echos,
            format: self.format,
            phantom: PhantomData,
        }
    }
}

/// A placeholder for [`Round::ProtocolError`] for the rounds that do not generate errors.
#[derive_where::derive_where(Clone)]
#[derive(Debug, Copy, Serialize, Deserialize)]
pub struct NoProtocolErrors<R>(PhantomData<fn() -> R>);

impl<Id, R> ProtocolError<Id> for NoProtocolErrors<R>
where
    Id: PartyId,
    R: Round<Id, ProtocolError = Self>,
{
    type Round = R;
    fn description(&self) -> String {
        panic!("Methods of `NoProtocolErrors` should not be called during normal operation.")
    }
    fn required_messages(&self, _round_id: &RoundId) -> RequiredMessages {
        panic!("Methods of `NoProtocolErrors` should not be called during normal operation.")
    }
    fn verify_evidence(
        &self,
        _round_id: &RoundId,
        _from: &Id,
        _shared_randomness: &[u8],
        _shared_data: &<<Self::Round as Round<Id>>::Protocol as Protocol<Id>>::SharedData,
        _messages: EvidenceMessages<'_, Id, Self::Round>,
    ) -> Result<(), EvidenceError> {
        panic!("Methods of `NoProtocolErrors` should not be called during normal operation.")
    }
}

/// Declares which parts of the message from a round have to be stored to serve as the evidence of malicious behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequiredMessageParts {
    pub(crate) echo_broadcast: bool,
    pub(crate) normal_broadcast: bool,
    pub(crate) direct_message: bool,
}

impl RequiredMessageParts {
    fn new(echo_broadcast: bool, normal_broadcast: bool, direct_message: bool) -> Self {
        // We must require at least one part, otherwise this struct doesn't need to be created.
        debug_assert!(echo_broadcast || normal_broadcast || direct_message);
        Self {
            echo_broadcast,
            normal_broadcast,
            direct_message,
        }
    }

    /// Store echo broadcast
    pub fn echo_broadcast() -> Self {
        Self::new(true, false, false)
    }

    /// Store normal broadcast
    pub fn normal_broadcast() -> Self {
        Self::new(false, true, false)
    }

    /// Store direct message
    pub fn direct_message() -> Self {
        Self::new(false, false, true)
    }

    /// Store echo broadcast in addition to what is already stored.
    pub fn and_echo_broadcast(&self) -> Self {
        Self::new(true, self.normal_broadcast, self.direct_message)
    }

    /// Store normal broadcast in addition to what is already stored.
    pub fn and_normal_broadcast(&self) -> Self {
        Self::new(self.echo_broadcast, true, self.direct_message)
    }

    /// Store direct message in addition to what is already stored.
    pub fn and_direct_message(&self) -> Self {
        Self::new(self.echo_broadcast, self.normal_broadcast, true)
    }
}

/// Declares which messages from this and previous rounds
/// have to be stored to serve as the evidence of malicious behavior.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequiredMessages {
    pub(crate) this_round: RequiredMessageParts,
    pub(crate) previous_rounds: Option<BTreeMap<RoundId, RequiredMessageParts>>,
    pub(crate) combined_echos: Option<BTreeSet<RoundId>>,
}

impl RequiredMessages {
    /// The general case constructor.
    ///
    /// `this_round` specifies the message parts to be stored from the message that triggered the error.
    ///
    /// `previous_rounds` specifies, optionally, if any message parts from the previous rounds need to be included.
    ///
    /// `combined_echos` specifies, optionally, if any echoed broadcasts need to be included.
    /// The combined echos are echo broadcasts sent by a party during the echo round,
    /// where it bundles all the received broadcasts and sends them back to everyone.
    /// That is, they will include the echo broadcasts from all other nodes signed by the guilty party.
    pub fn new(
        this_round: RequiredMessageParts,
        previous_rounds: Option<BTreeMap<RoundId, RequiredMessageParts>>,
        combined_echos: Option<BTreeSet<RoundId>>,
    ) -> Self {
        Self {
            this_round,
            previous_rounds,
            combined_echos,
        }
    }

    pub(crate) fn group_under(self, group_num: GroupNum) -> Self {
        let previous_rounds = self.previous_rounds.map(|previous_rounds| {
            previous_rounds
                .into_iter()
                .map(|(round_id, required)| (round_id.group_under(group_num), required))
                .collect()
        });

        let combined_echos = self.combined_echos.map(|combined_echos| {
            combined_echos
                .into_iter()
                .map(|round_id| round_id.group_under(group_num))
                .collect()
        });

        RequiredMessages {
            this_round: self.this_round,
            previous_rounds,
            combined_echos,
        }
    }
}

/// An error that can occur during the validation of an evidence of a protocol error.
#[derive(Debug, Clone)]
pub enum EvidenceError {
    /// Indicates a local problem, usually a bug in the library code.
    Local(LocalError),
    /// The evidence is improperly constructed
    ///
    /// This can indicate many things, such as: messages missing, invalid signatures, invalid messages,
    /// the messages not actually proving the malicious behavior.
    /// See the attached description for details.
    InvalidEvidence(String),
}

impl From<LocalError> for EvidenceError {
    fn from(error: LocalError) -> Self {
        Self::Local(error)
    }
}
