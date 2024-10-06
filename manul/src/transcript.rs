use alloc::collections::{btree_map::Entry, BTreeMap};
use core::fmt::Debug;

use crate::error::{LocalError, RemoteError};
use crate::evidence::Evidence;
use crate::message::SignedMessage;
use crate::round::{DirectMessage, EchoBroadcast, Protocol, RoundId};

pub(crate) struct Transcript<P: Protocol, Verifier, S> {
    echo_broadcasts: BTreeMap<RoundId, BTreeMap<Verifier, SignedMessage<S, EchoBroadcast>>>,
    direct_messages: BTreeMap<RoundId, BTreeMap<Verifier, SignedMessage<S, DirectMessage>>>,
    provable_errors: BTreeMap<Verifier, Evidence<P, Verifier, S>>,
    unprovable_errors: BTreeMap<Verifier, RemoteError>,
}

impl<P: Protocol, Verifier: Debug + Clone + Ord, S: Clone> Transcript<P, Verifier, S> {
    pub fn new() -> Self {
        Self {
            echo_broadcasts: BTreeMap::new(),
            direct_messages: BTreeMap::new(),
            provable_errors: BTreeMap::new(),
            unprovable_errors: BTreeMap::new(),
        }
    }

    pub fn update(
        self,
        round_id: RoundId,
        echo_broadcasts: BTreeMap<Verifier, SignedMessage<S, EchoBroadcast>>,
        direct_messages: BTreeMap<Verifier, SignedMessage<S, DirectMessage>>,
        provable_errors: BTreeMap<Verifier, Evidence<P, Verifier, S>>,
        unprovable_errors: BTreeMap<Verifier, RemoteError>,
    ) -> Result<Self, LocalError> {
        let mut all_echo_broadcasts = self.echo_broadcasts;
        match all_echo_broadcasts.entry(round_id) {
            Entry::Vacant(entry) => entry.insert(echo_broadcasts),
            Entry::Occupied(_) => {
                return Err(LocalError::new(format!(
                    "An echo-broadcasts entry for {round_id:?} already exists"
                )))
            }
        };

        let mut all_direct_messages = self.direct_messages;
        match all_direct_messages.entry(round_id) {
            Entry::Vacant(entry) => entry.insert(direct_messages),
            Entry::Occupied(_) => {
                return Err(LocalError::new(format!(
                    "A direct messages entry for {round_id:?} already exists"
                )))
            }
        };

        let mut all_provable_errors = self.provable_errors;
        for (verifier, error) in provable_errors {
            if all_provable_errors
                .insert(verifier.clone(), error)
                .is_some()
            {
                return Err(LocalError::new(format!(
                    "A provable errors entry for {verifier:?} already exists"
                )));
            }
        }

        let mut all_unprovable_errors = self.unprovable_errors;
        for (verifier, error) in unprovable_errors {
            if all_unprovable_errors
                .insert(verifier.clone(), error)
                .is_some()
            {
                return Err(LocalError::new(format!(
                    "An unprovable errors entry for {verifier:?} already exists"
                )));
            }
        }

        Ok(Self {
            echo_broadcasts: all_echo_broadcasts,
            direct_messages: all_direct_messages,
            provable_errors: all_provable_errors,
            unprovable_errors: all_unprovable_errors,
        })
    }

    pub fn get_echo_broadcast(
        &self,
        round_id: RoundId,
        from: &Verifier,
    ) -> Result<SignedMessage<S, EchoBroadcast>, LocalError> {
        self.echo_broadcasts
            .get(&round_id)
            .ok_or_else(|| {
                LocalError::new(format!("No echo broadcasts registered for {round_id:?}"))
            })?
            .get(from)
            .map(|echo_broadcast| echo_broadcast.clone())
            .ok_or_else(|| {
                LocalError::new(format!(
                    "No echo broadcasts registered for {from:?} in {round_id:?}"
                ))
            })
    }

    pub fn get_direct_message(
        &self,
        round_id: RoundId,
        from: &Verifier,
    ) -> Result<SignedMessage<S, DirectMessage>, LocalError> {
        self.direct_messages
            .get(&round_id)
            .ok_or_else(|| {
                LocalError::new(format!("No direct messages registered for {round_id:?}"))
            })?
            .get(from)
            .map(|direct_message| direct_message.clone())
            .ok_or_else(|| {
                LocalError::new(format!(
                    "No direct messages registered for {from:?} in {round_id:?}"
                ))
            })
    }

    pub fn is_banned(&self, from: &Verifier) -> bool {
        self.provable_errors.contains_key(from) || self.unprovable_errors.contains_key(from)
    }

    pub fn echo_broadcasts(
        &self,
        round_id: RoundId,
    ) -> Result<BTreeMap<Verifier, SignedMessage<S, EchoBroadcast>>, LocalError> {
        self.echo_broadcasts
            .get(&round_id)
            .map(|echo_broadcasts| echo_broadcasts.clone())
            .ok_or_else(|| {
                LocalError::new(format!(
                    "Echo-broadcasts for {round_id:?} are not in the transcript"
                ))
            })
    }

    pub fn register_unprovable_error(
        &mut self,
        from: &Verifier,
        error: RemoteError,
    ) -> Result<(), LocalError> {
        if self.unprovable_errors.insert(from.clone(), error).is_some() {
            return Err(LocalError::new(format!(
                "An unprovable errors entry for {from:?} already exists"
            )));
        }
        Ok(())
    }
}
