use alloc::collections::BTreeSet;
use core::fmt::{self, Debug, Display};

use serde::{Deserialize, Serialize};
use tinyvec::TinyVec;

use super::errors::LocalError;

/// A round identifier.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct RoundId {
    round_nums: TinyVec<[u8; 4]>,
    is_echo: bool,
}

impl Display for RoundId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "Round ")?;
        for (i, round_num) in self.round_nums.iter().enumerate().rev() {
            write!(f, "{round_num}")?;
            if i != 0 {
                write!(f, "-")?;
            }
        }
        if self.is_echo {
            write!(f, " (echo)")?;
        }
        Ok(())
    }
}

impl RoundId {
    /// Creates a new round identifier.
    pub fn new(round_num: u8) -> Self {
        let mut round_nums = TinyVec::new();
        round_nums.push(round_num);
        Self {
            round_nums,
            is_echo: false,
        }
    }

    /// Prefixes this round ID (possibly already nested) with a group number.
    ///
    /// This is supposed to be used internally, e.g. in the chain combinator,
    /// where we have several protocols joined up, and their round numbers may repeat.
    /// Grouping allows us to disambiguate them, assigning group 1 to one protocol and group 2 to the other.
    pub(crate) fn group_under(&self, round_num: u8) -> Self {
        let mut round_nums = self.round_nums.clone();
        round_nums.push(round_num);
        Self {
            round_nums,
            is_echo: self.is_echo,
        }
    }

    /// Removes the top group prefix from this round ID
    /// and returns this prefix along with the resulting round ID.
    ///
    /// Returns the `Err` variant if the round ID is not nested.
    pub(crate) fn split_group(&self) -> Result<(u8, Self), LocalError> {
        if self.round_nums.len() == 1 {
            Err(LocalError::new("This round ID is not in a group"))
        } else {
            let mut round_nums = self.round_nums.clone();
            let group = round_nums.pop().expect("vector size greater than 1");
            let round_id = Self {
                round_nums,
                is_echo: self.is_echo,
            };
            Ok((group, round_id))
        }
    }

    /// Returns `true` if this is an ID of an echo broadcast round.
    pub(crate) fn is_echo(&self) -> bool {
        self.is_echo
    }

    /// Returns the identifier of the echo round corresponding to the given non-echo round.
    ///
    /// Panics if `self` is already an echo round identifier.
    pub(crate) fn echo(&self) -> Result<Self, LocalError> {
        // If this panic happens, there is something wrong with the internal logic
        // of managing echo-broadcast rounds.
        if self.is_echo {
            Err(LocalError::new("This is already an echo round ID"))
        } else {
            Ok(Self {
                round_nums: self.round_nums.clone(),
                is_echo: true,
            })
        }
    }

    /// Returns the identifier of the non-echo round corresponding to the given echo round.
    ///
    /// Panics if `self` is already a non-echo round identifier.
    pub(crate) fn non_echo(&self) -> Result<Self, LocalError> {
        // If this panic happens, there is something wrong with the internal logic
        // of managing echo-broadcast rounds.
        if !self.is_echo {
            Err(LocalError::new("This is already an non-echo round ID"))
        } else {
            Ok(Self {
                round_nums: self.round_nums.clone(),
                is_echo: false,
            })
        }
    }
}

impl From<u8> for RoundId {
    fn from(source: u8) -> Self {
        Self::new(source)
    }
}

impl PartialEq<u8> for RoundId {
    fn eq(&self, rhs: &u8) -> bool {
        self == &RoundId::new(*rhs)
    }
}

impl PartialEq<u8> for &RoundId {
    fn eq(&self, rhs: &u8) -> bool {
        *self == &RoundId::new(*rhs)
    }
}

/// Information about the position of the round in the state transition graph.
#[derive(Debug, Clone)]
pub struct TransitionInfo {
    /// The round ID.
    ///
    /// **Note:** these should not repeat within the same protocol, that is, the graph of
    /// transitions between rounds must be acyclic.
    pub id: RoundId,

    /// Round IDs of the rounds that can finalize into this round.
    pub parents: BTreeSet<RoundId>,

    /// Round IDs of the other rounds that the parents of this round can finalize into.
    ///
    /// For example, a round can be followed either by a happy path round or an error round,
    /// depending on the outcome of some checks during the finalization.
    pub siblings: BTreeSet<RoundId>,

    /// The round IDs of the rounds this round can finalize into.
    ///
    /// Returns an empty set if this round only finalizes into a result.
    pub children: BTreeSet<RoundId>,

    /// `true` if this round's [`Round::finalize`](`crate::protocol::Round::finalize`)
    /// may return [`FinalizeOutcome::Result`](`crate::protocol::FinalizeOutcome::Result`).
    pub may_produce_result: bool,
}

impl TransitionInfo {
    /// Nest the round IDs under the given group. Used for combinators.
    pub(crate) fn group_under(self, group: u8) -> Self {
        Self {
            id: self.id.group_under(group),
            parents: self.parents.into_iter().map(|r| r.group_under(group)).collect(),
            siblings: self.siblings.into_iter().map(|r| r.group_under(group)).collect(),
            children: self.children.into_iter().map(|r| r.group_under(group)).collect(),
            may_produce_result: self.may_produce_result,
        }
    }

    /// Returns the set of round IDs that can be simultaneously active on other nodes
    /// (not including the current round ID).
    ///
    /// This includes: the child rounds (if some nodes already finalized this round),
    /// the parent rounds (if those nodes still are not finalized while we already are),
    /// and the sibling rounds (if some nodes went on a different path).
    pub(crate) fn simultaneous_rounds(&self, followed_by_echo_round: bool) -> Result<BTreeSet<RoundId>, LocalError> {
        let mut result = if followed_by_echo_round {
            BTreeSet::from([self.id.echo()?])
        } else {
            self.parents.clone()
        };
        result.extend(self.siblings.iter().cloned());
        result.extend(self.children.iter().cloned());
        Ok(result)
    }

    pub(crate) fn id(&self) -> RoundId {
        self.id.clone()
    }

    /// Returns the corresponding transition info for the echo round following this one.
    pub(crate) fn echo(self) -> Result<Self, LocalError> {
        Ok(Self {
            id: self.id.echo()?,
            parents: [self.id.clone()].into(),
            siblings: [].into(),
            children: self.children,
            may_produce_result: self.may_produce_result,
        })
    }

    /// Creates a [`TransitionInfo`] for a non-terminating round (`round_num`) in a linear sequence
    /// of rounds starting with 1.
    ///
    /// That is, if there are rounds 1, 2, 3, ..., N, where the N-th one returns the result,
    /// this constructor can be used for rounds 1 to N-1.
    pub fn new_linear(round_num: u8) -> Self {
        Self {
            id: RoundId::new(round_num),
            parents: if round_num > 1 {
                [RoundId::new(round_num - 1)].into()
            } else {
                [].into()
            },
            siblings: [].into(),
            children: [RoundId::new(round_num + 1)].into(),
            may_produce_result: false,
        }
    }

    /// Creates a [`TransitionInfo`] for the final round (`round_num`) in a linear sequence of
    /// rounds starting with 1.
    ///
    /// That is, if there are rounds 1, 2, 3, ..., N, where the N-th one returns the result,
    /// this constructor can be used for round N.
    pub fn new_linear_terminating(round_num: u8) -> Self {
        Self {
            id: RoundId::new(round_num),
            parents: if round_num > 1 {
                [RoundId::new(round_num - 1)].into()
            } else {
                [].into()
            },
            siblings: [].into(),
            children: [].into(),
            may_produce_result: true,
        }
    }

    /// Returns a new [`TransitionInfo`] with `round_nums` added to the set of children.
    pub fn with_children(self, round_nums: BTreeSet<u8>) -> Self {
        let mut children = self.children;
        children.extend(round_nums.iter().map(|num| RoundId::new(*num)));
        Self {
            id: self.id,
            parents: self.parents,
            siblings: self.siblings,
            children,
            may_produce_result: self.may_produce_result,
        }
    }

    /// Returns a new [`TransitionInfo`] with `round_nums` added to the set of siblings.
    pub fn with_siblings(self, round_nums: BTreeSet<u8>) -> Self {
        let mut siblings = self.siblings;
        siblings.extend(round_nums.iter().map(|num| RoundId::new(*num)));
        Self {
            id: self.id,
            parents: self.parents,
            siblings,
            children: self.children,
            may_produce_result: self.may_produce_result,
        }
    }
}
