use alloc::{collections::BTreeSet, format, vec::Vec};

use rand_core::CryptoRngCore;

use super::{
    extend::{ExtendableEntryPoint, RoundExtension},
    run_sync::{run_sync, ExecutionResult},
};
use crate::{
    protocol::{EntryPoint, Protocol, Round},
    session::{LocalError, SessionParameters},
    signature::Keypair,
};

/// Applies the `extend` function to one of the entry points in the given list and returns the new list
/// along with the ID of the modified entry point.
#[allow(clippy::type_complexity)]
pub fn extend_one<SP, EP>(
    entry_points: Vec<(SP::Signer, EP)>,
    extend: impl Fn(ExtendableEntryPoint<SP::Verifier, EP>) -> ExtendableEntryPoint<SP::Verifier, EP>,
) -> Result<(SP::Verifier, Vec<(SP::Signer, ExtendableEntryPoint<SP::Verifier, EP>)>), LocalError>
where
    SP: SessionParameters,
    EP: EntryPoint<SP::Verifier>,
{
    let ids = entry_points
        .iter()
        .map(|(signer, _ep)| signer.verifying_key())
        .collect::<BTreeSet<_>>();
    let modified_id = ids
        .first()
        .ok_or_else(|| LocalError::new("Entry points list cannot be empty"))?;
    let modified_entry_points = entry_points
        .into_iter()
        .map(|(signer, entry_point)| {
            let id = signer.verifying_key();
            let mut entry_point = ExtendableEntryPoint::new(entry_point);
            if &id == modified_id {
                entry_point = extend(entry_point);
            }
            (signer, entry_point)
        })
        .collect();
    Ok((modified_id.clone(), modified_entry_points))
}

/// Checks that the result for the node with the `target_id` is a provable error,
/// it can be verified using `shared_data`, and its description contains `expected_description`.
pub fn check_evidence<P, SP>(
    target_id: &SP::Verifier,
    execution_result: ExecutionResult<P, SP>,
    shared_data: &P::SharedData,
    expected_description: &str,
) -> Result<(), LocalError>
where
    P: Protocol<SP::Verifier>,
    SP: SessionParameters,
{
    let mut reports = execution_result.reports;

    let misbehaving_party_report = reports
        .remove(target_id)
        .ok_or_else(|| LocalError::new("Misbehaving node ID is not present in the reports"))?;
    assert!(misbehaving_party_report.provable_errors.is_empty());

    for (id, report) in reports {
        if report.provable_errors.is_empty() {
            return Err(LocalError::new(format!(
                "Node {id:?} did not report any provable errors, but it should have"
            )));
        }

        if report.provable_errors.len() > 1 {
            let errors = report
                .provable_errors
                .values()
                .map(|evidence| evidence.description())
                .collect::<Vec<_>>()
                .join(", ");
            return Err(LocalError::new(format!(
                "Node {id:?} reported {} provable errors when one was expected. Errors: {errors}",
                errors.len()
            )));
        }

        let description = report
            .provable_errors
            .get(target_id)
            .ok_or_else(|| {
                LocalError::new(format!(
                    "Node {id:?} did not generate a provable error report \
                    about the misbehaving node ({target_id:?})."
                ))
            })?
            .description();
        if !description.contains(expected_description) {
            return Err(LocalError::new(format!(
                "Got '{description}', expected '{expected_description}'"
            )));
        }

        let verification_result = report
            .provable_errors
            .get(target_id)
            .ok_or_else(|| {
                LocalError::new(format!(
                    "Node {id:?}'s report does not contain evidence for the misbehaving node {target_id:?}."
                ))
            })?
            .verify(shared_data);
        if verification_result.is_err() {
            return Err(LocalError::new(format!("Failed to verify: {verification_result:?}")));
        }
    }

    Ok(())
}

/// Applies the `extend` function to one of the entry points in the given list,
/// executes the protocol with the resulting entry points,
/// and checks the evidence for the modified node using [`check_evidence`].
#[allow(clippy::type_complexity)]
pub fn check_evidence_with_extensions<SP, EP>(
    rng: &mut impl CryptoRngCore,
    entry_points: Vec<(SP::Signer, EP)>,
    extend: impl Fn(ExtendableEntryPoint<SP::Verifier, EP>) -> ExtendableEntryPoint<SP::Verifier, EP>,
    shared_data: &<EP::Protocol as Protocol<SP::Verifier>>::SharedData,
    expected_description: &str,
) -> Result<(), LocalError>
where
    SP: SessionParameters,
    EP: EntryPoint<SP::Verifier>,
{
    let (misbehaving_id, modified_entry_points) = extend_one::<SP, _>(entry_points, extend)?;
    let execution_result = run_sync::<_, SP>(rng, modified_entry_points)?;
    check_evidence(&misbehaving_id, execution_result, shared_data, expected_description)
}

/// Same as [`check_evidence_with_extensions`], but with one extension only.
#[allow(clippy::type_complexity)]
pub fn check_evidence_with_extension<SP, EP, Ext>(
    rng: &mut impl CryptoRngCore,
    entry_points: Vec<(SP::Signer, EP)>,
    extension: &Ext,
    shared_data: &<EP::Protocol as Protocol<SP::Verifier>>::SharedData,
    expected_description: &str,
) -> Result<(), LocalError>
where
    SP: SessionParameters,
    EP: EntryPoint<SP::Verifier>,
    Ext: RoundExtension<SP::Verifier>,
    Ext::Round: Round<SP::Verifier, Protocol = EP::Protocol>,
{
    check_evidence_with_extensions::<SP, EP>(
        rng,
        entry_points,
        |entry_point| entry_point.with_extension(extension.clone()),
        shared_data,
        expected_description,
    )
}
