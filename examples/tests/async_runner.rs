extern crate alloc;

use alloc::collections::BTreeSet;

use manul::{
    dev::{tokio::run_async, BinaryFormat, TestSessionParams, TestSigner},
    signature::Keypair,
};
use manul_example::simple::SimpleProtocolEntryPoint;
use rand_core::OsRng;

async fn async_run(offload_processing: bool) {
    // Create 4 parties
    let signers = (0..3).map(TestSigner::new).collect::<Vec<_>>();
    let all_ids = signers
        .iter()
        .map(|signer| signer.verifying_key())
        .collect::<BTreeSet<_>>();

    // Create 4 entry points
    let entry_points = signers
        .into_iter()
        .map(|signer| {
            let entry_point = SimpleProtocolEntryPoint::new(all_ids.clone());
            (signer, entry_point)
        })
        .collect::<Vec<_>>();

    // Run the protocol
    run_async::<_, TestSessionParams<BinaryFormat>>(&mut OsRng, entry_points, offload_processing)
        .await
        .unwrap();
}

#[tokio::test]
async fn async_run_no_offload() {
    async_run(false).await
}

#[tokio::test]
async fn async_run_with_offload() {
    async_run(true).await
}
