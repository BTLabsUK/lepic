//! Comparing a LEPIC run with its reference run of the same story.

use super::view::{differences, restarted_differences};
use super::{AMOUNT, MinedShape, World, hex};

/// The slate file the subject wrote, and whether the subject created the slate in it.
#[derive(Debug, Clone, Copy)]
pub struct SubjectFile {
    pub name: &'static str,
    pub created: bool,
}

/// Every difference between the LEPIC run and the reference run. `restarted` says the LEPIC
/// run cancelled its slate and started over on a new one, so only what does not depend on
/// output keys is compared.
pub fn compare(
    name: &str,
    lepic: &World,
    reference: &World,
    subject_file: SubjectFile,
    restarted: bool,
) -> Vec<String> {
    let mut found = Vec::new();
    if lepic.checkpoints.len() != reference.checkpoints.len() {
        found.push(format!(
            "{name}: {} checkpoints, reference {}",
            lepic.checkpoints.len(),
            reference.checkpoints.len()
        ));
    }
    let compare_views = if restarted {
        restarted_differences
    } else {
        differences
    };
    for (observed, expected) in lepic.checkpoints.iter().zip(&reference.checkpoints) {
        // The initiator records the transaction at once, the responder once it has replied.
        if observed.label != "initiated"
            && (observed.peer.tx.is_none() || observed.subject.tx.is_none())
        {
            found.push(format!("{name} {}: a wallet has no entry", observed.label));
        }
        for difference in compare_views(&observed.peer, &expected.peer) {
            found.push(format!("{name} {}: peer {difference}", observed.label));
        }
        let expected_subject = expected_subject(expected, observed.label, subject_file);
        for difference in compare_views(&observed.subject, &expected_subject) {
            found.push(format!("{name} {}: subject {difference}", observed.label));
        }
    }
    let (mined, reference_mined) = if restarted {
        (
            format!("{:?}", kernel_shapes(lepic)),
            format!("{:?}", kernel_shapes(reference)),
        )
    } else {
        (
            format!("{:?}", lepic.mined_shapes()),
            format!("{:?}", reference.mined_shapes()),
        )
    };
    if mined != reference_mined {
        found.push(format!(
            "{name}: mined {mined}, reference {reference_mined}"
        ));
    }
    if lepic.height() != reference.height() {
        found.push(format!("{name}: chain heights differ"));
    }
    let (shape, reference_shape) = (
        file_shape(lepic, subject_file),
        file_shape(reference, subject_file),
    );
    if shape != reference_shape {
        found.push(format!(
            "{name}: subject wrote {shape:?}, reference {reference_shape:?}"
        ));
    }
    found.extend(check_v3_file(lepic, subject_file).map(|d| format!("{name}: {d}")));
    found.extend(check_kernel(lepic).map(|d| format!("{name}: {d}")));
    found
}

/// The reference's view of the subject. Until the invoice is paid and finalized, an upstream
/// issuer counts the invoice's output as awaiting finalization, while LEPIC counts it in no
/// figure (a deliberate difference, commit 2cc8512): the reference view loses that amount.
fn expected_subject(
    expected: &super::Checkpoint,
    label: &str,
    file: SubjectFile,
) -> super::view::PartyView {
    let mut view = expected.subject.clone();
    if file.created && file.name == "case.invoice" && matches!(label, "initiated" | "responded") {
        view.balance.awaiting_finalization =
            view.balance.awaiting_finalization.saturating_sub(AMOUNT);
    }
    view
}

/// The file LEPIC wrote is in the V3 shape with `version` and `orig_version` 3 (ADR 0015).
fn check_v3_file(world: &World, file: SubjectFile) -> Option<String> {
    let (version, keys) = file_shape(world, file);
    let v3_keys = ["ttl_cutoff_height", "payment_proof"]
        .iter()
        .all(|key| keys.iter().any(|k| k == key));
    let header_three = version.get(..2) == Some(&[Some(3), Some(3)][..]);
    (!v3_keys || !header_three)
        .then(|| format!("subject wrote header {version:?} and keys {keys:?}, not V3 at 3/3"))
}

/// The mined transactions without their commitments, which a restarted run derived from other
/// keys: how many inputs and outputs each has, and its kernels.
fn kernel_shapes(world: &World) -> Vec<(usize, usize, Vec<String>)> {
    world
        .mined_shapes()
        .into_iter()
        .map(
            |MinedShape {
                 inputs,
                 outputs,
                 kernels,
             }| (inputs.len(), outputs.len(), kernels),
        )
        .collect()
}

/// The shape of a slate file: its header and its top-level keys, which tell V2 from V3.
fn file_shape(world: &World, file: SubjectFile) -> (Vec<Option<u64>>, Vec<String>) {
    let text = std::fs::read_to_string(world.file(file.name)).unwrap();
    let value: serde_json::Value = serde_json::from_str(&text).unwrap();
    let header = |key: &str| {
        value
            .pointer(&format!("/version_info/{key}"))
            .and_then(serde_json::Value::as_u64)
    };
    let mut version = vec![header("version"), header("orig_version")];
    // A new slate records the block header version of the creator's network at the tip, and
    // the test chain changes header version far earlier than floonet, where LEPIC runs. A reply
    // carries the header it received, so there the whole header is compared.
    if !file.created {
        version.push(header("block_header_version"));
    }
    let keys = value
        .as_object()
        .map(|object| object.keys().cloned().collect())
        .unwrap_or_default();
    (version, keys)
}

/// The peer, when it recorded a kernel, recorded the one the chain mined.
fn check_kernel(world: &World) -> Option<String> {
    let mined = hex(&world.mined.first()?.body.kernels.first()?.excess.0);
    let recorded = world
        .checkpoints
        .last()?
        .peer
        .tx
        .as_ref()?
        .kernel_excess
        .clone()??;
    (recorded != mined).then(|| format!("peer recorded kernel {recorded}, the chain mined {mined}"))
}
