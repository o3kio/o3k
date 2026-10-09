//! O3K-side gate for the shared fabric provider contract.
//!
//! The `fabric-conformance` crate ships one executable suite that runs
//! against the reference in-memory fake kernel (`fabric_linux::RecordingRunner`).
//! Running it here as an integration test keeps the O3K build pinned to a
//! `fabric` provider revision that satisfies the fabric provider contract
//! (`contracts/fabric-provider-v1.md` in the o3kio/fabric repository), so a
//! future provider bump that breaks the contract fails O3K CI instead of
//! surfacing on hosts.
//!
//! Per ADR-0186 and SPEC-0049's provider conformance requirements, this is
//! the unprivileged provider-level gate; the privileged multi-host gate is
//! a separate harness in the fabric repository, and the real functional
//! gate (three independent KVM/libvirt hosts) remains SPEC-0049's
//! promotion requirement.
//!
//! The O3K Linux executor keeps its realm/TAP anti-spoof boundary locally and
//! uses the pinned provider contract as the shared WireGuard/VXLAN substrate
//! reference. This gate proves that pinned substrate continuously.

use fabric_conformance::run_suite;

#[test]
fn fabric_provider_conformance_suite_passes() {
    let report = run_suite();
    for case in &report.results {
        assert!(
            case.passed,
            "fabric conformance case '{}' failed: {}",
            case.name,
            case.detail.as_deref().unwrap_or("no detail")
        );
    }
    assert!(
        report.passed(),
        "fabric conformance suite must pass in full"
    );
}
