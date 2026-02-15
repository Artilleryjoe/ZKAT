# Codebase Audit: Proposed Follow-up Tasks

## 1) Typo fix task
**Issue found:** The module docstring in `zkat/agent/zkat_agent.py` uses "Entrypoint" instead of the standard spelling "Entry point".

**Proposed task:** Replace "Entrypoint" with "Entry point" in the module docstring for readability and consistency with documentation style.

**Why this matters:** Small spelling issues reduce polish and can make generated docs look less professional.

---

## 2) Bug fix task
**Issue found:** `zkat/verifier/zkat_verify.py` catches `binascii.Error` in `_verify_email`, but `binascii` is never imported. On malformed Base64 in an anchor email, this path can raise `NameError` instead of the intended verifier error.

**Proposed task:** Import `binascii` and keep the existing defensive error handling so malformed payloads fail with a clear `SystemExit` message.

**Why this matters:** The verifier should fail deterministically and clearly on corrupted email payloads.

---

## 3) Documentation/comment discrepancy task
**Issue found:** The CLI parser description in `zkat/agent/zkat_agent.py` says "ZKAT Milestone 1 attestation agent" while the repository README and milestone docs describe the current implementation as Milestone 2.

**Proposed task:** Update the CLI description string (and any nearby comments/help text, if needed) to consistently reference Milestone 2.

**Why this matters:** Inconsistent milestone labeling is confusing for users validating feature scope.

---

## 4) Test improvement task
**Issue found:** `tests/test_agent_workflow.py::test_verifier_rejects_mismatched_zk_commitment` edits the attestation and then runs verification with the original signature, so the failure is currently caused by signature validation before the ZK commitment check.

**Proposed task:** Adjust the test to isolate the ZK mismatch behavior (e.g., re-sign the tampered attestation with the fixture key, or unit-test `_verify_zk_proof` directly with validly signed input).

**Why this matters:** The test name and assertion intent should match the code path being exercised to avoid false confidence.
