# Local qualification

2026-10-22, macOS. Source baseline: 0abbc2f. Candidate branch: `hardening/sentinel-capture-20261022`.

- 227 tests pass; no skipped tests. Coverage: 94.50% statements; the existing 90% gates remain enabled.
- Source runtime: Python 3.12.7 in a locked isolated environment.
- Runtime and test-environment dependency audit reports zero known vulnerabilities at this check. Advisory databases can change; audit again at release. This is not proof of absence of vulnerabilities.
- Real loopback HTTPS tests verify certificate checks, form fields, metadata, no credential-bearing redirects, no POST retry, read retries, response limits and slow-drip bounds. Synthetic credentials only.
- Concurrency and secret-redaction regressions included. Python tests now block accidental external network access.

Exact-artifact verification uses fresh installation roots, not the source checkout. Release hashes and test results are retained by the maintainers. Registry publication of this opt-in candidate does not remove the production qualification gates below.

## Remaining production adoption gates

1. Qualify Sentinel caller and verifier deactivation and revocation as described in HARDENING.md.
2. Verify deployed token lifetime and revocation semantics using approved integration credentials.
3. Independent security review, Linux/Windows CI and representative load/cancellation qualification. Local tests are not cross-platform or production-capacity evidence.
4. Only then approve stable production adoption and add Sentinel authentication alongside html2md's existing user-token path. Enforce local authorization separately.

No html2md installation, server modification or production deployment is part of this qualification.
