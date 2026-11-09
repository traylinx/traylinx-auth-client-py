# Sentinel Pass SDK hardening candidate

Date: 2026-10-22. Status: **opt-in release candidate; production integration is not qualified**.
This SDK supplies Sentinel Pass authentication, not the full Google A2A task protocol.
The historical August sprint is broader than this change; it is not declared complete.

## Verified scope

- Existing OAuth token and form-encoded introspection endpoints and wire field names remain unchanged.
- Existing client/helper entry points remain available. Verified metadata is now available through `introspectToken` (JS) / `introspect_token` (Python); boolean validation remains available.
- Access tokens go to Sentinel. Remote-agent helpers send only the agent secret token and agent id. `getRequestHeaders` / `get_request_headers` remains Sentinel-only and must not be used as incoming A2A proof.
- TLS verification remains enabled. HTTP, URL userinfo, fragments, ambiguous credentials and caller-supplied credential/transport overrides are rejected before obtaining credentials. Base URLs cannot contain query strings.
- Credential-bearing redirects are refused. Both languages have request/decoded-response size limits: 4 MiB generally, 64 KiB for authentication responses. Streaming request bodies are not supported.
- Automatic retries are restricted to GET/HEAD. Token exchanges, introspection, RPC and other writes are never automatically replayed. A retry does not start with a fresh time budget.
- Token refresh coalesces concurrent calls. Invalid exchanges clear both cached tokens. Cache-disabled operations obtain one coherent token pair.
- Introspection requires exact agent-id binding, boolean active status, a future numeric expiry and `a2a` scope. If an explicit `is_active:false` is returned, verification fails. No introspection cache is used.
- Errors do not reflect remote response bodies, credentials or raw transport exceptions. Missing/invalid credentials return 401 through middleware; authentication-backend failures return a generic 503. Downstream handler errors are not swallowed.
- Existing test assertions that accepted malformed/ambiguous credentials, unsafe retries or leaked error text were deliberately tightened. Test mocking was corrected, not used to bypass these boundaries.

## Two token lifetimes

Sentinel's inspected token endpoint returns access-token `expires_in` but no separate agent-pass lifetime. Its server-side pass window is independently configurable. Do not assume the two lifetimes are equal.

The SDK understands optional `agent_secret_token_expires_in` if the server provides it. Alternatively an operator may set `agentTokenTtlSeconds` (JS) / `agent_token_ttl_seconds` (Python), **only after verifying the server's configured lifetime**. The shorter access/pass lifetime wins. Refresh skew defaults to 30 seconds, capped at 10% of short lifetimes.

If no pass lifetime is known, the pass is not reused across sequential operations. Concurrent calls still share the exchange already in flight; access-token caching remains separate. This conservative default can increase token exchanges. It must be considered in capacity testing; it is not a production performance claim.

## Compatibility and runtime changes

This is intentionally a new prerelease, not a silent patch to an installed stable SDK.
- JavaScript candidate: `1.1.0-rc.1`, Node.js >=22.
- Python candidate: `1.1.0rc1`, Python >=3.11,<4.
- Runtime/development dependency floors and locks refreshed. Legacy Node 14 and Python 3.8 badges are no longer advertised for this candidate.
- HTTPS-only transport, rejected ambiguous headers, restricted request options, earlier refresh, stricter metadata, sanitized error strings and middleware 503 are deliberate security behavior changes. Callers relying on old unsafe behavior must migrate.
- Optional custom outgoing options: JS `headers`, `params`, `data`, `timeout`, `signal`; Python `headers`, `params`, `data`, `json`, `timeout`. Authorization/host/cookie overrides are forbidden; input objects are not mutated.
- Header-extraction helpers return credentials to the caller. If callers send them using their own HTTP client, the SDK cannot enforce that client's TLS, redirects, timeouts or logging policy.

## Deployment gates: not solved by an SDK

**Production integration requires server qualification.** Before enabling production agent access, verify the deployed Sentinel server's caller and verifier deactivation, revocation and token-lifetime behavior. The SDK cannot infer server state that introspection omits. Do not interpret publication of this prerelease as approval of a production deployment. Independent security review and live integration qualification remain required.

Authentication is not authorization. html2md must retain its user bearer-token path and add a separate Sentinel-agent path, then enforce capture grants/ownership/quotas. Reject conflicting credentials; never fall back to another principal after failed proof. Agent ids supplied in headers are untrusted until introspected. Do not log or persist web passwords, passes or tokens.

The outgoing agent destination must be selected by trusted application configuration. This SDK is not an SSRF filter and does not infer that arbitrary scraped URLs are trusted agents. html2md's browser-destination controls remain separate.

## Qualification boundaries

Tests use synthetic credentials and owned loopback HTTPS fixtures with certificate verification, not real accounts. They cover redirect non-delivery, POST non-replay, decoded size limits, slow-drip time bounds, wire encoding, metadata binding, concurrency, caching and redaction. No production credentials were used and no live Sentinel pass was minted.

Local test/coverage and package qualification are recorded in `QUALIFICATION.md`. Linux/Windows CI, independent security review, production load tests and live Sentinel qualification remain production adoption gates. This change does not claim completion of every work package in the historical hardening sprint.

## Python transport and async behavior

The public client remains synchronous. FastAPI decorators use Starlette's bounded thread-pool bridge so HTTP I/O does not block the event loop. Cancellation of an awaiting coroutine does not forcibly terminate an in-flight Requests call. Requests socket reads are capped at five seconds or the remaining budget; decoded chunks are checked against the operation deadline. A stalled read can overshoot that deadline by at most one configured socket-read interval; DNS behavior depends on the platform resolver. This is not hard real-time cancellation. The shared session is serialized and does not reuse server cookies or implicit environment proxies/netrc credentials. This favors correctness over parallel throughput; benchmark before promising capacity.

Run source tests from the locked isolated environment: `poetry install --with dev`, then `poetry run pytest`. Do not fall back to a globally installed SDK.
