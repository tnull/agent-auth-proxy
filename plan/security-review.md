# Security review and evidence gates

Status: proposed review checklist, not a report of passed tests. This document
connects the existing contracts to adversarial scenarios and release claims.
It adds no authentication protocol, crate, or dependency. Keep the current
project and package names until a separately scoped rename.

## What the review must establish

Review three claims independently: **credential isolation**, **authorized use**,
and **confinement/inspection coverage**. An agent that cannot read a password
may still misuse an allowed account. A confined channel may still carry opaque
bytes. Successful authentication proves neither safe intent nor full visibility.

The trusted boundary includes the daemon or embedding host, configured store
adapters, operator authority, and the deployment's sandbox enforcement. Future
approver adapters are trusted to authenticate and bind human decisions; ordinary
observation consumers are not approvers or administrators. Treat agent code,
tool subprocesses, request fields, and remote content as attacker-controlled.

Approved credential recipients necessarily receive their own credentials.
Review their enrolled endpoints and response profiles, but do not claim that
filtering can prevent a malicious recipient from encoding and returning a
secret. Compromise of the trusted host or daemon is outside the credential
isolation guarantee; encrypted storage does not protect an unlocked process
from that compromise. These limits must accompany any supported-profile claim.

## Assets and permitted exposure

| Asset | Permitted custody / exposure | Review focus |
| --- | --- | --- |
| Passwords, API keys, upstream tokens | Store, trusted authentication path, exact enrolled upstream recipient | No agent, ordinary log, or observation export receives real values |
| Store unlock key and interception CA private key | Trusted host/store and their narrowly authorized consumers | Neither enters a sandbox or goes to an upstream website; only the public CA may be installed in scoped clients |
| Cookies, CSRF secrets, upstream MCP session state | Trusted, partitioned authentication/protocol state | No cross-session/account sharing; response and failure paths preserve custody |
| Fake credentials and local context handles | Bound agent session | Reuse grants no new authority; other sessions and destinations cannot redeem them |
| Session attachment | One confined agent and its authorized descendants | It grants limited proxy use, not store, operator, observer, or approver access |
| Catalog, backend references, policy | Trusted operator and necessary host components | Private metadata, even without passwords; only approved projections reach the agent |
| Sanitized communication content | Authorized agent view and separately authorized observers | Redaction does not make prompts, documents, or tool output public information |

The store contract intentionally avoids a dedicated secret-wrapper dependency.
Review ownership and diagnostic surfaces without promising complete memory
erasure, protection against a compromised host, or cryptographic isolation
between libraries in the same process.

## Reuse, duplicates, and replay

No new challenge-response scheme is required for this baseline. Distinguish
these cases instead of making a blanket claim that replay is either solved or
irrelevant:

| Case | Required behavior |
| --- | --- |
| Fake password reused in its still-valid context | Allowed for a separately authorized login, within attempt limits; it is not a one-time password |
| Fake password or context copied to another session/account/origin | Denied by the binding, independently of whether the value is known |
| Same local request ID submitted again | Return retained state, or reject conflicting work; do not dispatch twice |
| Same business action submitted with a new ID | Evaluate current policy and any approval again; local deduplication does not establish business idempotency |
| Response lost after possible dispatch | Report uncertainty; do not automatically repeat a potentially state-changing action |
| Old approval, attachment, or context reused after invalidation | Deny; restart and configuration changes cannot silently restore prior authority |
| Real upstream credential stolen through some other channel | Its native properties still apply; proxy policy cannot govern off-proxy use of that credential |

The [common operation contract](protocol-common.md) and
[authentication specification](authentication.md) remain authoritative for
these behaviors. A future signed human decision is an approval-channel concern,
not a reintroduction of an upstream agent authentication protocol.

## Adversarial review matrix

Each row names a review case, its owning contracts, and evidence needed before
the associated claim can pass. The IDs identify review cases, not new protocol
fields. Component tests alone cannot close rows requiring an actual daemon,
native store, or sandbox deployment.

| ID | Attack or failure | Required evidence and contract owner |
| --- | --- | --- |
| SR-01 | Compromised agent selects another session, item, account, or privilege | Cross-binding requests fail through each advertised ingress; no private store lookup or unauthorized dispatch follows. [Common protocol](protocol-common.md), [password manager](password-manager.md); W1/W4/W5 |
| SR-02 | Agent or remote content redirects credentials to a different destination | Controlled origins verify authority/SNI/Host agreement, admitted addresses, redirect policy, and no credential delivery to the rejected endpoint. [Architecture](architecture.md), [authentication](authentication.md); W3/W6 |
| SR-03 | Ambiguous fields or response framing bypass substitution/redaction | Malformed and duplicate fields, wrong selectors/encodings, secret echoes, error cookies, trailers, and chunk boundaries fail safely without partial secret disclosure. [Authentication](authentication.md), [observability](observability.md); W3/W6/W7 |
| SR-04 | Cookie, CSRF, or remote MCP state crosses accounts or survives invalidation | Two accounts and two sessions remain isolated; rotation, logout, expiry, revocation, and late responses cannot revive old state. [Authentication](authentication.md), [remote MCP](remote-mcp.md); W5/W6/W7 |
| SR-05 | Agent acquires host authority through a bypass path | Live outside-sandbox canaries remain reachable to positive controls but unreachable to the agent and descendants; test network, host files/processes, inherited descriptors, and alternate attachments. [Deployment](deployment.md); W4 and every added adapter |
| SR-06 | Missing/locked/changed store or inaccessible native item triggers fallback | No plaintext replacement, alternate-account selection, or Keychain-to-SQLite copy; verify encrypted recovery artifacts and the real backend's access behavior. [Secret stores](secret-stores.md), [operations](operations.md); W2/W8/W9 |
| SR-07 | Approval is forged, stale, duplicated, or bypassed using an existing cookie | Missing approver denies; deterministic races cover changed work, deadlines, cancellation, and policy changes before dispatch. Cookie-backed actions still enforce their policy. [Approval](approval.md); W1/W6, signed adapter separately |
| SR-08 | Concurrent requests or uncertain delivery produce duplicate work | Controlled upstream counters distinguish zero, one, and repeated dispatch; status/cancel and reconnect never resubmit. Race terminal transitions and invalidation across adapters. [Common protocol](protocol-common.md), [TCP binding](tcp-binding.md), [remote MCP](remote-mcp.md); W1/W4/W7 |
| SR-09 | Slow, disconnected, or malicious observer changes authority or hides loss | Bounded queues, authorized cursors, explicit gaps, and required-mode denial/termination work; acknowledgement cannot approve an action or prove IDS review. [Observability](observability.md); W3/W7 |
| SR-10 | Framing, pending work, or long-lived streams exhaust shared capacity | Finite byte/count/time limits hold across sessions and ingresses; status/cancel retains capacity; teardown terminates owned work without claiming remote rollback. [First-proof limits](proof-of-concept.md), [MCP](mcp.md), [TCP](tcp.md); W4/W7 |
| SR-11 | Unsafe catalog update, restore, or failed reload revives authority | Private-file checks reject unsafe paths/permissions; mixed revisions fail; pre-commit rejection preserves authority, while post-commit cleanup failure never reopens retired grants; recovery requires current-policy review. [Catalog](catalog.md), [lifecycle](lifecycle.md), [operations](operations.md); W2/W4/W8 |
| SR-12 | New adapter or embedding path avoids engine checks | Independent consumers pass the shared behavioral suite; client dependency closure excludes custody; no adapter opens an alternate upstream path, silently retries, or installs global trust. [Workspace](rust-workspace.md), [reuse](reuse.md); W0/W7/W8 |

Provider-hosted tools and remote MCP servers can act beyond the observed
connection. SR-02 and SR-12 must review those capabilities explicitly; observing
a tool invocation is not evidence that its further network activity is mediated.
For generic TCP, record connection-level authority and byte visibility only.
Do not describe arbitrary application messages as semantically inspected.

## Evidence record and closure rules

Maintain results in [the delivery tracker](../docs/proof-of-concept.md) or a
linked test report, not as checked boxes in this proposed design. For each
review case and supported deployment/profile, record:

- The exact scenario, expected denial or allowed result, and claimed boundary.
- Test path/name, repository revision, reproducible command, platform/backend,
  relevant feature selection, and synthetic fixture configuration.
- Both trusted-side evidence and agent-visible outcome where relevant: upstream
  receipt counts, private-state transitions, observation endings/gaps, and the
  absence of secret values from public outputs.
- Result: passed, failed, or unverified; list untested variants and platform
  constraints. A skipped case is unverified, not passed.
- For a regression guard, the expected failure on pre-fix code and the pass on
  the fix. A test passing on both versions does not establish that guard.

Use live positive controls for denial tests and deterministic synchronization
for race tests. A client error alone does not prove non-dispatch; a successful
response alone does not prove isolation. Timeouts must report the relevant
uncertainty rather than turn an unfinished probe into a successful denial test.
Synthetic canaries are test data, not permission to inspect personal credentials.

Close a claim only for its tested scope. For example, a Linux SQLCipher fixture
cannot close native Keychain access or macOS confinement; a direct engine test
cannot close session-socket isolation; a TCP test cannot close TLS inspection.
Adding an adapter requires rerunning shared cases through that path, not merely
reusing another adapter's result. Component reuse does not reuse deployment
evidence automatically.

## Review order and release decisions

1. Before credential-bearing dispatch, review SR-01 through SR-03 and SR-06 for
   the selected profile/backend. Keep fixtures synthetic until their custody
   and destination gates pass.
2. Before calling a deployment confined, close SR-05 for its exact launcher and
   every advertised agent-side adapter. Record any approved non-network host
   channels separately.
3. Before broadening authenticated session/transport support, review SR-04 and
   SR-07 through SR-10, including invalidation and failure races.
4. Before an operational release, complete SR-11/SR-12, recovery rehearsal,
   dependency review, and the applicable native-platform checks. Attach explicit
   residual risks and unsupported profiles to the handoff.

A failure of a mandatory gate blocks the corresponding claim. An optional
unsupported feature may remain disabled and documented; it must not become an
opaque fallback. Native tests unavailable on the development host may remain
unverified in a proof-of-concept report, but cannot establish native release
support. Product naming, human-approval UI/signing, and real-account enrollment
remain separate decisions and do not block this review plan.
