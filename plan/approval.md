# Asynchronous approval boundary

Approval is an engine extension, not a new upstream authentication protocol.
Sites continue to receive their ordinary passwords, cookies, or API keys.
This contract reserves human-in-the-loop integration without choosing a UI,
push service, signature format, or new cryptographic dependency now.

## Responsibility and policy

The engine decides whether an operation is permitted and needs approval. An
injected `ApprovalProvider` on the trusted host communicates that frozen
operation to an independent approver and returns a decision asynchronously.
`SecretStore` remains responsible for custody, native access control, and
unlock/user-presence requirements. A specialized store can add those checks,
but cannot replace operation-level approval: a protected request may use a
private cookie without retrieving a password at all.

| Item setting | Password login / fresh token acquisition / API-key injection | Existing private session used for a protected operation |
| --- | --- | --- |
| `inherit` | Only requirements added by global, session, or action policy | Only requirements added by global, session, or action policy |
| `authenticate` | Approval required for the exact authentication operation | No additional item requirement; other policies still apply |
| `always` | Approval required | Approval required for each protected operation |

These settings add requirements; none can override denial or a stricter layer.
There is no remembered "allow this agent forever" grant implicit in a positive
response. A future separately scoped approval lease would need its own design.
Explicit token refresh is an authentication operation, not an approval bypass.

Catalog search and issuance of wholly fake credentials do not themselves
release a real password or authenticate to a site. They can use non-secret
metadata after ordinary grant checks; item `authenticate` approval is requested
for the later exact login submission, including its final destination and body.
If preparation would disclose a real username or otherwise resolve secret
values, evaluate the relevant policy before doing so. Native unlock or
interaction requirements still apply to metadata access where the backend
requires them; an agent request cannot silently consent to a prompt.

## Interfaces and asynchronous behavior

`ApprovalProvider` belongs to the trusted engine API, alongside privileged
broker construction. Its conceptual operations are submit, await decision, and
cancel. Use the same object-safe asynchronous approach as the store interface;
no UI SDK or provider-specific signing types become core dependencies.

The initial implementation must provide the interface and a deterministic test
provider. Without a configured trusted provider, requests requiring approval
return `interaction_unavailable`; they do not fall back to no approval. A
production human UI and signed-response transport remain follow-up work.

All potentially blocking operations are asynchronous. Pending work retains a
bounded immutable request, deadline, and authority binding, not a held global
lock, open login transaction, or credential-bearing outbound request. It holds
no newly resolved password while waiting. Quotas cover pending count, retained
bytes, total wait time, and provider queue capacity across every ingress.

The agent receives a pending status and may poll or cancel through its existing
session interface. Trusted hosts may also subscribe to bounded lifecycle
notifications; polling remains authoritative after missed notifications. An
event being delivered or acknowledged is not approval. Closing an HTTP/MCP
connection must not accidentally dispatch, approve, or resubmit the operation;
its retention/cancellation rule is explicit and shared by both frontends.

## Decision binding

Freeze these facts before submitting an approval request:

- Daemon epoch, session identity, request ID, random single-use approval ID,
  expiry, and current configuration/grant generation.
- Exact account/item and resource profile, HTTPS origin, method, target,
  relevant headers and arguments, body, and limits.
- Authentication context and state generation where applicable, plus the
  credential version when it can be obtained without resolving values.
- The reason approval is required and the identity/authority of the permitted
  approver or configured approval provider.

The trusted interface renders resource/account/action information from these
facts. Agent text may be displayed only as untrusted content; it cannot replace
the verified destination or hide relevant arguments. Neither prompts nor
observations include real passwords, cookies, or native store references.

A future signed-response adapter verifies signer authorization, signature,
expiry, epoch, and the complete immutable binding before delivering a decision
to the engine. Transport authentication or possession of an approval ID alone
does not express consent. Signature encoding, canonicalization, trust-anchor
provisioning, and key rotation must be specified and tested before enabling
that adapter; they are not inferred from this conceptual interface.

## State transitions and races

Approval supplements the common operation state machine:

```text
validated -> pending_approval -> approved -> revalidation -> ready -> dispatch
                    |                |
                    +-- denied       +-- changed/expired/cancelled -> terminal
                    +-- expired
                    +-- cancelled
```

`approved` above is an internal decision, not a promise of eventual dispatch.
Before resolving credentials and again before dispatch, verify current policy,
session/context lifetime, native store access, credential version, and the
required observation channel. A changed approved binding is invalid; request
new preparation/approval instead of silently approving revised work. In the
baseline, a changed configuration generation invalidates pending approvals.

Only one decision can win atomically. Duplicate approvals, late responses,
out-of-order notifications, cancellation, and restart cannot create a second
dispatch. Mark the approval consumed when committing the operation to dispatch,
and retain its terminal status with the operation's deduplication state. Approval
consumption does not provide resource-side exactly-once execution. A lost
upstream response still produces `outcome_unknown` with no automatic retry.

Native unlock and human consent are distinct prerequisites. A store prompt
must not count as approval for an arbitrary action, and an approved action must
not bypass a denied Keychain access check. If native interaction changes the
credential or context, revalidate rather than transfer the prior consent.

## Acceptance checks

- With an approval-required policy and no provider, no secret resolution or
  protected dispatch occurs, even with an already authenticated cookie jar.
- A pending fake-provider request exposes status without blocking unrelated
  sessions; a matching approval permits exactly one dispatch.
- Denial, timeout, cancellation, provider failure, and queue overflow are
  terminal without releasing a password or widening policy.
- Item `inherit` cannot relax global/session/action requirements; cached
  cookies cannot bypass item `always` or route-specific approval.
- Changed request bytes, account, destination, credential/context generation,
  or policy invalidate the decision. Approval for login does not implicitly
  approve a later transfer or tool call.
- Cross-session, expired, duplicate, old-epoch, and late decisions cannot
  approve new work. Signed-adapter tests are a separate future release gate.
