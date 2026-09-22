# Common protocol and authorization contract

## Identities and grants

The operator establishes `tenant_id`, `agent_id`, `session_id`, a finite session
lifetime, and permitted resource/account profiles. The ingress channel is bound
to this identity by the trusted host. Request fields naming an agent do not
authenticate it. Merely originating on loopback is insufficient on a shared host.

Each grant binds an identity to a resource profile, account, allowed actions,
destination constraints, budgets, expiry, and any approval requirement. A
credential reference is resolved only inside that grant. The agent cannot
enumerate other accounts or use a credential alias to override destination
policy. Effective authority is the intersection of operator policy, session
grant, resource policy, and any human approval.

The local session attachment is a capability to ask for authorized work. Calling
the agent "secretless" means it lacks upstream authentication material; it does
not mean its session has no authority or cannot be abused by code in the sandbox.

## Agent-facing operation semantics

These are normative logical operations. Their binding to a particular HTTP
management API is deferred. The password-manager subset has concrete proposed
MCP tool names and JSON schemas in [its contract](password-manager.md).
Normal HTTP clients may use equivalent behavior through the admitted proxy
connection.

| Operation | Inputs | Result |
| --- | --- | --- |
| `request.execute` | `request_id`, `resource`, optional `auth_context`, method, target, headers, body | Safe response/stream, pending handle, or error |
| `request.status` | `request_id` | State and retained safe result metadata; never resubmits |
| `request.cancel` | `request_id` | Cancellation state; remote execution may already have occurred |
| `auth.prepare` | `request_id`, permitted `item_id`, site URI | Fake credentials, context handle, expiry, and profile-selected submission scope |
| `auth.status` | `auth_context` | Unauthenticated, authenticating, authenticated, expired, or revoked |
| `auth.logout` | `auth_context` | Local authority invalidated; remote logout outcome separately reported |

Methods are case-sensitive HTTP method tokens. Targets are absolute HTTPS URIs
for authenticated HTTP operations. Bodies are exact octets; a tool binding must
distinguish textual data from encoded binary data without implicit conversion.
The caller supplies application headers, not authentication or routing authority.
Profiles declare allowed headers, formats, lengths, and action constraints.

`request_id` is an unpadded base64url encoding of 16 random bytes (22 characters),
unique within a local session. The proxy remembers its frozen operation and
state until session teardown. Duplicate submission of that ID with the same
operation returns existing state, never a second dispatch; a different operation
returns `request_conflict`. When the session's tracking budget is exhausted,
reject new operations rather than evict live uniqueness state. Status queries
may report `result_unavailable` after content retention ends while retaining
the fact that the operation was dispatched.

This local deduplication is not resource-side idempotency. An agent can submit
the same business action under a new ID; policy and application controls must
decide whether that is allowed. Ordinary forwarded HTTP requests without an
explicit local ID receive proxy-generated IDs and cannot infer retry safety.

`auth_context` is an unpadded base64url encoding of 32 random bytes, bound to the
session, resource profile, account, and lifetime. Possession alone is not
authentication. Another sandbox cannot redeem it. Explicit proxy clients may
select it with the local-only `Proxy-Auth-Context` header; the daemon consumes
and removes that header. Transparent clients use a fixed account/profile per
session and route; ambiguous selection is rejected. No context handle is placed
in an upstream URL or an upstream authentication cookie.

## Operation state machine

```text
received -> validated -> [pending_approval] -> ready -> dispatching
                                                    -> completed
                                                    -> failed
                                                    -> outcome_unknown

Before dispatch: denied | expired | cancelled
After dispatch: cancellation records uncertainty; it does not undo execution
```

Validation freezes the exact action, selected account, relevant headers, body,
and policy version. Mutation requires a new operation. Credential preparation
happens for this frozen operation. No protected
application bytes are sent while approval is pending.

`outcome_unknown` means bytes may have reached the resource but the daemon
cannot determine whether the action ran. Do not automatically repeat a
potentially state-changing operation. A retry needs a documented resource
idempotency contract or an explicit new authorized operation. Local request IDs
alone do not provide exactly-once execution at the resource.

## Human interaction extension

Approval is an asynchronous engine-level interface, separate from `SecretStore`
unlock/user-presence interaction. Global/session, item, and action requirements
compose restrictively: any applicable requirement needs approval, and approval
cannot override denial. Distinguish permission to authenticate from permission
for an exact subsequent operation; cached cookies/tokens do not bypass the latter.
Freeze the operation before requesting approval and do not resolve its password
until the required approval succeeds. An unconfigured approval provider fails
closed. A future signed-response adapter must verify the trusted approver and
bind the decision to the operation, session, daemon epoch, expiry, and single-use
approval identifier. Signing format and UI remain a separate integration task.
The [approval contract](approval.md) specifies provider ownership, per-item
policy, pending-operation limits, and race/decision semantics. Item settings
are stored in the private [catalog](catalog.md), not in native password items.

Reserve `pending_approval` now. Return only `request_id`, `approval_id`,
`expires_at`, and a safe reason to the agent. The approval handle is a random
32-byte base64url value bound to the same session and immutable operation.
Polling it cannot approve it.

A future independent human channel displays the verified resource, account,
action, relevant arguments, limits, and expiry, using proxy-held data. An
approval binds that complete operation and approving identity, is usable once,
and expires. A generic "approve this agent" signal cannot silently authorize
an altered transfer, tool call, or login. Approval and 2FA are distinct: extra
authentication of the person does not itself express consent to an action.

After approval, recheck grants, store access, credential version, placeholder
expiry, and cookie/CSRF state. If preparation has expired, reject the pending
operation and require fresh preparation; never transfer approval to changed
work. Denial, expiry, cancellation, and session revocation invalidate the
pending operation.
If no approved human channel exists, return `interaction_unavailable`; never
let the agent supply its own approval or upstream OTP.

## Errors and retry contract

Local errors carry `code`, `request_id` when available, and a safe explanation.
No upstream credential, raw authentication response, or sensitive diagnostic
is included. The eventual transport binding must keep local errors distinct
from resource HTTP statuses and MCP application errors.

| Code | Meaning / caller action |
| --- | --- |
| `session_invalid` | Missing, expired, or revoked session; no forwarding |
| `policy_denied` | Destination/action/account not permitted; no retry escalation |
| `request_invalid` | Malformed or unsupported request; correct the request |
| `request_conflict` | Local ID reused for different work |
| `limit_exceeded` | Size, time, concurrency, or tracking budget exhausted |
| `inspection_unavailable` | Requested coverage cannot be provided |
| `auth_profile_unsupported` | Resource/flow has no approved compatible profile |
| `auth_failed` | Authentication failed; no automatic guessing or downgrade |
| `vault_locked` | Required backing store is locked; trusted unlock needed |
| `vault_unavailable` | Required store/credential version cannot be obtained safely |
| `placeholder_invalid` | Placeholder expired, revoked, or outside its permitted binding |
| `auth_in_progress` | Another login exchange is active for this context; inspect status |
| `interaction_unavailable` | Required trusted interaction cannot be completed |
| `observation_unavailable` | Required observation admission failed |
| `upstream_unavailable` | Connection failed with known non-dispatch, where provable |
| `outcome_unknown` | Dispatch may have occurred; inspect state, do not blindly repeat |
| `result_unavailable` | Dispatch state remains known but result content was not retained |

The authentication profile is operator-pinned per route. A 401 response or
attacker-controlled discovery metadata MUST NOT select a different account,
credential, authentication mechanism, or destination. Failed authentication
never authorizes broader access or fallback to caller-supplied secrets.
