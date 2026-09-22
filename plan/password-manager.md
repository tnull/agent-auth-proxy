# Password manager and secret-store contract

## Role and custody

The daemon acts as a password manager for the agent, backed by a trusted secret
store. An agent can ask for a site's login item through MCP and receive values
it can put into the login form. Those values are proxy-issued placeholders;
the secret store and real credentials remain outside the sandbox.

The backing store owns persistent secrets and their versions. Its credentials,
unlock material, and administrative interface MUST NOT be accessible to the
agent. The daemon accesses only items permitted by the deployment's store
identity and the requesting session's grants. A backend-neutral `SecretStore`
interface separates custody from authentication behavior. The macOS daemon
stores credentials directly in Keychain; other platforms default to encrypted
SQLite. The macOS adapter uses direct Rust `security-framework` bindings. See
[secret stores](secret-stores.md) for the interface and backend requirements.

Trusted macOS setup may enroll an existing accessible Keychain item without
copying its password. Such enrollment is read/use-only by default and requires
both native access permission and a proxy resource/grant binding. The MCP tools
below search only the authorized enrolled catalog, not the user's entire
Keychain. Unenrolling an existing item does not delete it from Keychain.

Passwords, API keys, and access/refresh tokens are managed through this boundary.
The store supplies secret material only to the trusted daemon. Interception-CA
keys and administrative credentials live in a separate namespace that is never
exposed through agent MCP item discovery.

## Item model

An enrolled login item has the following logical fields. Their storage format
is not specified.

| Field | Meaning / visibility |
| --- | --- |
| `item_id` | Opaque agent-visible alias; not the backing store's native record ID |
| `label` | Operator-approved display name; visible only to authorized sessions |
| `resource_profile` | Reference to approved origins, routes, login format, and response handling |
| `account_alias` | Safe account selector, optionally distinct from the real username |
| `username_ref`, `password_ref` | Private references to versioned fields in the secret store |
| `username_visibility` | Whether the actual username may be shown or must also be virtualized |
| `credential_version` | Private immutable version binding used for issuance and rotation |
| `grants` | Identities and operations allowed to request/use this item |

The resource profile declares exact HTTPS origins, login target/method, permitted
redirect transitions, form encoding, credential field selectors, CSRF behavior,
session-cookie treatment, and success/failure criteria. Stored website URLs are
matching hints, not unconditional permission to release a credential there.
Profile enrollment must establish the authorized recipient explicitly.

Site matching compares parsed normalized origins and profile route rules.
Never match by substring, display name, suffix without a label boundary, or a
model's assertion that two sites are equivalent. A password for
`https://example.com` is not available to `https://example.com.attacker.test`,
another port, or an unapproved identity-provider redirect.

## Proposed MCP tools

These names and JSON contracts are the proposed initial MCP surface. The tools
inherit the trusted local session binding; they do not accept a caller-selected
tenant, agent ID, store URL, native secret ID, or permission override. Unknown
input members are rejected. Tool schemas and outputs carry no hidden authority.
Examples below show application payloads carried in MCP tool results; normal
MCP transport envelopes remain governed by the negotiated MCP version. Errors
use the common `code`, optional `request_id`, and safe explanation contract.

### `vault.search_items`

Input:

```json
{"uri":"https://accounts.example/login","query":"work","cursor":null}
```

`uri` is required. `query` and `cursor` are optional strings; omitted or null
means no filter/first page. Search only items authorized for this session and
matching the site/profile. Return at most 50 records per page:

```json
{
  "items":[{
    "item_id":"item-work",
    "label":"Work account",
    "account_alias":"work",
    "origins":["https://accounts.example"],
    "login_supported":true
  }],
  "next_cursor":null
}
```

An opaque pagination cursor is session- and query-bound, expires with the
session, and cannot expand the result set. Unknown and unauthorized items are
indistinguishable. Labels and account aliases are treated as potentially private
metadata in observations. Searching must not unlock an inaccessible vault or
probe the existence of other tenants' items.

### `vault.get_login`

Input:

```json
{
  "request_id":"BASE64URL_16_BYTES",
  "item_id":"item-work",
  "uri":"https://accounts.example/login"
}
```

All three fields are required. The item must match the URI and an active grant.
The profile, not the agent, selects the credential fields and real submission
destination. If the URI identifies a page whose form posts elsewhere, return
only the separately enrolled action. A discovery URI cannot redefine it.

Result, with illustrative placeholders:

```json
{
  "item_id":"item-work",
  "auth_context":"BASE64URL_32_BYTES",
  "credentials":{
    "username":{"value":"aap_un1_BASE64URL_32_BYTES","kind":"placeholder"},
    "password":{"value":"aap_pw1_BASE64URL_32_BYTES","kind":"placeholder"}
  },
  "submission":{
    "uri":"https://accounts.example/session",
    "method":"POST",
    "content_type":"application/x-www-form-urlencoded",
    "fields":{"username":"username","password":"password"}
  },
  "expires_in":600,
  "reusable":true
}
```

The password is always a placeholder. The username may have `kind:"value"`
only if the item expressly allows the real username to be disclosed. Otherwise
it is an independently random `aap_un1_` placeholder, resolved in the same
login operation as the fake password. This supports login forms that require the
agent to type both fields without exposing a private username.

The tool performs the logical `auth.prepare` operation from the common
protocol and creates a permitted credential binding. It never returns a real
password, token, cookie, OTP, recovery code, or raw secret-store response.
Duplicate `request_id` with the same input returns the same still-valid issuance
or its terminal state; it cannot mint another binding. Changed input conflicts.
Expired or revoked issuance requires a new explicitly authorized request ID.
The subsequent login submission is a separate operation with its own request
ID, or a proxy-generated ID for ordinary forwarded HTTP.

Issuance verifies store availability and pins the credential version. A change
of version before use invalidates the issuance. `expires_in` is the remaining
positive integer lifetime in seconds, selected by operator policy and capped
by context/session/grant expiry; 600 above is illustrative. The proxy's clock
determines expiry. `reusable:true` permits multiple independently authorized
submissions within that binding, never use in another context or direct use at
the site. Retrieving or using the placeholder does not extend its lifetime.

### `vault.auth_status` and `vault.logout`

Input for either tool is `{"auth_context":"BASE64URL_32_BYTES"}`. Status returns
the item alias, safe account alias, and a state from the common contract, never
cookie contents. Logout immediately invalidates the context, placeholders, and
jar; report remote logout as `confirmed`, `failed`, `unknown`, or
`not_supported`, independently of local revocation.

The status result has exactly `item_id`, `account_alias`, and `state` string
fields. The logout result has exactly `state:"revoked"` and `remote_logout`
with one of the four values above. Repeated logout of the same known context
is idempotent; unknown or other-session contexts return `policy_denied` without
revealing existence. Status of a locally retained revoked context reports
`revoked` until its owning session ends.

The agent may subsequently obtain a fresh login only if its grant still allows
it. Operator revocation is the mechanism for removing that authority.

## Availability, rotation, and interaction

No usable secret store means no new credential release or login: return
`vault_locked` or `vault_unavailable`. Do not silently use a stale password
version, fall back to an agent-supplied password, or expose store diagnostics.
If the store requires human unlock, use the independent approval channel;
the agent sees only the pending state. Before that channel exists, deny the
operation with `interaction_unavailable`.

Default to no offline reuse after store lock or loss of a required lease.
Invalidate outstanding placeholders and associated authenticated contexts when
the daemon learns that an item is locked, revoked, or rotated. Recheck the
pinned version and store access immediately before credential dispatch. Remote
cookies may remain valid at the site after a password change; local invalidation
must not claim remote revocation.

Store secret material may exist transiently inside the trusted daemon.
Never include it in debug formatting, crash reports, child
environments, observation payloads, or agent error messages. Retention and
memory-hardening details belong to the later implementation/security design.

The initial agent tool surface is read/use-only. Creating items, revealing real
passwords, changing passwords, configuring destinations, and retrieving OTP
seeds are control-plane operations. Supporting agent-assisted account creation
or password rotation later requires a separate, explicit authorization design.

## Acceptance scenarios

- An agent searches a permitted site, selects an item, obtains fake credentials,
  fills a form, and receives an authenticated response without real secrets.
- An unauthorized item, a lookalike domain, a different account/session, or a
  malicious form action cannot cause a secret-store read/release outside scope.
- Multiple matching accounts require explicit item selection; the daemon never
  chooses a more privileged account based on model-supplied text.
- Username virtualization, repeated tool calls, expiry, concurrent submission,
  item rotation, store lock, and store outage preserve context isolation and
  invalidate bindings when required. Permitted reuse does not bypass login limits.
- Vault discovery, errors, observations, and MCP tool results contain only
  authorized metadata and placeholders, not native store identifiers or secrets.
