# macOS Keychain delivery plan

Status: proposed W9 work breakdown, not implemented macOS support. This extends
the [store contract](secret-stores.md) and [operator lifecycle](operations.md).
Keep current project/crate names; naming is not a prerequisite for this work.

## First supported deployment

Propose a freestanding process running in the logged-in user's context for the
first macOS delivery. It remains outside the agent sandbox and requires no
embedded agent, Swift application, or production approval UI. Installation as a
system-wide service is a separate deployment profile, not an implicit property
of the word daemon. Do not install a service while developing the adapter.

macOS has file-based and data-protection Keychain implementations. Apple notes
that processes outside a user context must use the file-based implementation;
access from an embedded library to the data-protection implementation depends
on the host executable's entitlements. Therefore, test the selected process
context and signed executable, not just a library test binary.
[Apple TN3137](https://developer.apple.com/documentation/technotes/tn3137-on-mac-keychains)

Record the selected Keychain implementation, item classes, synchronization mode,
minimum macOS version, and host signing/access requirements as one supported
profile. Select the target explicitly; neither search-list order nor a library
default may change which store supplies a credential. Existing file-based items
and newly managed data-protection items need separate native evidence if both
are supported. Do not infer one implementation's behavior from the other.

The initial enrollment scope is accessible, non-synchronized Internet-password
and generic-password items. New managed credentials are non-synchronized by
default. Synchronized-item reuse needs a separate identity design: Apple warns
against persistent references for those items. This limits initial reuse; it
does not authorize copying credentials out of an inaccessible store.
[Apple synchronization restrictions](https://developer.apple.com/documentation/security/ksecattrsynchronizable)

## Crate and dependency boundary

Add `aap-store-keychain` when delivering its real adapter, with the existing
`aap-secrets` read/use interface and optional trusted management capabilities.
Keep Apple dependencies target-specific. The portable engine, credential-free
client, and non-macOS default daemon must not acquire a Keychain dependency.
An embedding host can select this adapter without also selecting SQLCipher.

Use `security-framework` directly. Its password and scoped search facilities
provide the starting point; pin and build the chosen version at implementation
time rather than treating the documentation's current version as a manifest
decision. No additional secret-wrapper or cross-language binding package is
needed. Existing JSON/base64 support may encode private reference metadata.
[Password APIs](https://docs.rs/security-framework/latest/security_framework/passwords/index.html),
[scoped searches](https://docs.rs/security-framework/latest/security_framework/item/struct.ItemSearchOptions.html)

Before promising support, inventory the required native capabilities: explicit
target selection, metadata-only discovery, durable item identity, coherent
attribute/value reads, non-interactive access, and observable mutation failures.
A convenient get/set helper alone is not the complete store contract. Prefer
safe wrappers; any missing operation requiring `security-framework-sys` needs
a narrow adapter-local review against the workspace's unsafe-code policy.
Do not relax workspace-wide lints or expose native pointers in public contracts.

## Enrollment and item identity

Trusted enrollment follows the existing review/publication workflow:

1. Search only the operator-selected Keychain, item class, site/service, and
   account. Bound returned candidates; do not retrieve passwords merely to
   display choices. Search is an operator capability, never an agent MCP tool.
2. Require an explicit choice if several candidates match. A native hostname,
   service label, or account is matching metadata, not an authorization grant.
3. Obtain a supported persistent identity for the selected item, with explicit
   backend/implementation scope. Do not serialize an in-process object address
   or use a service/account query as if it uniquely identified the original item.
4. Verify access through an explicitly trusted enrollment step when necessary;
   recheck identity before publishing the reviewed catalog binding. Do not send
   a login to the real site as an enrollment check.
5. Publish only the opaque reference, safe aliases, profile, and item policy in
   the private catalog. Native access restrictions and proxy grants both apply.

Apple distinguishes persistent references, which can be stored, from ordinary
object references. Use that capability only for tested item/implementation
combinations. Treat the encoded result as private metadata, not a bearer grant
and not an agent-visible item ID.
[Apple persistent references](https://developer.apple.com/documentation/security/ksecreturnpersistentref)

The adapter defines a versioned, bounded reference encoding inside the existing
opaque `credential.key` field; no catalog schema expansion is required solely
to expose native attributes. References must reject malformed or unsupported
encodings. Deletion, a stale reference, a changed Keychain target, or inability
to prove identity requires explicit re-enrollment. Never select a replacement
because it has the same service/account, including after restore or restart.

Existing items remain unmodified and read/use-only by default. Unenrollment
removes proxy access and contexts, not the user's password. Policies remain in
the owner-only JSON catalog, never in proprietary payloads added to existing
Keychain items. Newly created item namespaces must be stable independently of
display branding; a future rename must not silently create replacement items.

## Credential shape, freshness, and writes

The first native shapes are an Internet-password item's coherent username and
password, and a generic-password item's API-key value under an enrolled field
mapping. Keep account attributes private just like other store metadata.
Preserve credential bytes; reject incompatible field shapes or encodings rather
than truncating, guessing, or assembling a bundle from independently read items.
Additional token/key bundles need an explicit supported mapping and tests.

Before implementing lease handling, specify how each supported shape establishes
its first opaque version and detects a changed value on subsequent use. Native
item identity is not a credential version. An adapter counter alone cannot
detect external edits, and a timestamp is not a proven collision-free revision.
Test password-only edits and multiple rapid edits, not just changed labels.

Metadata must not silently resolve a password to manufacture a revision before
operation approval. If the backend cannot bind an initial version without a
value read, explicitly resolve that contract gap before claiming compatibility.
Fresh coherent readback and bounded private comparison state may support later
revalidation, but cannot waive the approval boundary. Publish only opaque
versions; no secret-derived fingerprint belongs in the catalog or telemetry.

Document the exact point of each access/version check and the detection limit
for external changes. A successful read is not an atomic transaction with a
future upstream dispatch or another application's edits. On detected changes,
return the common changed/unavailable outcome and invalidate dependent contexts;
do not silently substitute the new credential into previously approved work.
No durable secret cache or SQLite mirror is permitted.

Native administration must preserve the common interface's create-only and
expected-version semantics. In particular, a read followed by an unconditional
native update is not automatically compare-and-swap against external writers.
Implement only mutations whose guarantees can be justified; return unsupported
for the others, without weakening the interface. Trusted create-only provisioning
is required for new managed items. Existing-item mutation remains separate,
explicit authority and is not required to enroll and use an existing password.

Creation and catalog publication remain separate transactions. A failed or
uncertain enrollment reports an unenrolled item for reconciliation; it neither
retries creation automatically nor deletes an item selected from the user's
existing Keychain. See [partial enrollment failures](operations.md#bootstrap-and-enrollment).

## Native permission and human approval

Keep the two decisions independent:

| Decision | Owner | Scope |
| --- | --- | --- |
| May this operation use the enrolled account? | Engine policy and configured `ApprovalProvider` | One immutable operation under current grants, including cookie-authenticated work |
| May this process access the native credential now? | Keychain and the trusted host's interaction policy | Native item access; no permission to change proxy policy or dispatch unrelated work |

Normal agent-triggered access uses a tested non-interactive path. It must not
produce unsolicited permission dialogs, choose a different item, or downgrade
access controls. If interaction is required, return the typed store outcome;
without a configured trusted interaction path, the operation fails closed.
Do not disguise inaccessible items as a successful empty store.

Enrollment/unlock interaction is operator-initiated. The initial adapter need
not resume a failed agent request after a prompt; the agent can submit fresh
work under current policy. A later async interaction adapter must preserve
operation identity and deadlines, then recheck grants, item identity, credential
version, and session/context generations. Native consent is never itself the
signed per-operation approval envisaged in [the approval contract](approval.md).

Do not toggle process-global interaction settings around concurrent requests in
a reusable library. Prefer a verified per-call mechanism; if the selected native
API cannot meet that isolation requirement, document the limitation and keep
that embedding profile unsupported until a separately reviewed solution exists.

Closing one broker must not lock the user's entire login Keychain or disrupt
another broker sharing the adapter. Adapter-local access closure, native
Keychain lock state, and broker revocation are distinct. Unsupported native
lock/unlock operations must be reported as such; closing a handle is not proof
that all native secret copies have disappeared.

## Bounded native work and cancellation

Use the host's bounded blocking execution, with no process-global runtime.
Start with at most eight queued/running native jobs per adapter instance and
no unbounded secondary queue. Keep permits until native work actually returns,
even when the async caller times out or drops its future. These are proposed
limits to verify, not native cancellation guarantees.

Construct and use non-transferable native query objects within their owning
execution context; do not assert thread safety merely to satisfy an async trait.
The documented Rust search builder is neither `Send` nor `Sync`.
[Search builder contract](https://docs.rs/security-framework/latest/security_framework/item/struct.ItemSearchOptions.html)

Admission, store generation, and session checks apply before accepting any late
result. Cancellation cannot turn a completed native read into credential
injection, restore a revoked cookie context, or authorize a second dispatch.
Blocked native work must not hold the broker's admission lock or prevent status,
cancellation, and unrelated sessions from progressing. Follow the shared
[closure and drain contract](lifecycle.md); a caller timeout is not native drain.

## Ordered delivery and acceptance

| Step | Deliverable | Required evidence |
| --- | --- | --- |
| K1 | Native feasibility profile and dependency choice | Actual supported host/item matrix; persistent identity, non-interactive access, coherent reads, revision strategy, and wrapper gaps recorded |
| K2 | Backend-neutral conformance scenarios | Same read/use expectations exercise SQLite, a controlled fixture, and the future native adapter; management capabilities tested separately |
| K3 | Native adapter and trusted enrollment | New synthetic managed items and existing synthetic Internet/generic items work in place; stale identity, ambiguity, denial, and malformed references fail safely |
| K4 | Bounded lifecycle and invalidation | External edits/deletion, native lock/access changes, cancelled queued/running work, saturation, restart, and late completion have safe outcomes |
| K5 | Daemon and embedded composition | Both use Keychain-held credentials for provider and form/cookie fixtures; agent, catalog, observations, and errors contain no real values |
| K6 | macOS release evidence | Selected signed host passes native permission tests, private-file ACL checks, dependency isolation, and its separate sandbox/egress acceptance profile |

Native fixtures must use isolated test keychains where the selected implementation
supports them. Other profiles require a dedicated disposable test user/host and
exactly tracked synthetic items. Never use a developer's personal items, change
their default Keychain/search list, or clean up with broad service/account
deletion. A skipped or unavailable native test is an unverified gate, not a pass.

Include these negative controls alongside successful native use:

- A matching but unenrolled item cannot be discovered or used by an agent;
  ambiguous native candidates cannot be resolved by first-result order.
- Deleting an enrolled item and creating a same-named replacement does not
  revive the old binding. Unenrollment leaves the original item readable by
  the trusted native fixture.
- A second process changes only the password while approval/native work is
  pending; old leases and approvals cannot silently migrate to the new value.
- Denied access or required interaction produces zero protected origin receipts
  and no fallback file; an independent positive control proves the origin works.
- Item `always` policy still requests approval when a private cookie exists and
  no password lookup is necessary. A native permission grant cannot bypass it.
- Drop a caller while a native job is held at a test barrier, exhaust capacity,
  and prove that cancellation does not release permits prematurely. Release
  the job and prove safe cleanup without secret delivery or context revival.
- Build the credential-free client and non-macOS daemon without Apple links,
  and the Keychain-selected host without an unintended SQLCipher dependency.

K1-K5 establish the adapter's declared capabilities, not universal Keychain
access or macOS confinement. K6 remains required for a macOS release. Keep
native evidence separate from portable mock tests and from the initial Linux
proof of concept; no implementation milestone is completed by this document.
