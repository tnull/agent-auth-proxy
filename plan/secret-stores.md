# Pluggable secret stores

Use a small Rust interface for credential custody. macOS stores credentials
directly in Keychain; encrypted SQLite is the default on other platforms.
Trusted Rust hosts may provide their own implementation. Reuse existing Keychain
items where authorized access is possible.
The engine, MCP tools, and authentication logic must not depend on which backend
is selected.

## Interface and packages

| Package | Responsibility |
| --- | --- |
| `aap-secrets` | Backend-neutral store interface, item/version types, safe errors, privately held secret bytes |
| `aap-store-sqlite` | Non-macOS default encrypted SQLite store, transactions, schema migration, keying and lock lifecycle |
| `aap-store-keychain` | macOS default: native credential storage and authorized reuse of existing items |

Backends are injected as a store implementation at trusted startup; this does
not require a dynamic plugin loader, an RPC service per backend, or a registry
framework. Keep backend SDKs/native links in their adapter crates. `aap-client`
must not depend on any of them. Daemon builds select the platform's default
backend: Keychain on macOS, SQLite elsewhere. Neither backend is mandatory for
an embedding host that supplies its own store.

The `SecretStore` interface is asynchronous and object-safe. Use standard-library
futures/boxed futures where dynamic dispatch is needed; do not add a macro or
utility crate solely to express this interface. Native blocking calls run on
bounded blocking work provided by the host/runtime. Do not block an async worker
or require a process-global runtime.

The logical read contract consists of:

| Operation | Result and requirements |
| --- | --- |
| Inspect availability | Ready, locked, unavailable, or trusted interaction required |
| Read item metadata | Backend-private item reference, safe metadata, field kinds, opaque version; no secret field values |
| Resolve item | One coherent credential snapshot with version and validity; optional expected-version check |
| Revalidate | Confirm access/version is still current, or return a typed failure |
| Invalidation reporting | Optional backend notification; absence requires revalidation on use and bounded caching |

The proxy owns its authorized item catalog and site matching; a backend need not
enumerate the user's entire vault or Keychain. A separate trusted enrollment
interface may support bounded discovery of accessible existing items; that
capability is not exposed as unrestricted agent MCP discovery. Resolve enrolled
references after grant checks. Backend access rights complement, but do not
replace, proxy policy. Real values are returned only to trusted authentication code.

Use a small error enum: locked, unavailable, not found, access denied, changed
version, interaction required, invalid data, and unsupported operation. Convert
it to the public error contract without revealing native identifiers or store
diagnostics. A backend cannot return a usable value after reporting access denied.

Keep provisioning separate from read/use. An optional trusted management
interface supports item creation/update/deletion and explicit lock/unlock where
the backend permits them. Agent MCP tools never receive this interface. Stores
managed by another application may implement only read/use; unsupported writes
must not lead to a shadow plaintext store or an unannounced backend switch.

Version changes invalidate placeholders and authenticated contexts as specified
in [the password-manager contract](password-manager.md). Keychain or other
backends without suitable native versioning must compare fresh coherent snapshots
inside the trusted adapter and maintain opaque local generations. Do not claim
instantaneous change notification when a backend only supports polling/readback.
Restart invalidates the proxy contexts, so local generations cannot revive an old
binding. Secret fingerprints never appear in public metadata or logs.

## Private catalog and policy metadata

Store proxy grants, per-item approval requirements, resource profiles, and
credential references in a versioned JSON catalog/configuration, separate from
credential values. Existing Keychain items need no proprietary policy payload.
Metadata is private even without passwords: it reveals enrolled sites/accounts.

The catalog is `catalog.json` under `$XDG_CONFIG_HOME/agent-auth-proxy`
(default `~/.config/agent-auth-proxy`) on Linux, and under
`~/Library/Application Support/AgentAuthProxy` on macOS. Entries contain an opaque
item alias, approved label/account alias, backend reference, profile reference,
and item policy. Reject unknown schema versions and unknown/duplicate fields.
This file is plaintext with filesystem protection, not an encrypted vault.
The [catalog contract](catalog.md) specifies its version-1 fields, approval
values, shared configuration revision, and update/recovery behavior.

On Unix, catalog/configuration directories MUST be user-owned with mode `0700`;
files MUST be user-owned regular files with mode `0600`. Create temporary files
and backups with those permissions from the start, and use atomic replacement
after complete validation. Validate ownership/type/mode on the opened descriptor;
reject symlinks, unexpected hard links, unsafe parent traversal, and excessive
input size. Refuse unsafe configuration rather than silently changing permissions.
Extended ACLs must not grant additional readers. Protect reloads identically.

Do not expose catalog metadata through ordinary logs, agent mounts, or error
messages. Owner-only permissions do not exclude root or other same-UID processes:
the sandbox MUST hide the catalog, store, backups, and operator sockets even if
its user matches the daemon's. Native platform support must verify actual ACL
behavior as well as Unix mode bits.

## Minimal handling of secret values

Use a small private-field Rust type over owned bytes with intentional access
methods. Do not derive `Debug`, `Display`, serialization, or unrestricted cloning
for secret-bearing values. Keep ownership narrow and avoid unnecessary copies.
Use the standard library for this wrapper; no dedicated secret-wrapper dependency
is planned. This is about accidental exposure through APIs and diagnostics,
not a guarantee that every memory copy can be erased.

Use established libraries for database encryption, TLS, protocol parsing, and
secure random generation. Minimal dependencies do not justify custom encryption,
random generators, certificate validation, or other security protocols.

## Non-macOS default: encrypted SQLite

Use SQLCipher-backed SQLite through `rusqlite`, isolated in `aap-store-sqlite`.
SQLCipher supplies database encryption; the adapter supplies item management and
the common store contract. Ordinary SQLite does not satisfy this requirement.
Verify encryption support and successful keyed access at startup; wrong/missing
keys or a non-encrypted SQLite build must fail closed, never create a plaintext
replacement. [SQLCipher](https://www.zetetic.net/sqlcipher/),
[rusqlite SQLCipher support](https://github.com/rusqlite/rusqlite)

Keep backend item identities, private usernames, secret fields, versions, and
schema metadata inside the encrypted database. Operator-approved catalog labels
and grants remain in the separate private JSON file. Transactions read a coherent
item snapshot and advance its version on every managed mutation. Password
rotation and deletion invalidate dependent bindings. Database encryption-key
rotation is a distinct administrative operation.

The database encryption key is supplied by the trusted host/unlock path and
stays outside the database and ordinary configuration. Never put it in command-line
arguments, SQL traces, logs, the agent environment, or a neighboring plaintext
configuration file. Headless deployments provision it through a protected host
channel, such as an inherited descriptor/service credential; interactive hosts
may obtain it through their own unlock flow. The library does not invent a default
password or prompt from an agent-initiated background read.

The macOS product uses Keychain for the credential items themselves, not merely
for a SQLite unlock key. Do not create a parallel SQLite password vault or
silently copy Keychain items into another backend. Explicit cross-backend
migration is a separate trusted administrative action, not a read fallback.

Encrypted-at-rest coverage includes database pages, journals/WAL, backups, and
temporary-file behavior. Configure and test the selected SQLCipher build so
these paths cannot expose plaintext records. Keep temporary secret-bearing
work in memory where necessary; do not assume every SQLite export/backup path
inherits encryption. Backups use an explicitly encrypted destination. Disabled
SQL tracing and extension loading prevent incidental exposure and unnecessary
capabilities. [SQLCipher design](https://www.zetetic.net/sqlcipher/design/),
[SQLCipher API](https://www.zetetic.net/sqlcipher/sqlcipher-api/)

Bound concurrent database work and transaction duration. Store lock closes access,
invalidates the store generation, and stops new secret resolution; late completions
must not reactivate revoked contexts. The daemon's ordinary cookie sessions remain
ephemeral and are not persisted simply because a database now exists.

Version schema migrations and run them only through a trusted opening/maintenance
path with a recoverable encrypted backup. Refuse newer unsupported schemas.
Test interrupted migrations and key changes. Key loss cannot be repaired by
the proxy; recovery uses operator-held keys and encrypted backups. Database
encryption alone does not detect restoring an older valid database snapshot or
protect an already compromised unlocked host.

The [operator lifecycle and recovery contract](operations.md) narrows the first
daemon's maintenance workflow to offline operation. It specifies verification
before publication, separate backup-key custody, current-policy review on
restore, and fault-injection gates. These are product-level requirements beyond
the existence of individual backend backup/rekey methods.

## macOS default: direct Keychain storage and reuse

`aap-store-keychain` stores passwords, provider keys, and other supported persistent
credential fields directly through Apple's Keychain services. New proxy-managed
items use a deliberate item namespace and access policy. Existing user items
remain in their original Keychain and are enrolled by private reference rather
than copied into a proxy-specific vault. Keep a credential bundle coherent when
username and password are resolved together, and map native access denial,
locked state, missing items, and interaction requirements to store errors.
[Apple Keychain services](https://developer.apple.com/documentation/security/keychain-services)

Support both relevant Internet-password items (site/account attributes) and
generic-password items (for example API keys). Trusted setup searches narrowly
for a specified site/account or selects an explicit item, obtains any required
native permission, and binds that item to a reviewed resource profile and grants.
Ambiguous matches require operator selection; a stored hostname alone cannot
authorize credential delivery. Agent tools search only this enrolled catalog.
[Apple password item model](https://developer.apple.com/documentation/security/adding-a-password-to-the-keychain)

Existing-item reuse is conditional, not a promise to read every password shown
in Apple's Passwords app, Safari, or iCloud. macOS file-based Keychain items use
per-item application access controls; data-protection/synchronizable items use
access groups and applicable entitlements. A user approval prompt cannot be
assumed to override all such restrictions. Validate which item classes and
Keychain implementations are accessible to the selected signed daemon/native
host, and document unsupported cases. Never scrape UI, weaken another item's
access policy, or bypass platform protections to obtain it.
[Apple access controls](https://developer.apple.com/documentation/security/access-control-lists),
[Apple access groups](https://developer.apple.com/documentation/security/sharing-access-to-keychain-items-among-a-collection-of-apps)

Existing-item enrollment is read/use-only by default. Updating or deleting a
user-owned item requires separate explicit operator authority; unenrolling an
item removes the proxy binding, not the original credential. External edits,
deletion, and changed access rights invalidate affected contexts on detection.
Persist only private references and approved non-secret catalog data outside
Keychain; no durable password mirror or cache. Missing/invalid references
require re-enrollment, not automatic selection of a same-named replacement.

Use `security-framework` directly from Rust for password storage, retrieval,
updates, deletion, and scoped item searches. If a required native operation lacks
a high-level wrapper, isolate a narrow `security-framework-sys` binding inside
the Keychain adapter. No Swift layer or generated cross-language interface is
needed. Embedding Rust hosts can use this backend or supply their own store.
[Password APIs](https://docs.rs/security-framework/latest/security_framework/passwords/index.html),
[item searches](https://docs.rs/security-framework/latest/security_framework/item/struct.ItemSearchOptions.html)

Keychain prompts and user-presence checks belong to the trusted application's
interaction policy. Initial enrollment may perform native permission setup;
agent-triggered reads without an available approved interaction path must fail
with a typed interaction-required outcome. A background resolution cannot approve
itself, fall back to SQLite, or copy denied material into a cache. Test native
access/lock behavior on macOS with isolated test items/keychains, never a
developer's personal items.

Follow the [Keychain delivery plan](keychain.md) for the initial per-user host
profile, non-synchronized enrollment scope, persistent identity, native-version
and management capability checks, bounded worker ownership, and W9 acceptance.
Broader native compatibility requires its own evidence; direct Rust bindings
alone do not establish every store-interface guarantee.

## Acceptance criteria

- The same read/use conformance suite runs against SQLite, the fixture backend,
  and later Keychain implementations without changing engine logic.
- The default database rejects no/wrong keys, remains encrypted through writes,
  WAL/checkpoints and backups, and never creates plaintext fallback storage.
- Item version changes, deletion, store lock, and failure invalidate access and
  dependent contexts without logging credential values or the encryption key.
- SQLite key provisioning works independently of its stored items; macOS stores
  the credentials themselves in Keychain with no SQLite mirror or fallback.
- Existing permitted Internet/generic-password items can be enrolled and used
  in place. Ambiguity, access denial, deletion, and external edits are tested;
  unenrollment never deletes the user's item.
- macOS release checks validate the real signed host's item-access behavior;
  inaccessible Passwords/iCloud or other-app items are reported as unsupported,
  not treated as an excuse to bypass platform controls.
- Client/minimal library builds pull neither SQLite nor Keychain bindings unless
  their selected functionality requires them.
- Store implementations cannot widen grants, choose arbitrary proxy destinations,
  silently unlock through an agent request, or bypass the proxy's state checks.
