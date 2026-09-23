# Operator lifecycle and recovery

Status: proposed requirements, not implemented command documentation. This
extends W2, W4, and W8 without introducing an upstream authentication protocol,
a new crate, or another storage abstraction. Product names remain provisional.

## Authority and interface ownership

Keep three authorities separate:

| Authority | Permitted work | Must not imply |
| --- | --- | --- |
| Agent session | Discover granted items, obtain fake credentials, request protected operations, inspect/cancel its work | Enrollment, secret export, store unlock, configuration changes, or maintenance |
| Trusted approver | Approve or deny one immutable operation within existing grants | Store administration, new grants, or permission to bypass native access checks |
| Trusted operator | Provision stores, enroll items, configure policy, revoke sessions, and perform supported maintenance | Automatic approval of queued agent work or retroactive success of an uncertain request |

Store management remains an optional trusted capability alongside `SecretStore`,
not an addition to the agent-facing read/use interface. Read-only adapters are
valid. Report unsupported management operations explicitly; never compensate by
copying credentials to another backend. The daemon composes operator commands;
store adapters own native mutations, the engine owns invalidation, and
`aap-config` owns private-file publication. Embedders enforce the same lifecycle
through library contracts without inheriting the daemon's CLI.

Potentially blocking management operations are asynchronous and bounded. A
future operator transport may expose status/cancellation, but disconnecting
does not prove a mutation was cancelled. Once a persistent change may have
started, report a verified result or an explicit recovery-required outcome;
never retry it automatically. Do not expose this authority on an agent socket
or through MCP vault tools.

## Bootstrap and enrollment

Separate explicit initialization from ordinary startup. Missing stores,
unsupported schemas, invalid catalog references, or wrong unlock keys must not
cause `serve` to create an empty replacement or select another backend.
Initialization must refuse to overwrite an existing store. Use the private
paths, descriptor validation, and permissions in [the catalog contract](catalog.md).

Supply unlock material through a trusted host channel, never command arguments,
ordinary environment variables, logs, or configuration. Do not probe a real
website with stored credentials merely to validate configuration. Native
permission setup during Keychain enrollment is a separate trusted interaction
from per-operation human approval.

Enrollment has a review phase and a publication phase:

1. Select one accessible native item, or explicitly create a managed item.
   Bound discovery to an operator-selected site/account; resolve ambiguity
   through operator choice. Discovery must not unnecessarily retrieve values.
2. Review the resource profile, credential field kinds, account/display aliases,
   and approval policy. Keep the real username private unless its disclosure
   is explicitly part of the reviewed profile.
3. Bind the selected private reference in a complete candidate catalog and
   configuration pair. Check existing-item identity again before publication;
   if it changed or disappeared, require a new selection.
4. Publish and reload under the catalog's matching-revision rules. Enrollment
   succeeds only when the intended binding is installed. Session access still
   requires a separately established grant; catalog presence alone grants none.

Native item creation and catalog replacement are not one transaction. If
publication fails after creating an item, keep it unenrolled and report it to
the operator for explicit reconciliation. Do not retry creation blindly, delete
an existing user-owned item, or silently enroll an apparent name match.

## Invalidation, removal, and rotation

Distinguish the following actions in both the operator interface and its result:

| Action | Local effect | External effect |
| --- | --- | --- |
| Revoke an agent session | Stop new dispatch, cancel pending work, close affected streams, discard contexts | Does not undo already dispatched work |
| Unenroll an item | Remove its binding and invalidate dependent work/contexts | Does not delete the native item or revoke the upstream password |
| Lock a store | Prevent new resolution and invalidate dependent credential contexts/leases | Does not log out sessions elsewhere at the resource |
| Replace a stored credential | Advance its store version and invalidate dependent bindings | Does not itself change the password or key at the resource |
| Rotate the SQLite encryption key | Change protection of the local database | Does not rotate item passwords, provider keys, or existing backup keys |
| Delete a managed native item | Remove that item only under explicit management authority | May affect other applications using the item; requires separate confirmation |

Existing Keychain enrollment is read/use-only by default. Unenrollment cannot
serve as implicit permission to update or delete another application's item.
Automatic upstream password changes and account recovery remain out of scope.

Before a managed mutation, block affected new dispatch and invalidate pending
approvals, secret leases, placeholders, and cookie/token contexts. Close affected
long-lived work; retain conservative outcomes for already attempted dispatch.
After a successful mutation, require fresh preparation under the current store
generation. Failure must not revive old contexts. An external native edit is
handled on detection according to the backend's documented revalidation limits;
do not claim an atomic transaction with changes made by another application.

An operator revocation acknowledgment means local admission is closed, not that
the upstream has rolled back anything. Failed configuration reload leaves the
previous generation active: use explicit session revocation or stop the daemon
when a policy change must take effect immediately. Unlocking a store never
automatically approves or replays previously pending agent requests.

## First maintenance boundary

For the first operational release, perform SQLite backup, restore, schema
migration, and encryption-key rotation offline, with the daemon stopped and
exclusive cooperating access to the store. The host must prevent concurrent
daemon or maintenance opens. Bound lock acquisition; report busy instead of
waiting indefinitely. This simplifies the initial product without requiring
online maintenance or a distributed locking service.

Stopping the daemon invalidates its sessions and approvals. Pending and
possibly dispatched operations keep their cancellation/uncertainty semantics;
restart cannot recover exactly-once execution from an upstream service.
An embedding host must close affected broker/store handles before maintenance
and construct fresh authority afterward. The API must not imply that holding
an administrative handle alone makes concurrent use safe.

Maintenance validates a private source, works on an isolated encrypted
candidate, verifies it, and only then publishes an explicitly selected result.
Retain a verified recovery copy before a destructive migration or key change.
Neither an interrupted command nor a missing file authorizes startup to guess
between old and new generations. Recovery stays an explicit operator action.
Low-level online-capable backend functions are not evidence that the complete
daemon supports online maintenance.

## Backup, restore, and migration

A recoverable SQLite backup consists of an independently openable encrypted
database plus protected metadata identifying its format/schema and compatible
configuration revision. Keep its unlock key outside that backup. Any saved
catalog/configuration pair remains private metadata under the same owner-only
rules as live files; it is not automatically encrypted by SQLCipher. Never
include cookies, placeholders, approvals, session attachments, or observation
captures in the credential recovery set.

Verify the backup by opening it with the intended key and checking both database
integrity and the application's schema/item invariants. A successful file copy
or key-setting call alone is insufficient. Export must explicitly preserve
required schema metadata: SQLCipher's `sqlcipher_export` does not transfer
`user_version`. [SQLCipher API](https://www.zetetic.net/sqlcipher/sqlcipher-api/#sqlcipher_export)

Restore first into a private staging location, without agent listeners. Verify
keys, format, schema, item references, and compatibility with the operator's
chosen current configuration. Missing references block admission; never repair
them through approximate native-item matching. Restoring old catalog data is
a separate, explicit policy decision because it can restore revoked authority.
Review the installed pair and create new sessions only after recovery succeeds.

Encryption does not prove freshness. Restoring a valid older database can
restore old passwords and item versions; the baseline provides no external
anti-rollback authority. Restart invalidation prevents reuse of local contexts,
not rollback of upstream account state. An old password may no longer work,
and upstream reconciliation is the operator's responsibility.

Schema migration and SQLCipher format migration are distinct operations. Refuse
unknown/newer versions before modifying them. Test every supported migration
path; no generic downgrade or plaintext intermediary is permitted. Verify a
rotated database by reopening with the new key and checking rejection of the
old key. Recovery copies retain their own key requirements: key rotation does
not revoke old backups, and deletion cannot promise secure erasure on arbitrary
storage. Lost keys without a usable recovery copy are not recoverable by the
proxy.

On macOS, recovery of credential values stays with native Keychain/platform
facilities, not a proxy-created SQLite export. Back up private enrollment/policy
metadata separately. A native reference that no longer resolves after recovery
requires explicit re-enrollment; the daemon must not substitute a similarly
named item or weaken native access controls.

## Acceptance and delivery

Use synthetic items and isolated files/keychains only. Add these checks to the
existing work packages; they do not introduce additional protocol support:

| Gate | Required evidence |
| --- | --- |
| W2: custody | Wrong/missing keys, encrypted independently readable backups, schema preservation, corruption detection, and key-rotation verification |
| W2: interruption | Faults before/during publication leave a verified recovery source or a closed recovery-required state; no plaintext temporary files or automatic rollback |
| W4: operator separation | Agent paths cannot initialize, enroll, unlock, export, mutate, or maintain stores; approver decisions cannot obtain management authority |
| W4: invalidation | Mutation/reload/revocation races cannot revive contexts; late approvals and responses cannot dispatch under removed authority |
| W8: recovery rehearsal | Stop, back up, restore into isolation, validate current policy, restart with fresh sessions, and prove old handles remain unusable |
| W8: failure rehearsal | Disk-full, wrong-key, corrupt/newer-schema, mixed configuration, concurrent-open, and interrupted-maintenance cases have safe, documented outcomes |
| W9: native custody | Unenrollment leaves existing Keychain items intact; missing references require re-enrollment; unsupported access never falls back to another store |

The operator handoff must distinguish implemented commands from these planned
capabilities. Document required keys, supported formats, recovery selection,
backup retention, and which failures require stopping admission. A unit-tested
backup API alone does not close the end-to-end maintenance or recovery gate.
