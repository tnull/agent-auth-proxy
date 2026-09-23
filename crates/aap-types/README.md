# aap-types

Credential-free public contracts shared by agent adapters and the trusted engine.

Provides strict JSON decoding, canonical/random local IDs, credential-free wire
types, and the asynchronous session-scoped `AgentService` interface. Runtime,
TLS, MCP SDK, and secret-store dependencies do not belong here. HTTP bodies use
runtime-neutral streaming traits. No implementation of the trusted engine is
implied by this interface.

The `mcp` module contains non-secret reviewed tool/argument descriptions, pinned
profile limits, schema reconstruction, and shared enrollment validation. Both
policy loading and the trusted remote adapter use that validation; it grants
no access, holds no upstream session state, and introduces no SDK dependency.

The `stream` module implements the credential-free TCP binding DTOs, five-byte
frame headers, bounded incremental decoding, and bidirectional frame sequence.
Opening controls bind the operation/resource, DATA obeys narrowed byte/frame
limits, and directional send-end is distinct from terminal completion. Missing
terminal records remain incomplete; abnormal ends after opening are uncertain.
Arbitrary application bytes have no implicit debug formatter.

These pure contracts do not dial or grant access. Their owner must reserve
aggregate buffers, bound retained frames, enforce deadlines and cancellation,
and track actual accepted socket writes separately from admitted frame bytes.
Reserve that memory before invoking a decoder. The engine now provides trusted
native-I/O relay integration; HTTP upgrade is implemented in `aap-http`, while
agent client support remains pending.

`AgentService::open_stream` and `stream::service` separate admission from
connection and forwarding through owned, non-cloneable handles. The engine
implements this seam; other adapters explicitly reject it by default. Admission
reports an existing operation or its sole pending attachment. Connection then
reports safe opening metadata or a terminal result. Adapter delivery failure
is a separate error, never invented success or a retry instruction.

The runtime-neutral `ApplicationIo` callbacks provide bounded read/write and
explicit directional end. They expose no upstream socket, secret store, or
authority override. The terminal outcome comes separately from the relay
future. Transfer takes ownership immediately; dropping handles/futures cancels
nonterminal work. Trusted implementations must honor wakeups, actual-prefix
write accounting, bounded framing memory, and the no-hidden-queue/no-reentrancy
contract. Fixed attachment errors cannot claim orderly success or approval.
Stop-only abort handles can terminate pending/connected work without waiting
for an I/O callback. Their termination wakeup is not a terminal result or proof
of delivery, and they must not be called reentrantly from engine callbacks.
