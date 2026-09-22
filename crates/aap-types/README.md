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
Reserve that memory before invoking a decoder. The planned HTTP upgrade,
engine relay, and client remain separate integration work.
