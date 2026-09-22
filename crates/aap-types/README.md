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
