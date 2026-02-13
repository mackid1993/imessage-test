# mautrix-imessage-v2

Matrix-iMessage puppeting bridge using rustpush + bridgev2.

## Build & Test

```bash
make build          # Build everything (Rust lib + Go binary)
make rust           # Rebuild only the Rust static library
make bindings       # Regenerate Go bindings from Rust FFI
```

No test suite exists yet. Verify changes compile with `make build`.

## Architecture

- **Go bridge** (`pkg/connector/`): bridgev2 connector — message routing, portal management, chat.db access
- **Rust library** (`pkg/rustpushgo/src/`): rustpush FFI — Apple Push, IDS auth, encryption, protocol encoding
- **Go FFI bindings** (`pkg/rustpushgo/rustpushgo.go`): auto-generated via uniffi-bindgen-go
- **Entry point** (`cmd/mautrix-imessage/`): main binary, config loading

## Key Files

| File | Purpose |
|------|---------|
| `pkg/connector/client.go` | Core message handling, portal routing, group chat logic |
| `pkg/connector/connector.go` | Bridge connector lifecycle, registration |
| `pkg/connector/dbmeta.go` | Portal/ghost/message metadata structs persisted to DB |
| `pkg/connector/login.go` | iMessage login flow (SMS 2FA, hardware key) |
| `pkg/connector/chatdb.go` | macOS chat.db reader for backfill and contacts |
| `pkg/connector/config.go` | Bridge configuration struct |
| `pkg/connector/contact_merge.go` | Multi-number contact portal merging |

## Conventions

- **Portal IDs**: DMs use a normalized identifier (e.g. `15551234567`). Groups use comma-joined sorted member identifiers.
- **Identifier normalization**: Strip `tel:`, `mailto:`, `+` prefixes → bare digits or email. Done by `normalizeIdentifierForPortalID()`.
- **Group routing**: Incoming group messages matched by sender_guid (persistent Apple group UUID), fuzzy member-list matching (±1 member), or member tracking. See `makePortalKey()`.
- **Outbound routing**: `portalToConversation()` reconstructs the Apple conversation from portal ID + cached group name + cached sender_guid.
- **Metadata persistence**: `PortalMetadata` in `dbmeta.go` stores fields that must survive restarts (sender_guid, group_name). Loaded in `loadSenderGuidsFromDB()`.
- **No tests**: Changes are verified by `make build` and manual testing against live iMessage accounts.

## Gotchas

- `BeeperBridgeType` must be `"imessagego"` (not `"imessage"`) — Android Beeper client checks this exact string.
- The Rust static library (`librustpushgo.a`) must be rebuilt when Rust source changes. `make build` handles this.
- `client.go` is large (~2800 lines). Read specific sections by line range rather than the whole file.
- Portal metadata is JSON-serialized into the bridgev2 database. Adding new fields requires `omitempty` tags for backwards compatibility.
- Group names (`imGroupNames`) and sender GUIDs (`imGroupGuids`) are cached in memory and persisted to `PortalMetadata`. Both caches are populated from DB on startup and updated from incoming messages.

## TPP Workflow

Technical Project Plans live in `_todo/` (active) and `_done/` (completed).
See `docs/TPP-GUIDE.md` for the full TPP format and conventions.

- Start a session: `/tpp path/to/tpp.md`
- Hand off when context is ~80-90% full: `/handoff`
