# Caller-owned backend frames

This directory contains the official `postgres-protocol` 0.6.12 crate from
crates.io, licensed under MIT OR Apache-2.0. Both upstream licenses are retained.
The official `.crate` archive SHA-256 is
`08808e3c483c46e999108051c78334f473d5adb59d78bb80a1268c7e6aa6c514`.
`UPSTREAM-FILES.sha256` records the original packaged file contents. The
package-local developer `Cargo.lock` and registry cache bookkeeping are omitted;
the enclosing Busbar workspace resolves its normal lock.

The only production source patch is in `src/message/backend.rs`:

- `Message::parse_owned(Bytes)` accepts exactly one complete frame and preserves
  its caller-provided byte owner through every parsed slice and cloned row.
- Existing `Message::parse(&mut BytesMut)` retains its incremental API and delegates
  complete frames to the same parser.

The new entry rejects incomplete headers/bodies, invalid lengths, unknown tags,
and trailing frames. It neither introduces unsafe access nor copies a caller's
frame into an independently owned allocation. PostgreSQL uses `Bytes::from_owner`
with a wiping allocation, so the final shared owner erases the initialized frame
before freeing it. The upstream field decoder and wire format are unchanged.

The owning plugin's receive tests cover shared row/slice lifetime, malformed
frames, fragmented/coalesced input, and staging growth/consumption/drop. This
patch does not claim to erase operating-system, database-server, or deferred
serde internal scratch memory.

Upstream project: https://github.com/rust-postgres/rust-postgres
Official release source commit: `76062c9b242da6aada065c021aa3083d0922f7d2`.
