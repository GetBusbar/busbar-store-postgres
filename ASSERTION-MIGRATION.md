# Postgres ordinary-test migration

Baseline: accepted017559f. Source pin remains a35493a5e74cc935ff7dcc15c1af869290da91cb;
no SDK, peer revision, lockfile, publication or dependency-policy changes are included.

## Product assertions

- The existing `the_linked_and_the_dropped_in_postgres_store_are_one_store`, foreign-byte rejection,
  wrong-kind rejection, all provider tests, real-install e2e and admin HTTP e2e assertions remain.
- `support/store_contract.rs` expands the pinned store script into ordinary Rust operations:
  all 86 original operation labels plus READY preserve exact first-crossing assertions (87 total),
  the pending/resume positive witness, all 31 slot guard, answer golden,
  replay/conflict, credentials, usage, budgets, denylist, event ordering, single redemption,
  generic record and scoped-key checks. Actual linked and actual dropped runs compare all answers.
- `support/door_refusals.rs` preserves ABI +1/-1 pack/linked/dropped errors; layout xor1/zero
  pack and linked-own/honest-row errors; three Statement mismatch branches; all six other kinds
  through both doors; no-table refusal through both doors and successful metadata probe.
- `support/host_boundaries.rs` preserves failed READY text, one READY, one real successful CLOSE,
  and exactly OPEN/READY/CLOSE crossings. It also compares declared needs to the actual Statement
  and enforces BUSBAR_EXPECT_RELEASE.
- Newer-schema refusal runs through both doors after an actual open and schema stamp.
- All three URL reference tests remain, calling the production `resolve_declared_fields` with
  the loaded Postgres plugin's own secret/reference declarations.
- Provider fault wrappers still intercept the same short write, withheld commit reply and
  cancellation conditions. Their underlying I/O is now the actual connector and actual TCP
  carrier rather than TcpConns. The narrowly scoped TLS request observer asserts the same
  verify_off flag before forwarding to production connection security.
- The macro's full store script still requires a live database locally (default localhost:5432)
  and in CI; CI must provision BUSBAR_TEST_POSTGRES_URL. Existing optional local durable tests
  retain their pre-existing local gate and hard failure in CI. No absent-artifact skip exists.

## Framework checks retired with the framework

- `red_a_moved_crossing_count_is_refused`: intentionally corrupting the removed Fold comparator.
  Exact unmodified crossing assertions remain on every ordinary store operation.
- Canary registration with no configured `credentials` (this input file has none) did no work.
  Existing concrete DSN password masking assertions remain.
- Unreported billing class, transport frame-piece, plane answer-layout, outbound wrong-byte,
  outbound no-field and outbound second-token checks were no-ops for kind:store.
- The conformance host's own TLS-anchor/withheld-anchor and private-destination guard tests
  exercised the deleted host helper, not Postgres. Postgres TLS trusted/untrusted/cleartext and
  verification-mode tests remain over production connector security. Production destination
  guard coverage belongs to the connector's tests.
- The raw rustls `UnknownIssuer` debug-string observation came from the old SecureDial helper.
  Its replacement observes production `upgrade_secure` returning Refused for the deliberately
  mismatched CA, while preserving the actual Postgres open refusal and trusted-CA positive arm.
  Production's public connection boundary exposes Refused, not the internal verifier error.

## Explicit qualification limits

The undeclared-need and cross-instance checks enter the actual host ABI slots through the
public hidden loader seams at the unchanged author pin. They preserve exact refusal outcomes
and text for undeclared needs, foreign write/read/close and owner-write success, with the actual
TCP carrier reaching a real listener. A final SDK with different visibility requires separate
qualification without retargeting the authored source.

CI must build this exact real cdylib immediately before the test run and export its absolute
path in BUSBAR_PLUGIN_CDYLIB. Missing/relative artifacts fail. Direct developer fallback names
only target/<profile>/libbusbar_store_postgres_plugin.<ext>; no deps/hash/mtime search remains.
The reusable CI producer is root-owned and remains at the existing pin in this source change.

Validation: cargo fmt --all -- --check and git diff --check. Builds and live execution await
resource-lane approval; this source change does not claim runtime equivalence or green CI.

Host-helper destination-judge cases (private/default-loopback/cloud-metadata refusal and
operator-infrastructure loopback admission) are retired helper selfchecks; their explicit
core connector-test mapping and final-SDK execution are pending root qualification.

The old framework's unused `store.node` mint-slot parameter is removed. Ordinary callbacks
use this repo's existing `common::mint`, which generates fresh bridge-write IDs independently
of test scheduling. Private schemas isolate both deliveries. Explicit replay/conflict calls
continue using exactly `OpId::from_parts(2, n)`; no operation-ID replay assertion changes.
