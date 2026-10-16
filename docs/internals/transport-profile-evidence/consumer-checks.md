# Isolated consumer checks

Use this record to assess the delivered library revision against the
selected Playground and Solve consumers. These checks did not land the
prepared migration or exercise live services.

## Delivered revision

The checked library is `41483d5a4d76686c58f7c1b6452db02045f45a90`,
delivered in PR #252. Its exact-head gate passed all 23 steps and 5,721
runtime tests, with three skips. All 43 current PR checks and all eight
main push workflows passed, including Windows and macOS.

## Consumer result

Fresh isolated copies used Playground `5b043fed` and Byway `93254a3`.
The installed dependency graphs resolve the expected Phantom forks and exact
BoringSSL revision. Primary dirty files and the prepared migration
`399af77e` were preserved. Foundry was not interrupted.

| Selected suite | Passed | Skipped |
| --- | ---: | ---: |
| Playground types | 657 | 0 |
| Playground TLS egress | 157 | 0 |
| Solve offline Shape | 9 | 0 |

The initial runner stopped before tests because its nextest listing option
was unsupported. That attempt remains retained. The corrected command uses
`--list-type binaries-only`; discovery binds every selected test and binary
to the subsequent run. The actual nextest version was 0.9.140, separately
recorded from the gate's pinned 0.9.145.

The retained proof binds both consumer dependency graphs, V8 artifacts,
actual binary and workload identities, full logs and source-preservation
checks. All 139 retained native inputs matched before and after. The
independent review approved the 823 executed controls. Offline Shape checks
do not establish live provider acceptance or full consumer compatibility.

## Retained receipts

Artifacts are under each lane's `target/transport-profile-campaign/` or the
integration checkout's directory with the same name. Retain the isolated
copies and logs until archived; they are not the prepared migration branch.

| Receipt | SHA256 |
| --- | --- |
| Delivered consumer binding | `ee4468a1866fee600c59202fe04bbc7c306e755b386c0618ca0ae20bff04bbfb` |
| 823-test runtime result | `beb71e4bfdcc407de44ecb2dc2b6109eaac9131d67ab3415e466faaa1b4e2fe7` |
| Independent actual-result review | `07165adccb8b15678de5975fb92551973825e1c75e45b832340f3977eb919fc4` |

The migration remains unpublished and unlanded by user choice. No changes to
primary consumers, dirty vendor files or Foundry are authorized by this result.

## Next

- [Campaign](../transport-and-profile-campaign.md): remaining work and closeout.
- [Downstream guide](../../guides/downstream.md): pin a delivered revision.
