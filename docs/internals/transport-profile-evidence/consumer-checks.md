# Isolated consumer checks

Use this record to assess the delivered library revision against the
selected Playground and Solve consumers. These checks did not land the
prepared migration or exercise live services.

## Current delivered result: 831 tests

The selected consumers passed against Phantom
`b5dd5b4270ebd35d59146e73dcf995b1bef0f2d7`, delivered in PR #260.
Its full gate passed all 23 steps, followed by all applicable PR and main
checks. The isolated inputs were Playground
`3fd4d346a8e0956a00df3de3469d96f03beda3c6` and the retained Solve source
from Byway `93254a3b6c5a765ff6c550565c05e03ba43d294b`.
Playground's advancing primary branch was observed separately.

| Selected suite | Passed | Skipped |
| --- | ---: | ---: |
| Playground types with serde | 665 | 0 |
| Playground TLS egress | 157 | 0 |
| Solve offline Shape | 9 | 0 |
| Total | 831 | 0 |

Every discovered test name matched a pass. All nine discovery, binary-listing
and run commands exited zero, with retries disabled. Executable identities
matched before execution, afterward and in retained copies.

Independent review verified all 36,003 placed source identities, all 139
retained native inputs and all 89 dirty original vendor files after execution.
The migration ref remained
`399af77e999a5f4f6bb094dda3cc9823cbb21359`. Actual engine build output binds
the selected Solve binary to the fork, ICU 78 and sandbox guards, and the
238,089,004-byte owned V8 archive. Its SHA256 is
`24a5e6090921282d7734deaa9b764add7e0af9b6786034c44c1abb5ac538c167`.

The packet is under the `chromium-macos-dns-integration` lane's
`target/transport-profile-campaign/D1-final-consumer-v4/runs/20261016T120907399633Z/`.

| Receipt within packet | SHA256 |
| --- | --- |
| `tests/result.json` | `c3cac1924cf3d217b7ffe71ed88c95079f44af240f13a807691a358501a656d9` |
| `tests/result-review.json` | `acd23c0e6caef5694c54366f7fa303aaded423f16841b15fb2c19986b3bb46e5` |
| `graph/result.json` | `b0d4c7bac6f6d8d6a497ee2faf3e3fb8875600432095fae565953b086154daed` |
| `graph-review.json` | `beafad14baeb0c4e295a7d0a8d1e870bb55673f2e9bfb1d77035e732c7f5c5aa` |
| `graph/sources-after-locks.json` | `0ed2e2ec11ba94fc7dc679920f6c0ffbea6fb5be3bf7cf0f5c4968953c3d0a22` |

This result covers fresh isolated Rust compilation, linking and the selected
offline tests using retained native inputs. It does not establish a fresh
native C/C++ rebuild, full consumer compatibility, browser parity, live
provider acceptance or throughput. The prepared migration remains
unpublished and unlanded. Foundry was not interrupted.

## Historical delivered result: 823 tests

The checked library is `41483d5a4d76686c58f7c1b6452db02045f45a90`,
delivered in PR #252. Its exact-head gate passed all 23 steps and 5,721
runtime tests, with three skips. All 43 current PR checks and all eight
main push workflows passed, including Windows and macOS.

### Consumer result

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

### Retained receipts

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
