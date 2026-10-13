# Audit findings

Use this ledger to connect each finding to its cause, change, and evidence.
No finding is resolved by an assignment or a proposed fix.

Historical record names in this page refer to the
[retained evidence](evidence.md). Earlier results keep their original revision
and scope; they do not establish final integration.

## Findings

| ID | Priority | Contract | Evidence | State |
| --- | --- | --- | --- | --- |
| A01 | P1 | Total deadline covers body reads | Raw and decoded ready-frame paths differ | Red/green tests; review approved |
| A02 | P1 | Invalid admission settings return a build error | Caller counts reach `Semaphore::new` above its maximum | Red/green tests; review approved |
| A03 | P1 | Disabled QUIC tickets prevent resumption | Changing the TLS profile retains an isolated cache | Red/green tests; review approved |
| A04 | P1 | Address cache bounds shared background work | Clear removes pending bookkeeping without ending work | Red/green tests; review approved |
| A05 | P2 | Proxy setup waiters receive their attempt's failure | A newer failure overwrites an older attempt's result | Red/green tests; review approved |
| A06 | P2 | EventSource owns Last-Event-ID | Templates and automatic hints can supply an unmanaged ID | Red/green tests; review approved |
| A07 | P1 | Failed WebSocket close releases ownership | Close errors retain the socket and admission | Red/green tests; review approved |
| A08 | P2 | Debug output protects arbitrary header values | Three profile field enums derive Debug over literal values | Red/green tests; review approved |
| A09 | P3 | QUIC key-update documentation matches its interface | Comment still describes an infallible interface | Source reconciled; review approved |
| A10 | P2 | GREASE parameter IDs fit their configured width | Full-range IDs overflow accepted narrow widths | Red/green tests; review approved |
| A11 | P1 | A failed boundary scan cannot report success | Manifest scan failure is lost through process substitution | Red/green tests; review approved |
| A12 | P2 | Malformed capture hex returns an error | UTF-8 slicing panics and radix parsing accepts signed pairs | Red/green tests; review approved |
| A13 | P2 | QUIC setup errors retain categories and release IDs | Provider failures report endpoint shutdown and retain an allocated ID | Red/green tests; review approved; native vendor checks pass |
| A14 | P1 | Cargo lock holders retain exclusive ownership | Stale reclamation can move a new holder's directory | Red/green tests; review approved |
| A15 | P2 | Android model constructors produce structured strings | Generic header validation accepts an embedded tab | Red/green tests; review approved |
| A16 | P2 | Tool-pin scans must finish before reporting agreement | Search status 2 is swallowed | Red/green tests; review approved |
| A17 | P2 | Freshness reports include validated fixture paths | Function-local paths are referenced outside their scope | Red/green offline tests; review approved |
| A18 | P2 | DNS test-server replies belong to their server | Detached reply tasks retain the socket after server drop | Red/green tests; review approved |
| A19 | P2 | Capture listeners accept loopback before binding | Wildcard arguments create a listener before rejection | Red/green tests; review approved |
| A20 | P2 | Captured SNI preserves the document format | UTF-8 SNI with CR/LF introduces metadata lines | Red/green tests; review approved |
| A21 | P3 | Fuzz documentation states reachable limits accurately | Short fields reach the count limit below 16 KiB | Source correction; review approved |
| A22 | P2 | Hook docs describe credential stripping precisely | Generic wording overstates protection of custom fields | Source correction; review approved |
| A23 | P1 | HTTPS discovery bounds outstanding lookup work | Pending eviction retains tasks and permits duplicate lookups | Red/green tests; review approved; lint passes |
| A24 | P1 | Replay byte limits also constrain retained metadata | Empty DATA frames grow a deque without consuming the byte budget | Three regressions red/green; breaking fix and review approved |
| A25 | P2 | Response decoding uses the actual template encoding | Forwarding-condition defaults differ from cached trust defaults | Proxy wire regression red; direct control passes; fix and composed source review approved |
| A26 | P2 | Prepared-template debug protects cached header values | Derived Debug prints copied Accept-Encoding values | Canary regression red; nested builder control passes; fix and review approved |
| A27 | P2 | SOCKS CONNECT errors retain their negotiation category | Upstream UnknownAuthMethod also denotes an unknown CONNECT reply | Red/green test; review approved; proxy suite and lint pass |
| A28 | P2 | ACK_FREQUENCY validates the selected wire format | A one-byte flag is decoded as a variable-length integer | Real connection regression red/green; review approved; vendor replay passes |
| A29 | P3 | Windows option tests survive reserved UDP ports | A raw port-zero bind bypasses the retry helper | Shared binder repair; 37 UDP tests pass; review approved |
| A30 | P2 | Capture containment owns children before they run | Job assignment follows an already-running process | Native bootstrap independently approved; 86 focused Windows tests pass; A37 shutdown gap remains |
| A31 | P2 | Profile sweeps preserve unrelated processes | Windows substring matching kills a different profile and quoted paths fail | Exact, descendant and prefix-sibling controls pass; independent review approved; A37 caller gap remains |
| A32 | P3 | ECH support documentation states what is checked | Parameter support does not validate the HPKE public key | Source correction and independent review approved; seven parser tests pass |
| A33 | P3 | Short tests stay with their module | AcceptCh's 51-line tests use a separate directory and path annotation | Inline move independently approved; all three tests pass |
| A34 | P2 | HTTP/3 control parsing bounds retained payloads | Control decoding waits for an entire peer-declared non-DATA payload | Red/green tests; 36 decoder and 52 peer tests pass; review approved; packaging pending |
| A35 | P2 | HTTP/3 cookie limits apply before splitting | Semantic validation repeats supplied-field limits over emitted crumbs | Red/green tests; 185 transport HTTP/3 and seven facade cookie tests pass; review approved |
| A36 | P2 | Known frame fields consume exactly their declared payload | Single-ID parsing leaves trailing bytes or treats a complete truncated field as partial input | Independently reviewed correction passes 41 decoder and 53 connection tests; final vendor gate pending |
| A37 | P2 | Capture shutdown continues after individual cleanup errors | First close or profile-sweep failure skips later owners and reporting | Final independent review approves owner attribution and repeated interruption; 96 capture tests pass on Windows and Linux |
| A38 | P3 | Server field-section tests use actual peer limits | Simulated limits are replaced by real SETTINGS before server assertions | Corrected controls pass; independent review and final Linux vendor check pass |
| A39 | P2 | CONNECT-UDP target ports meet the protocol contract | Template expansion accepts target port zero | Red/green Windows and Linux regressions; independent review approved |
| A40 | P3 | Shared H3 test endpoints bind loopback and handle reserved ports | Both endpoint constructors bind wildcard IPv6 with no Windows bind retry | Review approved; all 377 H3 unit tests pass on Windows and Linux; vendor replay passes |
| A41 | P3 | Stress tests execute at least one iteration | Zero iterations produce a passing test with four zero outcome counts | Actual zero now fails; parser and positive/default controls pass on Windows and Linux; independent review approved |
| A42 | P3 | Vendor checks and refresh instructions select the actual forks | Formatter commands include dependencies and notes name old package identities | Correction committed; selected formatting and ShellCheck pass; independent source review approved |
| A43 | P2 | DNS capture work is owned, bounded and observed | Detached children, unbounded query records and no operation deadlines | Authenticated baseline has three passes and nine failures; all 20 corrected tests pass on Windows and Linux; independent review approved |
| A44 | P1 | TLS message callback ownership survives an SNI context switch | Lookup uses the replacement context instead of the original callback owner | Actual process-abort regression red/green; independent review approved; native vendor checks pass; Windows staging warning qualified below |
| A45 | P2 | TLS message Debug omits message bytes | Derived Debug exposes an actual ClientHello canary as decimal bytes | Canary regression red/green; independent review approved; native vendor checks pass; Windows staging warning qualified below |
| A46 | P2 | Sensitive cookie crumbs retain diagnostic protection | Crumb policy overwrites sensitivity before dynamic-table insertion | Four regressions red/green; independent review approved; 14 captured HPACK replays pass; Windows and Linux vendor checks pass |
| A47 | P2 | Conformance image arguments cannot execute shell syntax | Whitespace-only validation forwards shell substitutions into the pinned runner | Marker reproduction and 18 failed baseline subcases; corrected eight-method suite passes; independent review approved |
| A48 | P2 | HPACK indexing arithmetic accepts legal peer limits | Three-quarter selection multiplies a peer u32 table limit in usize | Actual 32-bit debug panic and release mismatch; three corrected tests pass in debug and release; independent review and Windows/Linux vendor checks pass |
| A49 | P2 | WebSocket compression negotiation follows HTTP grammar | Unicode trim accepts non-HTTP whitespace around parameters | Two intended baseline failures and seven passes; nine corrected tests pass; independent review and Windows/Linux vendor checks pass |
| A50 | P2 | Failed downloads preserve files owned by another invocation | Planned cleanup and later path replacement lose file ownership | Private staging and added two-owner test independently approved; eighteen tests pass on Windows and Linux; Linux Rust 1.88 check passes |
| A51 | P3 | Manual QUIC version reports observe at least one request | Client accepts zero and returns without observations | Zero baseline reproduced; count controls and actual default/one-request peers pass; independent source review approved |
| A52 | P2 | Autobahn failures retain finite owned cleanup | Removal exit status is ignored and cleanup operations have no deadline | Initial repair approved; report-interruption follow-up has two intended baseline failures; corrected composition independently approved and 88 Windows/Linux methods pass |
| A53 | P2 | QUIC runner exits clean up only owned external resources | Outer timeout and interruption restore files without owning container cleanup | Recovery corrections independently approved; applicable controls pass in 145-method Windows/Linux suites; actual Linux descendant control passes; final gates pending |
| A54 | P2 | Version-report servers own temporary files and close after publication failure | Certificate directory has no cleanup owner; port publication precedes close-finally | Repair independently approved; composed 51-method suite passes on Windows and Linux; actual loopback output and scratch controls pass |
| A55 | P2 | WebSocket offer iterators stop at their parameter bound | Full collection and profile copying precede the four-parameter check | Signed baseline has four passes and one intended sixth-read failure; six corrected controls pass on Windows and Linux; Linux Rust 1.88 check passes; independent source review approved |
| A56 | P2 | WPT shutdown retains resources and reports failures | Success is published before cleanup, which loses simultaneous causes and has unbounded stop | Acquisition and interruption repairs independently approved; composed 122-method Windows/Linux suites pass with explicit platform skips; final gates pending |
| A57 | P2 | TLS-Anvil cleanup has verified ownership and a deadline | Removal failure is ignored and cleanup has no deadline | Source remedy and corrected shared composition independently approved; 37 focused methods and 88 composed Windows/Linux methods pass; final integration pending |
| A58 | P3 | Shared settings and request types have one public path | Public protocol aliases duplicate their root or request-module names | Signed source independently approved; Windows/Linux Clippy, 339 selected tests, 143 doctests, default/all-feature rustdoc, MSRV and path/Git downstream checks pass; eight API inventories regenerated; final gates pending |
| A59 | P3 | Runtime documentation describes the existing deadline service | Design denies a global runtime although shutdown_timer owns one | Prose correction independently approved; no runtime change |
| A60 | P2 | The excluded fuzz workspace resolves the current local forks | Its exact Quinn requirement and four lock entries retain older fork versions | Manifest failure reproduced; pin and four local lock versions corrected; Windows/Linux fuzz Clippy and nineteen tests pass; final gates pending |
| A61 | P2 | Trailer tests observe interleaved names and sensitivity on the wire | Decoded header maps cannot prove the order claimed by their names | Source and composition independently approved; six raw H2/H3 uploads and existing selected trailer controls pass in eight methods on Windows/Linux; final gates pending |
| A62 | P2 | Stream MASQUE test proxies own accepted and relay tasks | Drop aborts the listener while accepted connections and relay children detach | Stalled TLS and partial-capsule cancellation controls fail before repair; independently approved task ownership repair passes Windows/Linux; final gates pending |
| A63 | P2 | An H2 no-request assertion distinguishes parser failure from absence | Capability helper converts any protocol error into a successful absence observation | Malformed/truncated frame controls reproduce false absence; independently approved bounded raw observer passes Windows/Linux controls and existing callers; final gates pending |
| A64 | P2 | H1 WebSocket Close tests verify the observed opcode | Echo helper replies with Close for any second frame | Ping negative fails before repair; exact Close observation and positive echo pass Windows/Linux; source and composition approved; final gates pending |
| A65 | P3 | HTTPS WebSocket teardown accepts a Windows peer abort | Relay accepts reset and broken pipe but rejects ConnectionAborted | Classification fails before repair; approved existing peer-close predicate passes controlled errors and Windows/Linux proxy callers; final gates pending |
| A66 | P2 | Examples keep secrets out of diagnostics and enforce their same-origin task | Cookie values and URL queries are printed; joined fetch targets can use another origin | Independently approved examples preserve targets and Referer while rejecting foreign origins before I/O; four controls and workspace Clippy pass Windows/Linux; final gates pending |
| A67 | P2 | Gate and CI reject leaked test output | Nextest can report LEAK with a successful exit and the gate's log scan omits it | Independently approved same-interval failure policy and scanner; controls pass Windows/Linux. Original113 run retains ten Linux forward-proxy LEAK-FAIL; one instrumented exact113 replay passes those methods without identifying the historical cause. No timeout or retry waiver; independent assessment qualifies sampling gaps and observed-EOF detector; historical cause and final gates remain open |
| A68 | P2 | An H3 no-request assertion preserves protocol failures | Accept errors can satisfy the absence assertion | Four typed malformed-peer negatives fail before repair; explicit clean-close and quiet-window positives pass; corrected controls and callers pass Windows/Linux; independent approval; final gates pending |
| A69 | P2 | H3 test relays own receiver and delayed-send tasks | Front-owner cancellation leaves descendants holding UDP sockets | Actual UDP cancellation controls fail before repair and pass afterward on Windows/Linux; receiver and send JoinSets independently approved; final gates pending |
| A70 | P3 | A fresh SOCKS association permits OS port reuse | Retry test requires a different UDP address after releasing the first socket | Unsupported inequality removed; two completed control associations and nonzero traffic retained; existing retry test passes Windows/Linux; source-approved; final gates pending |
| A71 | P2 | A rejected early-data test observes dispatch and resend | Ordinary handshake requests also satisfy the original path assertions | Source-approved held reply gate and dispatch observations pass Windows/Linux; disabling early data fails the Linux control and byte-exact restoration passes; final gates pending |
| A72 | P2 | H3 MASQUE fixtures cancel every accepted connection phase | Accepted tasks detach and bootstrap or rejection waits do not observe close signals | Six authenticated cancellation controls fail and one positive passes on Windows/Linux; approved remedy passes all 36 selected controls on both hosts; final gates pending |
| A73 | P3 | A refused SOCKS TCP endpoint reserves the TCP port | Alt-Svc race fixture uses a UDP-only blackhole address for a TCP refusal | Held TCP reservation source-approved; all 31 Alt-Svc controls pass Windows/Linux; final gates pending |
| A74 | P2 | Untrusted alternative fixtures own pending handshakes | Dropped handshake handles detach after the accept owner stops | Actual pending-handshake cancellation fails before repair on both hosts; owned-task remedy independently approved; all 31 selected controls pass Windows/Linux; final gates pending |
| A75 | P2 | Admission recovery tests preserve unrelated failures | Race test retries every stringified send error until success | Unexpected-input control fails before repair; typed retry remedy approved; control's expected category corrected to InvalidAuthority; all 31 selected controls pass Windows/Linux; final gates pending |
| A76 | P3 | Cancelled and abandoned QUIC attempts have independent identities | UDP peer-address count assumes the OS will not reuse a released port | Same-address distinct-identity regression fails before repair; approved Initial-header identity counting passes Windows/Linux controls; final gates pending |
| A77 | P2 | A quiet datagram observation has a healthy observer | Blackhole receiver and lock failures can leave stale nonzero counts | Three health regressions fail on Windows/Linux; approved remedy and fallible poison guard pass all 34 Alt-Svc controls on both hosts; final gates pending |
| A78 | P2 | DNS lookup provenance comes from the selected cache entry | A new or joined resolution can publish before readiness is mistaken for a cache hit | Both real-publication regressions fail Windows/Linux; explicit Stored selection source-approved; 38 initial and 66 later selected controls pass both hosts; test paragraph corrected; final gates pending |
| A79 | P2 | Interface lookup and binding errors retain their OS cause | Lookup and source-binding wrappers replace original errors with strings | Eight cause regressions fail on Windows/Linux; approved typed-context remedy passes all 66 selected network controls on both hosts; final gates pending |
| A80 | P2 | Shared DNS errors retain the resolver's original cause | Cache outcomes retain only kind and message, even for first and inline lookup | Five cached-cause regressions fail on Windows/Linux; approved shared-cause remedy and corrected client docs pass all 66 selected network controls on both hosts; final gates pending |
| A81 | P3 | A streaming test peer owns its connection until shutdown | The upload helper detaches its connection driver and returns a byte count | Actual 200000-byte upload completes before the ownership control fails Windows/Linux; inline driver remedy source-approved; all 38 selected controls and targeted checks pass both hosts; exceptional outer-handle cleanup remains qualified; final gates pending |
| A82 | P3 | Parser guards have distinct operation paragraphs | Disarmed-head and oversized-capsule guards run into independent work | Two source-confirmed grouping edits composed separately; no logic change or extra tests |
| A83 | P2 | Early-response test peers remain owned on exceptional exit | Raw outer handles detach on early errors, assertion unwinding or cancellation | Both causal baselines fail on Windows and Linux; approved concrete ownership and typed combined causes pass all 71 selected network controls and focused checks on both hosts; final gates pending |
| A84 | P2 | Plaintext and query test exchanges own their peers | Request-first awaits detach peers on cancellation and hide completed peer failures | Four real-exchange regressions fail on Windows and Linux; source-approved lexical concurrency passes all fifteen request controls and focused checks on both hosts; final gates pending |
| A85 | P2 | Connection and CONNECT fixtures own accepted work | Detached relay children and abort-without-join lose ownership and late errors | Independently reviewed ownership and reset-cause repairs pass 25 cleanup controls and 118 callers on Windows and Linux, plus formatting, Clippy and Rust 1.88 checks; final gates pending |
| A86 | P2 | Diagnostic scratch ownership reports cleanup failures | Early exits abandon directories and exhausted removal retries return success | Actual filesystem failures reproduced; independently reviewed cleanup and caller repairs pass the 25-control and 118-caller Windows/Linux composition; final gates pending |
| A87 | P2 | HTTP/1 test peers remain owned after cancellation | Raw peer and transaction handles detach on exceptional exits | Causal controls fail before repair; independently approved remedy passes all 88 H1 tests on Windows and Linux; final gates pending |
| A88 | P2 | HTTP/1 fixture deadlines retain their typed cause | Deadline wrappers replace Elapsed with strings | Both cause controls fail before repair; corrected resolved import and typed remedy pass the 88-test Windows/Linux H1 selection; final gates pending |
| A89 | P2 | H2 WebSocket origins observe handler failures | Detached inner echo handler and broad teardown suppression lose failures | Corrected baseline passes four controls and fails two intended regressions per host; reviewed lexical handler remedy passes all six on Windows/Linux; final gates pending |
| A90 | P2 | Request API fixtures own their exchange peers | Request-first waits detach peers and hide completed peer failures | Reviewed lexical repair and failed-upload client retention pass all 59 selected request tests on Windows/Linux, plus focused checks; final gates pending |
| A91 | P2 | Failed-upload test peers retain unexpected protocol failures | Accept and DATA helpers convert unrelated errors into normal completion | Typed protocol, unexpected reset and unrelated I/O controls pass; DATA teardown failure traced to early client destruction and fixed by retention; all 59 selected tests and focused checks pass both hosts; final gates pending |
| A92 | P2 | Client test deadlines retain Elapsed | The bounded wrapper returns a string for timeout | Typed deadline control fails in the corrected baseline and passes after repair on Windows/Linux; final gates pending |
| A93 | P3 | Hook retry and redirect tests observe the required positive fields | Equal retry heads can both omit the hook; cookie absence lacks a first-hop presence check | Literal hook and first-hop cookie controls fail before repair and pass in the native composition on both hosts; final gates pending |
| A94 | P2 | H2 shutdown test peers remain owned and report completed failures | Raw peer ownership detaches on exceptional exit and stop ignores the join result | Causal ownership controls fail before repair; independently reviewed remedy passes all 151 selected H2 tests and focused checks on Windows/Linux; final gates pending |
| A95 | P2 | H2 shutdown fixture deadlines retain their actual causes | Wrappers stringify Elapsed, RecvError and ScheduleError or return untyped expiry | Four deadline regressions fail before repair; typed remedy and ready-operation positive pass in the independently reviewed 151-test Windows/Linux composition; final gates pending |
| A96 | P2 | H2 shutdown observers preserve transport failures | Some(Err) is reported as an unexpected request or lost reset | Both actual transport-fault controls fail before repair; typed observers, real CANCEL and forced-close positives pass in the 151-test Windows/Linux composition; final gates pending |
| A97 | P3 | Proxy configuration errors retain validation causes | Credentials, authorities and target validation lose their original causes | Fifteen intended regressions fail on both hosts; reviewed repair and bounded error storage pass all twenty controls, forty-five unit tests and focused checks on Windows/Linux; final gates pending |
| A98 | P2 | Capture publication preserves the first failure and recovery path | Failed staged-file removal replaces the publication error or interruption | Nine combined capture regressions fail in the Windows baseline; reviewed publication/startup repair passes all 57 selected methods on Windows/Linux; final gates pending |
| A99 | P2 | Acquired HTTP/3 capture servers close after startup failure | Metadata and startup output run before the cleanup boundary | Controlled acquired-server regressions fail before repair; reviewed ownership and independent cleanup pass the 57-method Windows/Linux composition; actual OS drain is not established; final gates pending |
| A100 | P2 | Environment fixtures own peers through exceptional exits | Raw front and child relay handles can detach before collection | Seven baseline failures reproduce on both hosts; reviewed ownership remedy passes all 21 environment controls on Windows/Linux; final gates pending |
| A101 | P2 | Environment fixture deadlines retain their typed cause | Both bounded wrappers replace Elapsed with strings | Typed timeout baseline failures reproduce on both hosts; reviewed remedy passes the 21-control environment selection; final gates pending |
| A102 | P2 | Verified environment H2 peers preserve observer failures | RecvError and actual transport outcomes become string diagnostics | Typed receiver and transport causes preserved by reviewed remedy; all 21 environment controls pass Windows/Linux; final gates pending |
| A103 | P2 | Alt-Svc state fixtures own peers through exceptional exits | Plaintext persistence and pinned peers retain raw task handles | Five baseline failures reproduce per host; reviewed owner remedy passes all 40 Alt-Svc state controls on Windows/Linux; final gates pending |
| A104 | P2 | Alt-Svc state fixture deadlines retain Elapsed | Three bounded wrappers replace the cause with strings | Three typed timeout negatives fail before repair; reviewed remedy passes the 40-control state selection on both hosts; final gates pending |
| A105 | P3 | Cross-origin pin tests use deterministic DNS | Foreign-origin refusal depends on ambient system lookup | Reviewed selected resolver and literal first-hop assertions pass in the 40-control Windows/Linux state selection; final gates pending |
| A106 | P2 | HTTP/3 upgrade cleanup observes all owner outcomes | First failure returns before remaining owners are joined | Nine causal failures reproduce before repair; reviewed remedy passes all fourteen controls within the complete 271-test HTTP/3 binary on Windows/Linux at 2b4a401b; focused checks pass; final gates pending |
| A107 | P2 | HTTP/3 captures bound total retained stream data | A per-stream byte limit leaves stream count and combined bytes unbounded | Five intended Windows baseline failures and four positives; independently reviewed remedy passes 66 composed methods and focused Python checks on Windows/Linux; final gates pending |
| A108 | P3 | Route models use one ECH type and readable validation | Identical ECH type repeated; facade exports follow modules and independent guards run together | Four owner reads and layout differential independently reviewed; eight initial focused stages plus later three network and thirty facade route controls pass per host; final gates pending |
| A109 | P3 | Cache tests observe pending lookup selection | Scheduling yields and a sleep do not prove concurrent sharing or pre-clear registration | Three existing controls strengthened; release-order review finding corrected; all 42 cache tests and focused checks pass on Windows/Linux at 2b4a401b; no measured historical flake or production defect claim; final gates pending |
| A110 | P2 | Remaining H2 test peers retain failures and ownership | Raw cancellation peer/upload and lifecycle peers skip joins on early errors; several causes become text | Reviewed fixture repair passes all 195 selected H2 tests on Windows/Linux at fd7ef84e, including the formerly backend-masked case; historical baseline retained; final gates pending |
| A111 | P3 | Facade exports and unit tests follow their owners | Root exports are scattered around modules; error tests occupy 431 inline lines; DNS category wording omits direct TCP lookup | Reviewed twenty-test move and export grouping pass twenty-two selected tests and all eighteen focused Windows/Linux stages at 7af60ef1; two stale API inventories refreshed and independently approved at 96ee6074; final gates pending |
| A112 | P3 | H2 owner checks have readable operation boundaries | Request validations, reuse checks and driver guards run into independent work | Two complete production owner reads; independently approved twenty-blank-line remedy composed at 4dd43eac; nonblank bytes unchanged; final gate pending |
| A113 | P3 | Review evidence attributes have one rule per behavior | Thirty-four file-specific JSON rules repeat the existing wildcard | Independently approved attribute-only remedy composed at 45a3ad77; effective attributes identical for 2,433 tracked paths and three future probes; final gate pending |
| A114 | P2 | WebSocket routing peers retain ownership and completed failures | Raw handles detach on early return or outer cancellation; the first peer error skips its sibling | Independently reviewed repair passes all 42 selected WebSocket methods on Windows/Linux at 43fe668c; focused checks pass; final gates pending |
| A115 | P3 | WebSocket fixture deadlines preserve Elapsed | Shared and H2 proxy wrappers replace the timer cause with text | Typed deadline and operation-context repair independently approved; all 42 selected WebSocket methods and focused checks pass both hosts; final gates pending |
| A116 | P2 | Upgrade control construction owns supplied peers | Fallible identity and endpoint setup precede the fixture owner | Reviewed eager acquisition repair passes all eleven owner-result methods on both hosts at 43fe668c; frozen controls preserved; final gates pending |
| A117 | P2 | CONNECT-UDP test origins own connection and response tasks | Listener discards child handles and outcomes; stalled responses remain pending | Reviewed ownership and typed-result repair passes all 39 origin methods on each host at 482e75dd; four original regressions pass; historical Linux reuse failure remains qualified; final gates pending |
| A118 | P2 | SOCKS test peers retain ownership and sibling failures | Raw tasks surround fallible setup and client work; sequential joins skip remaining failures | Independently reviewed ownership and result repair passes all 31 selected methods on Windows/Linux at 6d6cd85e; original eight failures and TLS acquisition assertion-order limits remain recorded; final gates pending |
| A119 | P3 | Proxy fixture deadlines preserve Elapsed | Four CONNECT-UDP and SOCKS timer paths replace causes with text | Reviewed typed operation-context repair passes 33 CONNECT-UDP and twenty SOCKS methods per host at 593fc4ae; focused checks pass; body/counter expiry paths retain source-only failure evidence; final gates pending |
| A120 | P2 | CONNECT-UDP zero-retry assertions require trace outcomes | An empty result vector satisfies the current all-zero predicate | Corrected baseline reaches absent-observer failure on both hosts; reviewed terminal-outcome predicate passes native proxy selection; original invalid initial-zero expectation retained separately; final gates pending |
| A121 | P3 | Client setting tests name their actual coverage | TCP propagation test omits independent checks of several clones; imports need grouping | Reviewed explicit connector assertions pass on both hosts at 43fe668c; configuration propagation only, no OS socket application claim; final gates pending |
| A122 | P2 | H2 resets after terminal connection failure release streams | A lower duplicate reset returns early while its outer action re-enrols the failed stream for expiration | Reviewed canonical repair and fork identities pass 195 selected H2 tests and both HTTP vendor scripts per host at fd7ef84e; package late-reset case passes; two unexpected facade failures keep the combined candidate nonzero |
| A123 | P2 | Local SOCKS fixtures own peers and retain both results | Six raw origin/proxy pairs span fallible work and cancellation; origin failure skips proxy completion | Independently reviewed eager local setup ownership passes all twenty local methods within the 51-method Windows/Linux SOCKS selection at 1e23deb9; both pretransfer destruction witnesses now pass; final gates pending |
| A124 | P2 | Local SOCKS assertions observe IP address representation | CONNECT decoding erases ATYP; numeric domain-form loopback satisfies the local-IP assertion | Independently reviewed typed observation repair passes all five target controls and migrated callers on Windows/Linux at 81c61f13; no client DNS defect inferred; final gates pending |
| A125 | P3 | Proxy fixture deadlines retain Elapsed | Local SOCKS, forward, negotiated, credential and field-order outer bounds replace the timer cause with text | All local, forward, credential, negotiated and field-order concrete Elapsed controls pass on both hosts at their recorded revisions; nineteen negotiated and twenty-two field focused runs are green; final gates pending |
| A126 | P2 | Forward-proxy fixtures own request and peer tasks | Raw peers, queued requests and transferred leftover readers can lose ownership or sibling results | Reviewed complete forward remedy and finite-read follow-up pass all 49 forward methods on Windows/Linux at ff1d8452; lexical queued ownership remains source-confirmed without a new cancellation control; final gates pending |
| A127 | P2 | Forward response observers own handlers and report failure | Supervisors detach response tasks; poisoned observation locks silently skip writes | Reviewed accepted-handler and observer repair passes all 49 forward methods on Windows/Linux at ff1d8452, including cancellation, completed partial-head and poisoned recording controls; final gates pending |
| A128 | P2 | Forward absence assertions distinguish failed reads | Read and timeout outcomes are discarded before empty buffers support no-replay assertions | Both injected reader-error controls and finite quiet-window positives pass in the 49-method Windows/Linux forward selection at ff1d8452; injected faults do not establish OS failure; final gates pending |
| A129 | P3 | Proxy fixtures group imports and operations | Local imports precede standard/external groups; several guards run into independent output | Local, forward, credential, negotiated and field-order layout repairs have independent source review and focused Windows/Linux checks; final gates pending |
| A130 | P3 | Early-response ownership control bounds retain Elapsed | Three outer control wrappers discard their timer error while adding context | Actual 12-second baseline fails on both hosts; reviewed existing PeerDeadline reuse passes all six controls on each host at 482e75dd; final gates pending |
| A131 | P2 | H3 MASQUE test relays survive an oversized origin payload | TooLarge ends the whole proxy handler instead of dropping one UDP payload | Actual diagnostic retains TooLarge on both hosts; oversized baseline fails while ordinary forwarding and protocol-error controls pass; reviewed narrow repair passes ten proxy controls and both original WebSocket failures per host at 482e75dd; final gates pending |
| A132 | P2 | Alt-Svc and negotiated callers observe completed secondary peer failures | Request and body errors return before explicit peer or fixture finish | Forty-four Alt-Svc and nineteen negotiated methods pass on both hosts; actual truncated-body primary and completed origin secondary objects are retained and formerly unreached assertions now pass; final gates pending |
| A133 | P3 | Snapshot tests separate independent cases | Persistence round-trip and validation loops run into different cases and observations | Three paragraph boundaries corrected with independently reviewed Alt-Svc repair; no behavioral test added; final gate pending |
| A134 | P2 | Credential fixtures own accepted handlers and report their failures | Two accept loops discard handler handles and turn accept failure into successful completion | Reviewed credential ownership and direct join propagation pass all seventeen methods on Windows/Linux at 1e23deb9, including actual relay/incomplete-TLS cancellation and concrete completed CONNECT/TLS causes; accept errors remain source-only; final gates pending |
| A135 | P2 | Credential observation failures remain errors | Counts substitutes empty heads after poison; both writers skip poisoned locks and continue responses | Reviewed concrete observer failures pass all seventeen credential methods on Windows/Linux at 1e23deb9, including literal challenges, authenticated traffic and all poisoned observers; final gates pending |
| A136 | P2 | Field-order exchanges own peers and preserve secondary failures | Raw server handles span fallible client work and success-only joins | Reviewed ownership and result repair passes all twenty-two field methods on Windows/Linux at ed320379, including driven/unpolled cancellation and concrete combined failures; original eleven-pass/seven-failure baseline preserved; final gates pending |
| A137 | P3 | Negotiated challenge documentation describes connection reuse | Comment says fresh connection while the test requires challenged-connection reuse | Challenged-connection reuse wording corrected and independently source-approved; all nineteen negotiated methods pass Windows/Linux; final gates pending |
| A138 | P3 | CONNECT field tests propagate preparation errors and classify expected failures | Tunnel helper skips construction errors and discards every send result; WebSocket opening discards outcomes | All twenty-two field methods pass Windows/Linux at ed320379; typed template/HTTP/WSS 502 causes retained, both deliberate 200-close positives pass, and actual untrusted-certificate error now propagates after its real TLS prerequisites; intermediate nineteen-pass/three-failure baseline preserved; final gates pending |
| A139 | P3 | Environment tests use the existing peer owner directly | Two aliases and passthrough spawn helpers repeat ConnectionPeer without adding behavior | Independently reviewed removal preserves all operation tokens and 21 methods; all 14 proxy and seven streaming environment methods pass Windows/Linux at 1e23deb9; final gates pending |
| A140 | P3 | Sanitizer comments describe the tested FFI boundary | The opening calls QUIC the only permitted unsafe crate, omitting the audited network socket boundary | Comment correction independently approved; complete workflow source and unchanged executable bytes verified; no runtime change; final gates pending |
| A141 | P2 | H2 proxy callers own peers and preserve secondary outcomes | Raw peer handles cross fallible setup and success-only joins | Independently source-reviewed external CONNECT owner and corrected rejection callers pass all 100 H2 methods on both hosts at `a0d2c622`; actual completed relay plus primary cause assertions now pass; independent focused native assessment approved; final gates pending |
| A142 | P2 | H2 proxy fixtures own listeners, drivers and relay descendants | Several forwarding, CONNECT and multiplex tasks detach without shutdown owners | All 100 H2 controls pass on both hosts at `a0d2c622`, including acquired-owner cancellation and explicit completed-child results; Drop remains abort-only and cleanup finite; independent focused native assessment approved; final gates pending |
| A143 | P2 | H2 proxy fixtures retain unexpected transport causes | Accept, body, relay and capacity errors become ordinary termination or disappear | Source-reviewed backend CANCEL classification repairs both ordinary regressions at `d983ad7e`; all 100 frozen H2 cases pass at `a0d2c622` on both hosts, including unrelated I/O/reset causes; no blanket InactiveStreamId suppression; independent focused native assessment approved; final gates pending |
| A144 | P3 | H2 proxy deadlines retain Elapsed | Both ten-second wrappers replace the concrete timer cause with strings | Reviewed concrete deadline repairs pass both actual expiry controls within all 41 H2 methods on Windows/Linux at 2cea08af; independent native review approved; final gates pending |
| A145 | P2 | H2 proxy recording failures remain errors | Poisoned observations become empty results or silently skip writes | Source-reviewed wrapper exposes the retained backend I/O source; ordinary and multiplex poison controls pass within all 100 H2 methods on both hosts at `a0d2c622`; ordinary control proves I/O type without specific payload identity; independent focused native assessment approved; final gates pending |
| A146 | P2 | Deliberate H2 CONNECT rejections retain their expected category | Three 502 workflows discard every HTTPS or WSS result | Typed actual 502 and substitution controls remain green after independently reviewed rejection scaffold migration at `a0d2c622`; all 100 H2 methods pass both hosts; independent focused native assessment approved; final gates pending |
| A147 | P3 | Remembered HPACK credentials prove dynamic indexing | A valid literal-name field without indexing satisfies the remembered predicate | Both literal-credential negatives reproduced at 3c5ca80e; source-approved exact credential-position remedy passes all 41 H2 methods on Windows/Linux at 2cea08af; independent native review approved; final gates pending |
| A148 | P2 | H2 capture helpers reject malformed input explicitly | Unchecked hex, priority and integer/string arithmetic can panic or accept truncation | Six parser negatives reproduced before repair; added signed +1 gap reproduced at 3c5ca80e; source-approved bounds and strict digits pass all 41 H2 methods on Windows/Linux at 2cea08af; independent native review approved; final gates pending |
| A149 | P3 | H2 proxy fixtures group imports and independent operations | Both owners have mixed import groups and dense operation boundaries | Independently reviewed lexical blocks remove introduced closure diagnostics; combined strict Clippy passes at `42858688` on both hosts; final gate remains pending |
| A150 | P2 | Field capture hexadecimal is validated before slicing | UTF8 byte slicing panics and radix parsing accepts signed pairs | Both actual negatives reproduced at `623e18fd`; reviewed narrow ASCII validation passes all twenty-two field methods on Windows/Linux at ed320379; private fixture parser only; final gates pending |
| A151 | P2 | Cookie capture helpers reject malformed data | Unchecked HPACK arithmetic, short priority slicing, partial frames, signed hex and unknown Huffman flags | Seven actual parser negatives reproduced at 76f86667; reviewed repair passes all seventeen previous cookie methods at 767c116a and 2cea08af on both hosts; 767c116a native independently reviewed; final gates pending |
| A152 | P2 | Cookie exchange tasks remain owned and retain sibling failures | Raw server handles cross fallible work; completed client/server causes become text or are skipped | Source-approved eager ownership and explicit cleanup at 211099a6 pass all thirty unchanged methods on both hosts at 2fb596ad, including previously unreached typed aggregate assertions; independent native review approved, final gates pending |
| A153 | P3 | Cookie fixture timers and receivers retain concrete causes | Elapsed and receiver failures become strings | Source-approved contextual Elapsed and RecvError repair passes actual receiver and both expiry controls on both hosts at 2fb596ad; independent native review approved, final gates pending |
| A154 | P2 | Cookie H2 recording reports unexpected driver failures | Final poll_closed result is ignored before observations are returned | Source-approved narrow get_io disconnect classification passes healthy-close and unrelated final-read controls on both hosts at 2fb596ad; fixture-only repair, final gates pending |
| A155 | P3 | Cookie fixtures group imports and independent operations | Local import precedes standard/external imports; several independent operations run together | Current complete 825-line manual source and independent review approve narrow import/operation cleanup at 211099a6; thirty methods pass each host, final gates pending |
| A156 | P2 | Public CONNECT callers own peers and retain completed siblings | Raw handles span fallible preparation and success-only sequential joins in both public fixture owners | Source-approved eager ownership and explicit cleanup pass all 106 selected methods per host at 602284c2; derived public CONNECT subset has 24 passes, including all previous failures; independent native assessment approved, final gates pending |
| A157 | P3 | Public CONNECT deadlines retain Elapsed | Shared five-second wrapper replaces the concrete cause with text | Actual paused expiry now retains Elapsed on both hosts within the unchanged 602284c2 selection; independent source/native review approved, final gates pending |
| A158 | P3 | Public CONNECT fixtures group imports and independent operations | Redundant auth path and mixed import/operation groups hinder reading | Complete current six-owner root review and independent source assessment approve cleanup; 602284c2 focused checks pass both hosts, final gates pending |
| A159 | P2 | Every named trust-anchor connector has an actual observation | Aggregate capture counts allow duplicate observations from one operation to substitute for another | Actual equal-total substitution fails observer rejection at d0a45c1e on both hosts; reviewed named nonempty-batch remedy at 1ac70fe1 passes all four methods with default/all features on both hosts; no missing production connector claim, final gates pending |
| A160 | P2 | Cookie and hint fixture tasks remain owned on all exits | Raw server, proxy and request handles span fallible work | Cookie ownership remains separately verified. Hint remedy at `d9418c3a` passes the unchanged 44 methods on both hosts after the seven causal baseline failures; independent source/native approval retains finite destruction and completed ALPS error scope. Final gates pending. |
| A161 | P2 | Cookie redirect cleanup observes both H2 drivers | Raw drivers are aborted without inspecting completed outcomes | Cookie redirect remedy passes all five controls and concrete first/second/combined causes on both hosts at `42858688`; independent source and native approval; compiler-only history retained; final gates pending |
| A162 | P3 | Cookie and hint expiry retains concrete Elapsed | Both contextual wrappers substitute text | Two actual paused expiry failures at33715620 become green after reviewed private wrapper repair at85f2d58b on both hosts; all31 selected methods and focused checks pass; independent native review approved, final gates pending; existing client A92 remains separate |
| A163 | P2 | ALPS quiet observation preserves accept errors | Only a successful unexpected request is rejected | Actual postresponse read control fails at `71176f08` after its real exchange and invoked reader; two-arm remedy at `c12d5f49` passes all 53 selected methods on both hosts, retaining typed H2/IO cause; independent source and native approval; final gates pending |
| A164 | P2 | Hint admission tests observe readiness before learning | A fixed sleep substitutes for actual preparation/admission readiness | Independent source-reviewed49c remedy integrated at8fb; actual same-key HTTP2 Capacity establishes the retained request's pending reservation. All33 selected hint methods,fmt/strict Clippy/Rust1.88 pass both hosts. No historical flake or production failure claimed; final gates pending. |
| A165 | P2 | Hint order assertions observe decoded ordinary wire order | HeaderMap keys have arbitrary unique-name order | Reviewed decoded-order observer passes both actual H2/H3 negatives within all 41 methods on both hosts at `121bbf19`; independent focused native assessment approved, missing/mismatched extensions remain errors; final gates pending |
| A166 | P3 | Learned hint assertions check actual values and absence | High-entropy positives test presence; H1 absence checks only an expected literal | Reviewed exact singleton-value and complete-absence assertions pass all four actual-client negatives within all 41 methods on both hosts at `121bbf19`; independent focused native assessment approved, positives preserved; final gates pending |
| A167 | P3 | Request fixtures group imports and use one drain helper | Local imports precede external imports; two hint helpers have identical operations | Narrow import and duplicate-helper cleanup independently source-approved and committed at `f78f63ca`; exact inverse preserves all other source and five children. No behavior change or crate split; later combined compilation pending. |
| A168 | P2 | Received H3 requests retain documented ordered headers | Request parts and resolver discard the decoded ordinary sidecar | Real QPACK baseline 772b9c73 fails both order controls; reviewed named RequestParts and resolver repair at e6f01439 passes all three controls on both hosts; Linux full vendor check and Windows package checks pass; Windows archive replay unavailable locally, final gates pending |
| A169 | P2 | Trust-rejection server assertions distinguish unrelated failures | Three CONNECT TLS servers accept any handshake failure | Reviewed cause-specific trust repair passes all29 selected proxy methods on both hosts at1690; independent native assessment approved. That batch lint/MSRV failed on unrelated prepared imports; later0418 combined focused checks pass. Final gates pending. |
| A170 | P2 | ALPS capture startup and readers finish or return retained failures | Silent startup has no deadline; a live/failed reader can still publish a partial fixture | Independent source-reviewed completion witness repair passes all18 focused methods on both hosts at6c98, including unchanged Windows deadline. Earlier deadline failure cause unknown; broader socket warnings and final gates remain |
| A171 | P2 | ALPS NetLog events belong to the exact capture origin | Hostname substring accepts foreign host, path/query and HTTP scheme | Exact HTTPS host/port matcher and all foreign-origin controls pass within18-method repaired runs on both hosts at6c98; final gates pending |
| A172 | P2 | TCP missing-certificate rejection has a cause-specific witness | Any serve_one failure and coarse request category satisfy the negative | Cause-specific TCP observer source-reviewed; TLS12/TLS13 wrong-authority controls and actual missing-certificate positive pass within all43 certificate methods on both hosts at1088701d. Original causal failures retained; final gates pending. |
| A173 | P2 | QUIC missing-certificate rejection retains its server outcome | Server result is discarded and client Tls/Http3 category is broad | Cause-specific QUIC observer and corrected input-specific DecryptError prerequisite source-reviewed. Original missing-certificate positive and wrong-authority negative pass within all43 certificate methods on both hosts at1088701d. Historical843 prerequisite failure retained; final gates pending. |
| A174 | P2 | Certificate proxy callers observe completed peer failures | Two HTTPS-proxy and two WSS callers return early and rely on abort-only Drop | Four completed-peer controls and two additional inline request/origin regressions pass unchanged on both hosts at1088701d after causal baselines. Independent source and native reviews approve retained typed causes and finite explicit cleanup. All43 certificate and489 request methods pass both hosts; final gates pending. |
| A175 | P2 | First capture cleanup interruption keeps its original identity | Cleanup wraps the first KeyboardInterrupt instead of returning it | Original cleanup interruption identity and secondary failure/publication controls pass both hosts at6c98; independent source and native reviews approved. Earlier Windows deadline failure cause remains unknown; final gates pending. |
| A176 | P2 | Prepared-body peers retain ownership and every outcome | Fallible requests precede success-only joins; first sibling failure skips another result | Corrected332 baseline reaches three causal failures after actual wire traffic; reviewed eager ownership and completed-error remedy passes all19 unchanged controls on both hosts at0418. Independent source/native approval; finite lifetime witness; final gates pending. |
| A177 | P2 | Known form-body size is checked before fixture allocation | Redirect peer allocates from Content-Length before requiring literal a=b | Reviewed fixture remedy requires known literal form length3 before allocation; ordinary upload controls pass both hosts at0418. Static allocation ordering verified; no adversarial huge allocation attempted; final gates pending. |
| A178 | P2 | Scripted proxy client closes acquired connections | Task cancellation leaves both client stream writers unclosed | Reviewed acquired-writer cleanup retains original exception chains; all32 focused controls and isolated traced proxy method pass both hosts at0418. The separate remote fixture warnings also disappear in the later d27 capture runs. Final gates pending. |
| A179 | P2 | Browser remote fixtures own accepted peers and cleanup on failed operations | Listener-only close and success-only callers miss accepted handlers, writers and results | All six canonical controls fail causally at496 on both hosts. Independently reviewedcf1 repair integrated atd27; all23 unchanged methods pass both hosts without ResourceWarning. Full capture passes461 Windows and450 plus11 skips Linux without warnings. Final gates and combined audit remain pending. |

| A180 | P2 | HTTPS-record ECH fixture tasks remain owned on every exit | Negotiated raw tasks, exact active handshakes and QUIC TCP descendants escape exceptional ownership | Parallel repair passes seven frozen controls and the wider 66-method selection on both hosts at `5973305d`. The TCP baseline at `fa97832b` has one healthy pass and two pre-backup child-destruction failures per host. After independent review, all eighteen TCP/count/deadline/ordinary controls pass at `1f5c128b`, reaching child and parent destruction and socket closure. Formatting, strict test-target Clippy and Rust 1.88 checks pass both hosts. The later QUIC coordinator repair at `145552a1` passes all eight unchanged ownership controls and all 29 composed methods on both hosts, with independent source and native approval. Pending handshake stop and origin-drop destruction are observed before backup. Exact serving cancellation, beyond-budget outcomes, broader TCP classification and final gates remain open. See `quic-coordinator-root-checkpoint-145552a1.json`. The exact normal-finish baseline at `15c0dc79` passes two owner controls and fails the typed pending-handshake finish deadline on both hosts. The source-reviewed stop selection at `e8069b42` passes all 26 exact-module methods on both hosts, reaching unchanged pre-backup destruction and socket closure. Strict focused Clippy and Rust 1.88 checks pass both hosts. See `exact-ech-normal-finish-root-checkpoint-e8069b42.json`; serving cancellation, QUIC budgets and final gates remain open. |
| A181 | P2 | ECH fixture finish retains completed serving failures | Sequential early returns and abort-without-join discard completed concrete child outcomes | Earlier exact collector repair passes 52 unchanged controls. Parallel collection retains ordered typed failures and client-primary plus worker-secondary failures: seven frozen controls and the wider 66-method selection pass both hosts at `5973305d`. TCP collection now owns and drains accepted workers; eighteen selected controls pass both hosts at `1f5c128b`, including the original lifetime controls and typed count deadlines. Independent source/native review approved. At that checkpoint, completed TCP faults remained unverified. Completed TCP cancellation and typed panic controls now pass within all 21 selected methods on both hosts at `9803513f`; strict focused quality checks pass. At `145552a1`, the reviewed QUIC coordinator retains both simultaneous concrete serving errors, client-primary plus completed-worker errors, and actual externally cancelled JoinError identity. All eight unchanged controls and 29 composed methods pass on both hosts; formatting, strict focused Clippy and Rust 1.88 checks pass. Beyond-budget outcomes, broader TCP classification and final gates remain open. See `quic-coordinator-root-checkpoint-145552a1.json`. |
| A182 | P2 | HTTPS-record fixture deadlines retain their typed causes | Four outer bounds and QUIC count waits replace Elapsed with text | Independently reviewed count repair at `3a68a39f` passes the unchanged 57 methods on both hosts, including both previously failing typed Elapsed assertions. Original 20-second waits, messages and earlier 52 methods remain. Controls use private counter/task state; final gates pending. |
| A183 | P3 | No-direct-DNS route controls own the refusal address | Fixed loopback port9 is assumed to have no listener | Independent source-approved existing ReservedPort correction integratedd862 and passes within50 HTTPS methods both hosts at aed. Windows/Linux retain bound ports; existing macOS helper releases them. Original Proxy category/zeroDNS assertions preserved; final platform CI pending. |
| A184 | P3 | QUIC ECH fixture acquisition retains local-address failure | Endpoint local_addr error becomes port0 after TCP task acquisition | Pre-spawn local-address acquisition independently source-approved at `f0939302`; all seven ordinary QUIC methods compile and pass within the unchanged 52-method selection at `e8a0c593` on both hosts. No measured OS lookup fault or production defect; final platform gates pending. |

| A185 | P2 | QUIC analyzer summaries obey their persisted STREAM-space contract | Authenticated Initial/Handshake STREAM metadata is published but rejected by the strict loader | Both-host19 baseline reproduces17/2 after literal decode/publication/reload prerequisites. Narrow8c analyzer repair passes unchanged19 and full465 capture methods on Windows; Linux454 plus11 platform skips. Independent source/native review approved; integratedc8f7 with complete capture tree equal to verified8c. Final gates pending; no live-browser or full-QUIC validation claim. |
| A186 | P2 | Remote upgrade and close retain acquired socket cleanup | Upgrade failures/cancellation and completed reader errors bypass writer closure | Independently reviewed final owner passes all 35 focused methods on both hosts at `e4544b67`; unchanged upgrade-writer, completed-reader and navigation primary/cleanup assertions now pass. Full capture selection passes 477 Windows and 466 plus11 platform skips Linux. Controlled faults; browser-driver cleanup is separate A196. Final gates pending. |
| A187 | P2 | Remote pending commands retain causes and leave no stale entries | Read failures become strings; send/call failures leave pending state | All unchanged original-cause, pending-completion and failed-send/cancel/15-second-timeout assertions pass on both hosts at `e4544b67`. The extra unsolicited-handler control proves actual failed-reader identity and socket closure after an intermediate 34/1 baseline. Independent source/native approval; final gates pending. |
| A188 | P2 | Browser launcher cleanup attempts independent owners | Entry termination failure skips profile removal; exit termination failure skips profile-process discovery and replaces initiating errors | Independent source/native review approves the seven synchronous and two deferred executor controls. Full capture suite at `dcb664a5`: Windows 495 pass; Linux 484 pass plus 11 platform skips. Capture sources are exact through `5973305d`. Deferred faults retain the actual Future and initiating cancellation in the explicit report. Undriven removal-error combinations and other stated boundaries remain open. Final gates pending. |
| A189 | P2 | Race capture owns partial startup resources | Socket/listener acquisition precedes the protecting cleanup region | Eight startup and five lower-allocation closure/error-retention failures reproduce on both hosts. Reviewed repairs pass the unchanged nine startup and six allocation controls, then the full 510-method capture selection at `4074c370`: Windows 510 pass; Linux 499 pass and eleven platform skips. The initial Windows socket harness faults remain separate. Later interruption, accepted-task and handler-scope repairs are recorded in A197, A190 and A198. Classification and remaining combinations stay open; final gates pending. |
| A190 | P2 | Race TCP listener owns accepted callback outcomes | Writers are tracked but accepted tasks and completed outcomes are not | Complete control review and independent native review confirm one healthy pass and two causal failures per host at `55b26d84`: close returns before the actual pending handler finishes, and capture loses a completed handler's escaped error. Its closed-time assertion is unreached in that baseline. Partial-peer policy is retained. The reviewed accepted-owner repair passes all 23 focused controls at `c07aba49`, then the full capture suite at `9803513f`: Windows 518 pass; Linux 507 pass and eleven platform skips. Original completion, closed-time and escaped-failure assertions now pass. Deadline and late-callback limits remain qualified; concurrent handler scopes and serving-start branches still need investigation. Final gates pending. |
| A191 | P2 | Race capture distinguishes clean closure from unrelated failures | Broad TLS, transport and H2 exception handling produces ordinary termination | Earlier read/send repair passes four controls and the 31-control composition at `d2bfd093`. The next corrected baseline has six passes and two exact local-reader cause failures per host. At `c5fe57a8`, all eight unchanged controls pass, including original cause identity and record tags; deferred H2 responses retain their original owner when another H2 or H3 peer releases them. Full capture: 534 Windows passes; 523 Linux passes and eleven unchanged platform skips. Independent comparison preserves all 526 prior outcomes and order. Windows slow-task and expected parser diagnostics remain qualified. Flush/BIO/ALPN, other established TLS/reset categories, concurrent scopes and final gates remain open. See `tls-peer-errors-root-checkpoint-c5fe57a8.json`; no whole A191 closure. The reviewed cross-peer retirement repair at `13ba3a93` passes all six controls on both hosts and the full554 capture selection (Windows554; Linux543 plus11 skips). Original owner tags, raw ordinary errors and later retirement are verified with controlled post-write faults. Original format1 results remain preserved; the layout-only `83f793cf` follow-up passes the same six controls and capture lint/format on both hosts. Full554 execution applies only to13ba. See `retirement-root-checkpoint-83f793cf.json`; broader classification and final gates remain open. |
| A192 | P2 | UDP race observations retain listener identity | One source address merges origin and earlier-alternative observations | Independently reviewed listener/address lookup passes all 15 focused methods on both hosts at `c0dc392b`, after the same 13/2 baseline at `14e43021`. Callback and synthetic-path controls preserve literal totals and distinct stable peer records. Browser occurrence and QUIC connection-generation identity unmeasured; final gates pending. |
| A193 | P2 | Remote credentials omit values in default diagnostics | Default dataclass representation includes username and password | Both benign username/password assertions pass unchanged on both hosts at `e4544b67` after the causal password-repr failure. Independent source/native approval; no real disclosure or broader redaction claim. Final gates pending. |
| A194 | P2 | Test controls compile across optional feature sets | Ordinary tests rely on optional futures-util; two boxed error conversions fail strict Clippy | Signed `c0794ff4` adds the already pinned test dependency and removes two identity conversions. Independent source review and both-host workspace Clippy, Rust 1.88 and JSON-only all-target checks pass at `3a68a39f`; all four upload controls pass. PR CI and final gates pending. |
| A195 | P2 | Repeated test migration preserves every registered module | Two new modules are absent from GROUPS, failing its guard and existing-module lookups | Exact two-entry roster repair independently approved at `fd518ed0`; unchanged 16-method targeted baseline reproduces two missing-module subtests. All 35 development methods pass on both hosts after installing Linux's missing stable formatter. PR CI and final gates pending. |
| A196 | P2 | Proxy browser driver cleans up all acquired owners | Remote close failure skips browser exit; cancellation during remote startup leaves the entered browser outside context cleanup | Fixed owner and unchanged seven controls pass both hosts at `59634fd7`, after corrected `52bf59cb` baseline failed five causal cases. Independent source and focused native reviews approve resource closure and exact original/ordered cleanup retention. Full capture suite passes 486 Windows and 475 plus11 platform skips Linux. Constructor/callback and other browser paths remain undriven; inherited synchronous cleanup has no new total deadline. Final gates pending. |
| A197 | P2 | Race cleanup retains control-flow interruptions | Multiple cleanup failures without an operation primary wrap cancellation or interruption in an ordinary exception | Independently confirmed source branch in the startup remedy. Four actual-resource identity failures reproduce on each host at `1ba43ba0`. The unchanged five controls pass after the reviewed repair at `1df5404c`, followed by the full capture suite: Windows 515 pass; Linux 504 pass and eleven skips. An import-only correction preserves all test bodies and passes five focused controls on both hosts at `69b42db8`. Undriven interruption combinations and final gates remain open. Accepted-task repair is recorded in A190. |
| A198 | P2 | Race capture preserves the caller's loop handler | Capture replaces the handler permanently and bypasses it for unrelated callback failures | Four original controls fail causally on both hosts at `cb5a7d14`. The independently reviewed repair at `6fee7a53` scopes the reset filter, forwards the original unrelated context and restores the exact previous handler. All 27 related controls pass on both hosts; full capture runs pass 522 on Windows and 511 with eleven platform skips on Linux. None-handler and cleanup-only cases remain source-assessed. At `75606714`, overlapping scopes reproduce two passes and two causal failures per host. The independently reviewed repair at `e57dade6` passes all four unchanged controls and twenty related methods on both hosts. Full capture passes 538 on Windows and 527 with eleven platform skips on Linux; every previous method retains status, skip reason and relative order. External handler replacement, more than two scopes, retained closed-node dispatch and remaining capture branches stay source-assessed or open. See `handler-overlap-root-checkpoint-e57dade6.json`. See `handler-scope-root-checkpoint-6fee7a53.json`; final gates pending. |
| A199 | P3 | Maintainer instructions reflect current repository authorities | A removed page-banner rule, boot-specific port range and stale CodeQL language comment remain in instructions | Independently reviewed text corrections at `59d29568` follow the documentation and Windows-host guidance and the configured CodeQL languages. Both instruction files and the configuration were read completely; non-comment configuration bytes are unchanged. See `instruction-authority-correction-independent-review-cb5a7d14.json`; no skill or browser execution is claimed. |
| A206 | P2 | Loopback QUIC test contexts close owned resources and retain failures | Cleanup errors skip transport closure, replace initiating errors and overwrite nested causes; failed shutdown retains timers and a pre-close queued callback | Independently reviewed repairs pass all ten unchanged controls on Windows and Linux at `8b544ea1`, including native lost-callback/socket closure, actual timer cancellation, queued-work ownership and original error identities. Full capture has 548 Windows passes and 537 Linux passes plus 11 unchanged platform skips. All prior 538 names retain status, relative order and skip text; pinned Ruff checks pass both hosts. Historical failures and backup visibility limits remain preserved. No universal callback drainage, new wait deadline or production-client defect is claimed; final gates pending. |
| A207 | P2 | Invalid capture repetition preserves existing output | Zero and negative Alt-Svc repeat counts skip capture and replace the fixture | Both-host baseline at `4b1533a6` observes two causal missing-rejection failures, actual temporary fixture replacement and NetLog directory creation; positive dispatch passes. Reviewed guard at `b08163ee` passes all three unchanged semantic controls and six retirement controls. Full capture: Windows557; Linux546 plus11 unchanged skips; lint/format pass. No real browser is launched by the CLI controls. Original failures remain recorded; final gates pending. See `cli-logical-source-root-checkpoint-b08163ee.json`. |
| A208 | P3 | Logical summary operations have readable paragraph boundaries | Independent input guards, conversion and output run together in two files | Complete four-owner source review records the grouping gaps. Reviewed `854839b4` adds seven blank lines across the comparison and projection owners; complete source ASTs and all statements remain identical. Targeted lint/format pass. No functional defect or new behavioral test is claimed; final gates pending. See `cli-logical-source-root-checkpoint-b08163ee.json`. |
| A209 | P2 | Refused Android captures perform no mutating commands | Entry refusal precedes acquisition, but unconditional exit force-stops the selected browser | Reviewed ownership repair preserves the original refusal and no-mutation assertions. All 63 synchronous Android methods pass on both hosts at `802517fa`; original b8 failures remain recorded. Required-query failures are separate A217. See `android-synchronous-followup-root-checkpoint-802517fa.json`; final gates pending. |
| A210 | P2 | Android configuration cleanup owns a started upload | Configuration ownership is recorded after push, local cleanup and chmod all return | Reviewed repair owns local preparation and remote publication separately. The unchanged three added controls now retain original simultaneous failures, clean actual local material and preserve prior remote state on preparation failure. All 63 synchronous methods pass both hosts at `802517fa`; device state is modeled. Final gates pending. |
| A211 | P2 | Android shutdown attempts independent actions and retains initiating failures | The first cleanup exception skips later actions; failed-entry cleanup can obscure the initiating error | Reviewed repairs retain ordered original errors, initiating failures and failed ownership slots. Six original aggregation/retry failures now pass; six rejected-status controls change from one pass/five causal failures at `115c03af` to all passing at `802517fa`. All 63 synchronous methods pass both hosts, including only-failed-action retries. Other unchecked queries and async ownership remain separate; final gates pending. |
| A212 | P2 | Direct Android launch attempts reject nonpositive counts before setup | Nonpositive counts allow setup with no opening attempt | Reviewed constructor validation passes unchanged zero/negative rejection and no-command assertions in all 63 synchronous methods on both hosts at `802517fa`. One-attempt positive and ordinary default remain. Final gates pending. |
| A213 | P2 | Async Android captures keep the serving loop available and own worker cleanup | Android entry, driver exit and proxy exit invoke blocking operations on the loop | Reviewed worker repair at bb96fc4d passes pending and completed entry cancellation, shared exits and rejected-submission recovery. The 129-method worker/proxy selection passes both hosts at 428a6010 (two Linux platform skips). Full capture at a68e171c passes 648 Windows methods and 637 plus eleven Linux skips. Original 802517fa progress failures and worker/report limits remain retained. See android-worker-ui-cli-root-checkpoint-a68e171c.json; final gates pending. |
| A214 | P2 | Alt-Svc capture waits use finite deadlines | CLI margins and direct effective budgets admit infinity and NaN | Root guard and independent review preserve zero and finite margins. Original14 baseline has eight passes/six causal failures; all unchanged14 pass both hosts at `f9210a46`, with exact rejection-before-resource and retained-output assertions. Current timeout source is unchanged, but execution remains bound to f921. Matrix process budgets remain separate; final gates pending. |
| A215 | P2 | Direct Android hold values reject before launch | Negative/nonfinite float parsing reaches device launch before sleep validation | The 1d4cc658 baseline has six passes and seven causal CLI failures on each host. The reviewed finite nonnegative guard at a68e171c passes all thirteen unchanged controls and full capture on both hosts, preserving zero, default eight and positive holds. Sleep arguments and device state are modeled; no natural duration claim. See android-worker-ui-cli-root-checkpoint-a68e171c.json; final gates pending. |
| A216 | P2 | A direct cold-boot flag applies to its launch | The CLI changes process environment permanently, including print-only mode | Reviewed per-launch forwarding through LaunchPlan to AndroidLaunch passes the unchanged print-only environment and later default-refusal controls at a68e171c on both hosts. Explicit ambient permission remains valid. All thirteen CLI controls and full capture pass; no parent-environment or hardware claim. See android-worker-ui-cli-root-checkpoint-a68e171c.json; final gates pending. |
| A217 | P2 | Required emulator and snapshot observations report command failure | Unchecked getprop status with success-shaped stdout authorizes mutation | Required getprop status checking is independently approved. Original 46ac360b four-pass/two-failure baseline is retained. All six unchanged controls pass within the reviewed worker/proxy selection and final a68e171c full capture on both hosts, including exact canonical error identity and no mutation. Ancillary command policies remain separate. See android-worker-ui-cli-root-checkpoint-a68e171c.json; final gates pending. |
| A218 | P2 | Onboarding completion uses successful focus observations | Two failed empty dumpsys results count as leaving onboarding | The original 428a6010 twelve-control UI baseline has six passes and six causal failures per host. Reviewed required-query checks at 0b1f3bcd pass all twelve controls, including failed-focus rejection and successful empty-focus completion. The same controls pass in a68e171c full capture; command results are modeled. See android-worker-ui-cli-root-checkpoint-a68e171c.json; final gates pending. |
| A219 | P2 | Typed navigation and onboarding use successful UI observations | Failed dump/read status can leave stale or success-shaped XML for Enter or taps | Five required UI query/read status checks are independently approved at 0b1f3bcd. All twelve unchanged UI controls pass both hosts, reaching original error identity and no Enter/tap assertions. Successful malformed/partial XML, Wait, onboarding and full-URL policies remain unchanged. Full capture passes at a68e171c; no persisted-device observation claim. See android-worker-ui-cli-root-checkpoint-a68e171c.json; final gates pending. |

| A220 | P2 | H3 vendor checks compare full license content on Windows | Symlink placeholders differ from the replayed archive, and native drive-letter paths fail GNU tar | Independently reviewed link staging and path normalization pass both vendor checks at `17ad91de`. Linux passes all nine controls; Windows passes seven with two symlink-privilege skips. Exact link validation and changed-license rejection remain. Original path failures are retained; full gates pending. See `h3-license-path-normalization-independent-native-addendum-17ad91de.json`. |
| A221 | P2 | ECH capture shutdown retains original TCP worker failures | Direct serving errors and the unit-returning registration discard local causes | The original owner-cause negative fails on both hosts at `664383e0`. The independently reviewed worker-result repair passes all seven serving controls and all 27 example methods on both hosts at `4c55e280`; strict example Clippy and Rust 1.88 checks pass. Formatting follow-ups and final gates remain pending. Original worker and ordered primary/worker payload identities are observed; no process-level publication or natural OS-fault result is claimed. See `origin-fallback-root-native-checkpoint-4c55e280.json`. |
| A222 | P2 | ECH QUIC capture retains serving errors and sends fatal request closes | Setup and resolver failures become successful partial captures; immediate driver Drop sends H3_NO_ERROR before the original fatal code | The independently reviewed repair at a3095217 passes all 39 unchanged capture methods on Windows and Linux. Three malformed inputs receive FRAME_UNEXPECTED, FRAME_ERROR and QPACK_DECOMPRESSION_FAILED. The controlled local-resolution error retains its type, payload and Arc identity. Record and resource prerequisites pass. Formatting, strict Clippy and Rust 1.88 checks pass. Earlier causal failures remain in `fatal-template-root-baseline-54cbca60.json`; current results are in `fatal-template-root-remedy-a3095217.json`. Additional phase policies, handoff timeout/invariant branches, natural backend faults and final gates remain open. |
| A223 | P2 | H3 relay fixtures retain local failures and outer ownership | Unit-returning relay and sniffer tasks lose I/O and child errors; raw relay handles cross fallible callers | Independently source-reviewed repair at3b39526f passes all25 early-data and seven session-resumption methods on Windows and Linux, including the unchanged relay/sniffer causal controls and ordinary consumers. Typed local failures, external cancellation and pre-backup destruction assertions pass. Strict target Clippy/MSRV pass; formatting passes at e158bcb4. Historical failing baselines remain preserved. Adjacent accepted tasks, unexercised failure combinations and final gates remain open. No natural OS-fault or complete lifecycle approval follows. See `combined-remedies-root-native-3b39526f.json`. |
| A224 | P2 | H2 fallback fixtures own every worker and collect sibling outcomes | Raw outer workers detach on exceptional exits; success-only sequential joins skip remaining results | The independently reviewed outer-worker repair at `4ed504fc` retains the existing nested-driver fix and collects refusal, serving and SOCKS sibling outcomes. All 24 fallback contracts pass on Windows and Linux, including original wire assertions and a rejected-upload control that preserves InvalidTarget and rebinds both listener ports. At `88733d8e`, the affected early-data test separately confirms the server observed the exact untrusted-issuer rejection before cleanup on both hosts. Formatting, strict target Clippy and Rust 1.88 pass. Root and independent reviewers read full logs and exact clean bindings. Drop aborts without asynchronously joining; forced cleanup timeout does not prove completed destruction. Earlier causal failures remain retained; final gates remain open. |
| A225 | P2 | H2 fallback test deadlines retain the original timer cause | The twenty-second outer wrapper replaces Elapsed with text | At `4c55e280`, both hosts pass the two ready-operation positives and fail the entered Pending/actual twenty-second expiry control at the missing original Elapsed assertion. Original context and inner-error identity are preserved. The typed remedy at `4d99e490` passes all sixteen fallback methods on both hosts, including the unchanged expiry and inner-error controls. Formatting, strict HTTP3-test Clippy and Rust 1.88 checks pass. Original failures are retained; final gates remain pending. See `fallback-deadline-remedy-root-native-4d99e490.json`. See `http2-fallback-owner-independent-source-review-664383e0.json`. |
| A226 | P2 | H2 fallback recipe observations validate the complete wire shape | The observer omits preface and SETTINGS stream validation and discards trailing setting bytes | Independent source review approves the bounded observer repair. At ab754e97, all 23 fallback methods pass on both hosts, including the three previously failing literal malformed-wire controls. Formatting, strict target Clippy and Rust 1.88 pass. Final gates remain open. No malformed client output was observed. See `fixture-owner-root-baseline-ab754e97.json` and the retained 5a766eee baseline. |
| A227 | P3 | Discovery test imports follow the standards grouping | Three local aliases precede standard and external imports | The independently reviewed three-alias correction at b1dbea6a preserves all functions and assertions. Both hosts pass formatting and HTTP3-test Clippy/MSRV at 0b018777. No behavioral test is required for this mechanical correction. See `https-record-discovery-imports-independent-addendum-0340818c.json` and `quic-response-root-native-checkpoint-0b018777.json`. |
| A228 | P2 | Discovery tests observe completion before asserting cache effects | A200ms sleep observes neither cache publication nor completed failure caching | The independently reviewed completion repair at3b39526f passes all eleven discovery methods on Windows and Linux, including held real result, failure caching and original deadline controls. The current-thread observation replaces fixed readiness sleeps without a public cache API. Cleanup retains the actual failure category and release result under one finite deadline. Formatting and affected Rust1.88 checks pass at e158bcb4; final gates remain open. No historical flake or production defect claim. See `combined-remedies-root-native-3b39526f.json` and `combined-format-root-checkpoint-e158bcb4.json`. |
| A229 | P2 | Request-template capture readers reject malformed records | UTF-8 byte slicing can panic, signed hex pairs are accepted, and duplicate record keys overwrite earlier evidence | The three actual malformed-record negatives fail before repair at37c22108 and pass after the independently reviewed ASCII/duplicate-key repair at3b39526f on Windows and Linux. All41 request-template methods pass, retaining literal repeated-header order, uppercase support and pseudo-header exclusion. Strict requests-test Clippy/MSRV pass. Final gates remain open. This is fixture infrastructure, not runtime HTTP parsing. See `combined-remedies-root-native-3b39526f.json`. |
| A230 | P2 | Authenticated proxy-session tests retain both peer owners | Raw origin and proxy tasks cross fallible setup and request operations, and the first awaited error skips the other result | Approved concrete-owner and result-composition repair at3fb68a34 passes all four controls on Windows and Linux. Original setup destruction/socket/rebind and both completed I/O cause/marker/identity assertions now pass; prior638 causal failures remain retained. Auth formatting, strict sessions Clippy and Rust1.88 checks pass. Outer timeout, panic, finite-expiry collection, partial acquisition and external-cancellation combinations remain open, along with final gates. No natural or permanent task leak was measured. See `peer-resolution-root-native-3fb68a34.json`. |
| A231 | P2 | Runtime and parallel-session fixtures retain peer failures | Uncollected listener and child tasks discard concrete outcomes; H1 read/write errors collapse into ordinary termination | Original runtime coordinator aggregation now passes all16 selected methods on both hosts after12P4F. Child and parallel repairs remain qualified by earlier receipts. Outer watchdog, multiple-child/external-cancel, H2/H3/held-thread and full integration remain open. See `reviewed-fixture-root-checks-60c2f5ef.json` and earlier runtime receipts. |
| A232 | P2 | Parallel-session fixtures own accepted peers and requests | Server Drop aborts only its accept task; serving descendants and several raw request tasks cross fallible operations | Accepted parallel peers and queued callers retain owners and composed cleanup. Runtime H1 child and ordinary coordinator repairs are qualified on both hosts; coordinator16P0. Manual/TLS/held runtime paths and final gates remain open. See prior receipts and `reviewed-fixture-root-checks-60c2f5ef.json`. |
| A233 | P3 | Fixture deadlines retain Elapsed | Runtime, parallel, template, reuse, H2 authority/idle, direct HTTP, tracing, DNS and SSE fixture mappings replace Elapsed with contextual text | The changed template/TLS/H2 authority/idle and DNS override deadline paths are repaired. At a44af645 all 101 selected fixture methods pass on each host, with quality passing at 57a9f1b0. At 33de1fc4 all 28 selected DNS methods pass on each host, including actual pending deadline cause retention; formatting passes after the whitespace-only 327f18a3 correction. No old-mapping DNS runtime baseline was executed. Two SSE mappings and other recorded deadline sites remain open, together with broader ownership and final gates. See coverage.md#native-quic-input-and-dns-deadline-checks. |
| A234 | P2 | Template reply fixtures retain malformed-head failures | The HTTP/1.1 reply loop treats every read error as a successful disconnect | The independently reviewed explicit read-error remedy at a3095217 passes all 43 unchanged template methods on Windows and Linux. The original oversized-head InvalidData kind/message and socket/rebind assertions pass. Clean EOF and all 41 earlier methods still pass. Formatting, strict Clippy and Rust 1.88 checks pass. The causal failure remains in `fatal-template-root-baseline-54cbca60.json`; current results are in `fatal-template-root-remedy-a3095217.json`. Separate A235 ownership and final gates remain open. |
| A235 | P2 | Template tests retain server owners and completed causes | Parent/default-profile raw task handles cross fallible setup, request and body operations; consuming timeouts can detach them | The six remaining raw callers now eagerly retain the existing ConnectionPeer owner and compose caller, completed-worker and original deadline causes. Root and independent whole-source review accept the repair. All 101 selected methods pass on each host at a44af645; warning-free focused quality passes at 57a9f1b0. The factory Drop control proves listener and pending-connection release, not accept readiness. Nonjoining Drop and final gates remain qualified. See coverage.md#template-tls-and-http2-fixture-completion. |
| A236 | P2 | Session-reuse tests retain server, proxy and request tasks | Raw task handles cross fallible operations; nested peer handles cross later acceptance and early returns can detach them | Prior 33/41 peer and request-caller results remain qualified. All 19 HTTP/1 methods pass on both hosts at 86e7ab92: nine ordinary contracts, eight unchanged peer/queued controls, the unchanged real budget control and one added completed-cancel/deadline control. The three queued failures now reach cleanup observations before backup. Completed budget-Pending cancellation retains original JoinError/task ID plus URI/parser cause after causal failure at ad366637. The 0fad19-pass checkpoint retains its strict lint failure; three-expression boxing clears it without changing controls. Other session owners, acquisition/error variants, unfinished races and final gates remain open. See `session-http1-queued-boxed-remedy-independent-native-review-86e7ab92.json`, its source gate and retained baselines. The body/tunnel baseline at 59c28617 executes 54 methods on each host: 41 pass and 13 fail. Eight targets fail at destruction, one captures queued setup destruction/completion/socket failures, and four pass actual InvalidUri prerequisites before failing at missing completed cancellation causes. Original returned JoinError/task-ID checks are unreached. The earlier aef7eea1 four URI prerequisite failures remain preserved. The baseline required repair; see `session-body-uri-baseline-independent-native-review-59c28617.json`. At 36f6c695 all 54 methods pass on Windows and Linux. Thirteen unchanged controls now reach actual destruction/completion/same-socket closure, original contextual Elapsed, actual InvalidUri/parser causes and original cancelled task IDs (both tunnel peers). Queued setup recovery preserves the original RecvError/context before cleanup and separate backup. Both host quality checks pass. The four ordinary wire contracts stay unchanged. External Drop output reporting, unfinished cancellation races, expiry/recovery variants, broader session owners and final gates remain open. See `session-body-tunnel-remedy-independent-native-review-36f6c695.json`. |
| A237 | P2 | H2 upload fixtures retain incomplete-stream errors | The collector maps clean driver closure to successful stream EOF without re-polling the original receive stream | The independently reviewed collector repair passes all 14 selected methods on both hosts, including actual incomplete and complete uploads. Original BrokenPipe is retained after driver closure; quality checks pass. Prior causal failures remain preserved. Broader owner and final gates remain open. See `upload-stream-root-remedy-63306d62.json`. |
| A238 | P2 | DNS test origins retain serving tasks and failures | TLS and SOCKS5 raw tasks cross fallible callers; closing and keep-alive origins detach children or discard serving causes | Reviewed ordinary origin owners collect original worker/proxy/caller cleanup outcomes and stop descendants. All27 DNS methods pass on both hosts after the paired15P5F baseline, including seven new ordinary-collector controls. Focused formatting, strict Clippy and Rust1.88 pass. DNS deadline A233 and full gates remain open. See `dns-origin-owner-root-remedy-a02978a3.json`. |
| A239 | P2 | Direct, tracing and SSE test peers survive exceptional caller cleanup | Raw peer handles cross fallible requests, body reads and assertions inside deadlines; early returns lose result observation | Managed-ID peer ownership and cause composition now pass all 69 selected SSE methods on both hosts, including the prior three failures and new actual deadline cleanup. Focused quality passes. Other eight raw sites, contextual deadlines and final gates remain. See `owner-netlog-root-checkpoint-02cad4f2.json`. |
| A240 | P2 | Idle SSE teardown distinguishes disconnect from unrelated read failure | await_peer_close maps every actual TLS read error to successful teardown | Independently reviewed explicit EOF/four-supported-disconnect policy retains the original unrelated I/O error. All eleven idle methods pass on both hosts, including cause/payload/Arc identity, original seven methods and three positives. Original causal failure is preserved. A239 broader ownership and final gates remain open. See `fixture-remedy-root-checks-4bf6000f.json`. |
| A241 | P2 | HTTP/2 authority and idle fixtures retain task owners and reader failures | Authority peers cross later acceptance and fallible callers; idle coordinator, serving, frame-reader and release tasks detach while failures are discarded or printed | Authority callers collect actual accepted peers through fallible setup and borrowed deadlines. The idle coordinator owns accepted peers, retains events through cleanup and polls one persistent frame reader across release. Boundary EOF is accepted only after an answered request; truncated frames and typed worker/channel failures remain errors. Four causal controls and the unchanged wire scripts pass in the 101-method paired selection at a44af645; warning-free focused quality passes at 57a9f1b0. Independent review accepts the composition; final gates remain open. |
| A242 | P2 | Scoped tracing captures rebuild callsite interest under their own dispatcher | Sole-dispatch cache rebuild outside Capture reads the empty current default, disabling old callsites in grouped tests | The older group has four pass/four missing-span failures on each host, while selected isolated tests pass. Scoped rebuild preserves privacy assertions and restores all old group cases; only the two original ownership negatives fail. Source independently approved; final integration remains. See `tracing-cache-root-diagnostic-7a697040.json` and `fixture-owner-root-remedy-a860167f.json`. |
| A243 | P2 | Source-binding fixtures retain prerequisites and original peer failures | UDP errors become skips; raw SOCKS peers lose second outcomes; interface errors become strings and raw peers detach | Immediate original interface owner and typed result/caller composition repair passes all21 methods on both hosts after17P4F, including completed capability-skip cause. Allquality0. SOCKS/bind prerequisites, interrupted joins/foreign cancellation and final gates remain. See `source-binding-interface-root-remedy-36c99fed.json`. |
| A244 | P2 | Connection-retry fixtures own caller and serving tasks | Raw tasks cross fallible retry/listen/caller/body operations; setup aborts lack joins and deadlines discard Elapsed | Prior H1/terminal-status and scripted status repairs retain original task and caller/serving outcomes. Shared-cap 13dedda4 passes all 37 selected methods on both hosts after four causal failures at acdbf923. All 29 prior status contracts, six original shared-cap controls and two new cause controls pass; focused quality passes. Raw other workers, parser bounds, setup/acquisition/outer deadlines, cancellation races and final gates remain. See `shared-cap-owner-remedy-independent-native-review-13dedda4.json`, its retained baseline, and prior status receipts. |
| A245 | P2 | Timeout and stale-replay fixtures retain task outcomes | Raw workers cross fallible caller/observation paths and cancellation joins discard causes; deadline mappings erase Elapsed | All 17 stale-replay methods pass on both hosts at e0228c78 after five causal failures at 41e4831b. Ten ordinary contracts and seven controls are unchanged; original destruction/socket, Elapsed and typed caller/serving identity targets pass before backup. Focused formatting, strict Clippy and Rust 1.88 pass. The mixed completed-worker/outer-deadline control fails on both hosts at e1f309e2 (17 pass, one fail) and passes at 7a69d906 (all 18 pass). Original deadline/Elapsed, completed serving payload identity and no-backup targets now pass; focused quality passes. The task and captured caller outcome remain outside the consuming caller timeout. No-server setup, healthy join timeout/final collection and finished foreign cancellation branches remain source-only. See `stale-mixed-deadline-remedy-independent-native-review-7a69d906.json`. At 304ee690 root and independent source/native review accept the seven raw-worker repairs and outer-deadline cause boundary: all 28 stale methods pass on Windows and Linux, including six previously red targets and the new mixed control; formatting, strict linting and Rust 1.88 pass. All eight logs/exits are read and clean exact sources checked after terminal runners. Quiet-accept and parser/allocation paths, concurrent cancellation provenance and other timeout owners remain open. Replay-body I/O and redirect late-write causes remain open. All twenty timeout methods pass on both hosts at 711ca477 after seven causal failures at 0612bfc9. The partial-response owner preserves completed serving/cancellation and caller failures; its body watchdog retains Elapsed. Focused quality passes. Other ten raw ordinary timeout workers, acquisition, mixed outer deadlines and broader A245 remain open; final gates remain open. See `total-body-timeout-remedy-independent-native-review-711ca477.json`. See `stale-replay-owner-remedy-independent-native-review-e0228c78.json` and its retained baseline. |
| A246 | P2 | NetLog evidence rejects malformed interior records | Truncated-log fallback silently discards malformed middle events and accepts closed malformed documents as incomplete | Reject malformed records and retain only original complete events before valid truncation. All 13 reader controls pass on both hosts. Full capture discovery passes 661 methods on Windows and 650 with 11 skips on Linux; pinned quality passes. Earlier resource-warning and withdrawn BMP review receipts remain preserved. Full gates remain. See `owner-netlog-root-checkpoint-02cad4f2.json`. |
| A247 | P2 | Status retries verify each received body | Owned and buffered PUT retries checked request heads and counts without checking the bytes received on each attempt | Retain actual received bytes and assert literal payload on both attempts. All 18 selected methods and focused quality pass on Windows and Linux at cabbe4dd. Changing only the second recorded body fails both body assertions; restoring source passes both. Observation sensitivity only; task ownership, serving errors and final gates remain open. See `status-retry-body-oracle-independent-native-review-cabbe4dd.json`. |
| A248 | P2 | Replay fixtures retain their task trees and failures | PING and unprocessed-replay servers detach TLS drains and H2 drivers; raw worker and handler joins cross fallible callers; tunnel children discard failures; H3 cleanup and observation erase errors | Root whole-source review accepts composition of d6c95874 and 9f004cd9: concrete retained task trees, explicit cooperative stop outcomes, original deadline/body/H3 errors and interrupted cleanup state. Pending external cancellation and interrupted completion have actual CONNECT controls. Independent follow-up review and native checks remain open. Shared raw-frame payload allocation and nonjoining abort fallback remain qualified; these fixture findings do not establish production leaks. See coverage.md#replay-fixture-completion. |
| A249 | P2 | Expect-continue fixtures own workers and retain bounded failures | Fifteen raw workers cross consuming caller deadlines; peer collectors lack aggregate byte ceilings; quiet and cancellation checks erase typed errors | Verified at 2a03a835: all thirty methods pass on both hosts, including sixteen unchanged ordinary contracts, twelve original causal controls and two reader-bound controls. All fifteen workers have immediate retained guards and finite cleanup; original Elapsed, InvalidUri, foreign JoinError/task ID and queued RecvError causes survive. H3 strict ApplicationClosed 0x100 and physical closure assertions now execute before backup. Formatting, strict linting and Rust 1.88 pass. Root and independent complete-log/clean-source reviews accepted; the original 231d5379 sixteen-pass/twelve-failure baseline remains. External Drop is not an asynchronous join, unfinished foreign-cancel races are unmeasured, and shared support readers plus final gates remain open. See coverage.md#expect-continue-fixture-ownership. |
| A250 | P2 | TCP early-data and TLS-resumption fixtures retain original workers and errors | Six raw factories cross consuming caller watchdogs; rejected-stream reads and second-accept failures lose classification; channel checks discard RecvError | All six worker factories now retain owners outside borrowed watchdogs, collect completed original outcomes and preserve expected negative client failures when peer completion also fails. Rejected-stream reads are bounded and classify only supported disconnects. Resolved BoringSSL supplies the early-data storage bound; partial H2 frame observation remains intentional. Three causal controls and original ALPN, ticket and request checks pass in the 101-method paired selection at a44af645; focused quality passes at 57a9f1b0. Drop remains nonjoining; final gates remain open. |
| A251 | P2 | Negotiated session fixtures retain workers and original failures | Raw server, proxy and concurrent request tasks cross consuming callers; five-second bounds erase Elapsed; quiet accepts and channels discard typed causes | Complete root and independent reads cover all 1188 lines. Normal cancellation explicitly aborts and awaits, but accepts any JoinError. Quiet accept errors fail observations while losing their causes; expected quiet expiry remains valid. Aggregate collectors need bounds. Clean H2 driver closure before receive completion remains a candidate requiring controls. Preserve protocol, cookie, trailer, GOAWAY and timer-free input contracts. Controls, remedies and native verification remain open. See `negotiated-independent-source-review-5aa2f5bb.json`. |
| A252 | P2 | Parallel negotiated fixtures own descendants and observe serving failures | Origin aborts its listener but detaches connection and response workers; raw callers and CONNECT children lose outcomes; outer deadlines erase Elapsed | Complete root and independent reads cover all 957 lines. Listener, head-read and H2 driver errors lose classification; Closed events and drain do not distinguish serving failure. Normal handshake cancellation already checks is_cancelled, and seven expected Capacity results intentionally compare kind and protocol. Parser and finite event/admission budgets require contract controls. Preserve gates, connection IDs, wire observations and original timing. Controls, remedies and native verification remain open. See `negotiated-parallel-independent-source-review-5aa2f5bb.json`. |
| A253 | P2 | Idle pruning preserves address-family memory when an origin becomes active | The timer clears shared memory from per-entry empty observations after releasing their connection locks | Fixed and independently verified at `3d71315b`. Both Windows and Linux pass 66 pool, 10 timer and 20 backup tests, formatting, strict linting and Rust 1.88. The original real-connection failure from `bf0af1f8` now passes alongside stable-empty forgetting and a genuine pending pool reservation. Snapshot capture shares the registry lock; registration, setup, adoption and every record invalidate old observations. Complete activation paths are source-reviewed; late registration and negotiated adoption races have no new native controls. This changes TCP address selection, not DNS query type. The residual retention gap has a source-reviewed remedy at ddb906ed. Both hosts at e9df18a9 pass the existing three prune controls and fail the two missing-recheck controls; later reset assertions are unreached. The remedy schedules a recheck after rejected empty observations and when the last owner leaves empty. At 1182b4d1 both hosts pass 68 pool, 10 timer and 20 backup methods plus formatting, strict linting and Rust 1.88; all five prune controls reach final assertions. Root and independent review accept terminal logs and clean exact sources. The new controls use an unscheduled timer seam rather than measuring a real one-second wake. Full integration gates remain open. |
| A254 | P2 | Partitioned cookie identity includes its schemeful site | Storage and snapshot deduplication use a partitioned boolean instead of the actual partition site | Root read the complete cookie owner and actual snapshot import/export. The resolved `cookie_store` replaces by domain/path/name. Trustworthy HTTP and HTTPS localhost sites can store the same cookie key, so one partition overwrites or expires the other; snapshot seen/held-key filtering also collides. Request matching filters the stored partition site, so this is state loss, with no confirmed outgoing credential leak. Include the site in backend storage and canonical keys, preserve host-only/domain separation and existing count bounds, and remove empty per-site stores. At e8fcdb93, both hosts compile and run 50 cookie methods: 46 pass and four fail at their literal state-count assertions (coexistence 2/4, expiry 0/2, import 2/4, export 1/2). Later assertions are unreached. Both runners are terminal and clean exact source is separately verified. The independently reviewed repair at 956067f6 passes all 51 cookie methods on both hosts, including the four original negative controls and the empty-store resource control. Formatting, strict linting and Rust 1.88 pass. All logs and clean exact source are independently reviewed; final gates remain pending. |
| A255 | P2 | HTTP/3 body errors retain the original worker failure | The body worker task handle is dropped; event-channel closure replaces its panic cause with a source-less local error | Source-confirmed after tracing early response handoff, caller upload polling, body events and task ownership. Retain the actual worker handle and preserve its original JoinError after unexpected channel closure, while keeping bounded cleanup and cancellation. Independent source review approves baseline 192e3f21 and remedy d920b06e. At root caaab883, both hosts reproduce the actual upload panic followed by the source-less Local error; later original-cause assertions are unreached. At ee164f59, both hosts pass all twenty HTTP/3 connection methods, including the original task-ID and panic-cause assertions; formatting, strict linting and Rust 1.88 pass. The pinned Windows API generator produces an unchanged 1,250-line transport inventory. Root and independent review qualify terminal logs and clean exact source. Published to draft PR #197; final gates and current CI remain open. |
| A256 | P2 | Stacked content decoding yields during no-output expansion | Intermediate progress can keep one pump running indefinitely before body deadlines are checked | Whole codec and pipeline reads confirm that compressed gzip names/comments can expand without final data. At 800c9bdc both hosts fail the actual buffered-body regression at the first poll: Ready(None) instead of Pending, so the later total-deadline assertion is unreached. The independently reviewed source remedy bounds stage inputs and pump passes, yields with a wake, and checks deadlines during no-output progress and completion. The initial remedy incorrectly let idle expiry win ready EOF at a quota; correction 92db927f recognizes actual completion before idle while retaining total expiry. At faa675f7 both hosts pass six body, seventeen request-body, thirty-nine codec and twenty-one HTTP content-decoding integration methods; formatting, strict linting and Rust 1.88 pass. Root reads every terminal log and separately verifies clean exact sources. Independent review accepts all twelve logs and exit receipts, with unchanged code at the later documentation checkpoint; final gates remain open. No retained-buffer explosion or performance improvement is claimed. |
| A257 | P2 | Proxy capture owns partial listener acquisition and complete shutdown | Startup precedes the cleanup region, and close stops at the first failure | Source-confirmed in proxy_route.py at 800c9bdc. Cleanup must attempt every acquired listener and writer under a finite bound and retain initiating plus cleanup failures. Verified at 39c6fb8f: independently reviewed source, 687 Windows capture methods and 676 Linux methods with eleven platform skips, and Python quality checks. See coverage.md#capture-tool-ownership-follow-up for the retained failed attempt and cancellation correction. Final gates and broader capture findings remain open. |
| A258 | P2 | Proxy capture collects accepted handler tasks and local failures | Only writers are retained, and handle converts every Exception to a class-name record | Source-confirmed in the complete proxy owner read. Retain actual handler tasks at acceptance and observe their outcomes before publishing a run. Preserve explicit expected peer and browser-rejection capture policies. Verified at 39c6fb8f: independently reviewed source, 687 Windows capture methods and 676 Linux methods with eleven platform skips, and Python quality checks. See coverage.md#capture-tool-ownership-follow-up for the retained failed attempt and cancellation correction. Final gates and broader capture findings remain open. |
| A259 | P2 | Completed proxy HTTP/1 heads obey the head limit | A fragment that supplies the terminator can bypass the 64 KiB check | Source-confirmed in Http1Exchange.feed. Validate the completed head extent before parsing or recording, while allowing multiple ordinary heads in one chunk. The separate 16 MiB connection cap does not enforce this contract. Verified at 39c6fb8f: independently reviewed source, 687 Windows capture methods and 676 Linux methods with eleven platform skips, and Python quality checks. See coverage.md#capture-tool-ownership-follow-up for the retained failed attempt and cancellation correction. Final gates and broader capture findings remain open. |
| A260 | P2 | Shared proxy TLS readers preserve unrelated failures | Broad ConnectionError and SSLError catches turn local errors into EOF | Source-confirmed in called http2_session.py channel owners. Keep explicit clean TLS close and supported peer disconnects; propagate other original errors to the capture owner. Native handshake rejection has a separate evidence policy. Verified at 39c6fb8f: independently reviewed source, 687 Windows capture methods and 676 Linux methods with eleven platform skips, and Python quality checks. See coverage.md#capture-tool-ownership-follow-up for the retained failed attempt and cancellation correction. Final gates and broader capture findings remain open. |
| A261 | P2 | Proxy capture durations remain finite | Non-finite values reach wait_for and timer scheduling | Source-confirmed at CaptureRun, capture_scenario, run and CLI entry points. Reject non-finite observation and run durations before resources or output changes. Preserve existing finite zero and negative expiry behavior. Verified at 39c6fb8f: independently reviewed source, 687 Windows capture methods and 676 Linux methods with eleven platform skips, and Python quality checks. See coverage.md#capture-tool-ownership-follow-up for the retained failed attempt and cancellation correction. Final gates and broader capture findings remain open. |
| A262 | P2 | Race H3 callbacks retain local held-response errors | Done is set before hold release, and H3 responders lack a collected failure owner | Source-confirmed in Origin.request, Http3Protocol and capture cleanup at 800c9bdc. The independently reviewed repair at 7704e38d retains original callback failures and stops owned callbacks before publication. All 75 race methods and Python quality checks pass on both hosts. Original FrameUnexpected identity, reason and strict normal close assertions remain. The first 5ae13b69 attempt and its trailer-input failure remain recorded in coverage.md#capture-tool-ownership-follow-up. Aggregate limits, live-browser evidence and final gates remain open. |
| A263 | P2 | Capture record collections and tunnel state have aggregate bounds | Accepted connections, requests and UDP peers grow per run; ended H2 tunnels remain mapped | Proxy verified at ba8dd848: all 703 capture methods pass on Windows and 692 on Linux with eleven skips. Race verified at cccad0ff: all 88 methods and lint/format pass on both hosts. Root and independent review read complete packets and separately bind exact clean sources. Original quotas, overflow cause, closure and ownership assertions remain. The failed 151e3e1a, 6de973d7 and 13e6fb83 attempts remain in coverage. No permanently infallible cleanup or default H3 64 KiB capacity is claimed; combined gates remain open. |
| A264 | P2 | Proxy listen addresses agree with page and authority formatting | IPv6 loopback is accepted while direct page URLs use IPv4 and authorities omit brackets | Proxy verified at ba8dd848: desktop loopback URLs, authorities and browser routes agree; Android IPv6 fails before resource acquisition. Actual IPv6 sockets and complete capture suites pass both hosts with eleven Linux skips. Independent source, complete-log and clean-source reviews accepted. No actual browser capture is claimed. Shared WebSocket address handling is separately open in A269; final gates remain. |
| A265 | P2 | Unix browser cleanup distinguishes failed census from no processes | A failed ps command is decoded as an empty listing | Source-confirmed in browser_launch.py terminate_profile_processes. At ad13642f check=True and captured output retain the original command failure before interpreting absence. The real-child exit-23 adapter fails the original code and passes the remedy. Windows passes all 28 browser-launch methods; Linux passes 26 with two platform skips. Python lint and format pass on both hosts. Independent source review accepts the bounded repair. No actual failing ps command or cleanup-duration improvement is claimed; final gates remain open. |
| A266 | P2 | Shared H2 and WebSocket capture owns listeners, handlers and shutdown | Second-listener acquisition loses the first owner; handlers and their original failures are uncollected; release removes a writer before fallible close; publication precedes cleanup | Locally verified at `86fd68bc`: acquired listeners, handlers and writers remain owned through finite cleanup; original cancellation and independent failures survive collection. See coverage.md#capture-and-dns-completion-batch. Final gates remain open. |
| A267 | P2 | Shared capture parsers validate complete extents and frame sequences | Completed oversized heads bypass limits; truncated ClientHello fields, empty padding and priority payloads permit unchecked access; continuation sequence ownership is unchecked | Locally verified at `86fd68bc`: complete parser extents, HTTP/2 continuation ownership and decoded header bounds are enforced while intentional incomplete records remain available. See coverage.md#capture-and-dns-completion-batch. Final gates remain open. |
| A268 | P2 | Shared WebSocket capture bounds aggregate records and decoded output | Lifetime collections and ended-stream maps retain records; echo decompression lacks an output ceiling | Locally verified at `86fd68bc`: finite per-run and lifetime record limits plus decoded WebSocket bounds fail capture before publication. These are tooling guardrails, not measured browser maxima. See coverage.md#capture-and-dns-completion-batch. Final gates remain open. |
| A269 | P2 | Shared WebSocket capture validates address and duration contracts | Literal IPv6 page URLs lack brackets; Firefox disables IPv6 unconditionally; non-finite durations reach scheduling | Locally verified at `86fd68bc`: selected loopback family, bracketed IPv6 URLs and desktop browser routes agree; Android requires IPv4 and durations are validated before acquisition. See coverage.md#capture-and-dns-completion-batch. No live-browser capture is claimed; final gates remain open. |
| A270 | P2 | Shared H2 capture distinguishes incoming peer failures from local operations | ProtocolError handling covers both receive and local outgoing operations; StreamClosedError suppression lacks a phase contract | Locally verified at `86fd68bc`: incoming peer failures are phase-qualified; unrelated local errors survive. HEADERS followed by reset skips only affected outgoing responses. See coverage.md#capture-and-dns-completion-batch. Final gates remain open. |
| A271 | P2 | Request-ownership shutdown avoids an unqualified simultaneous peer close | The fixture drops Client before requiring the held H2 peer to finish without error | At `0425b7cd`, macOS reports Shutdown/BrokenPipe for the dropped independent caller; the historical first-syntax failure remains unclassified. The reviewed `6d0dcced` fixture shuts down TCP after actual held-stream read EOF without another TLS write and preserves returned errors. All 31 focused contracts and target quality checks pass on Windows and Linux. All 43 PR checks, including macOS and Windows, pass at `1e95577c`. Final integration gates remain open. |
| A272 | P2 | HTTP/2 connection and stream errors retain original I/O causes | Private errors copy only kind and text; public Error stops cause traversal | Root and independent source review trace real connection-to-stream fanout. The 13e6fb83 actual held-read control records PermissionDenied and fails because its original typed cause becomes text on both hosts. Native OS codes are also discarded by the same conversion. The reviewed shared-cause remedy and both protocol adapters at efc21440 preserve the original error. Formatting correction 8fef2005 passes canonical vendor replay and both fork suites, nine first-party request and sixteen reuse controls, and workspace quality checks on Windows and Linux. Original typed payload and native-code identity assertions pass. Root and independent reviewers read full logs/exits and separate exact clean bindings. All 43 PR checks pass at `1e95577c`, including macOS and Windows. Final gates and CI for later candidates remain open. |
| A273 | P2 | Socket-hook runs retain every partially acquired resource and failure | run_once acquires listeners/profile before its try; browser.stop failure skips later cleanup | The 3c037031 real second-bind and profile-creation controls fail on both hosts because the first listener still serves. The reviewed repair protects acquisition and retains independent cleanup causes and unfinished original workers. At 96c1363a all twelve owner controls and 32 existing tests pass on Windows and Linux, with lint, format and docs clean. Root and independent review read full logs/exits and separate exact clean bindings. Locally verified; blocked Frida preemption, accepted handlers and final gates remain separate. |
| A274 | P2 | Socket-hook child work has an observed shutdown and bounded queues | A daemon worker can append sessions after detach, join timeout is unchecked, failures are suppressed and report/child queues grow | The independently reviewed owner retains suspended-process kernel handles, requires observed exit before retirement, cancels and joins its worker, bounds admission/reports and retains unknown identities and cleanup failures. At a3782686 all 53 combined ownership controls pass on Windows; Linux passes 52 with one Windows-only skip. Pinned local callback ordering has source review; actual Frida/browser acceptance and final gates remain open. |
| A275 | P2 | Socket-hook origin owns accepted handlers and bounds per-run records | Listener closure does not join accepted handlers; mutable connection/request collections are unbounded | The independently reviewed Origin owns accepted writers, serving/closing tasks and original listener waiters, bounds records and rejects malformed completed heads and Host authorities. Corrected 5f36f0ec baseline failures reproduce on both hosts. At a3782686 all applicable combined controls pass on both hosts, retaining original A273 cancellation assertions. The listener fence covers attached transports; pre-attachment backend work and final gates remain outside this proof. |
| A276 | P2 | Socket-hook evidence requires acknowledged hooks and supported layouts | Missing hooks are normal reports discarded by decoding; ready architecture is ignored despite fixed x64 layouts | The agent fails unsupported Windows layouts or missing required hooks and acknowledges installed hooks plus configuration before the network-service child resumes. Controlled readiness/failure checks pass in the a3782686 combined suite on both hosts. This is reviewed source and controlled-boundary verification, not live browser acceptance. Final gates remain open. |
| A277 | P2 | Socket-hook launch arguments preserve the owned profile | Extra arguments can replace user-data-dir or add a positional URL without pre-acquisition validation | Pre-acquisition validation preserves managed profile/page ownership and accepted switch order. The corrected baseline reproduces both rejection-method failures without harness errors on Windows and Linux. All expanded rejection, positive-order and CLI controls pass in the a3782686 combined suite on both hosts; docs include Migrate guidance. Final gates remain open. |
| A278 | P3 | Retained socket-hook fixtures describe their historical tool versions | Tests require old capture hashes to equal current source hashes | Root and independent review verify retained source digests against their original Git bytes for 21 Chromium and six Firefox captures. The ce80d5f2 repair preserves archived bytes and tests current rendering separately. At 96c1363a all 32 existing socket-hook tests pass on Windows and Linux. Locally verified; no fresh capture or live acceptance is claimed, and final gates remain open. |
| A279 | P3 | Client configuration represents DNS and route choices directly | Nested DNS options and a route plus explicit flag duplicate state decoding | Replaced with a private DNS choice enum and one optional route at `a9c7ebbc`. Source review confirms precedence, proxy construction and diagnostics are unchanged. All 28 client and 14 environment-route tests pass on both hosts; strict Clippy, Rust 1.88 and formatting pass. Final gates remain open. |
| A280 | P3 | HTTP protocols share their forbidden-trailer policy | Three protocol owners repeat the same seventeen forbidden field names | One private predicate in the existing request domain replaces the repeated policy at `a9c7ebbc`. Protocol-specific parsing, errors, bounds and wire paths remain local. Independent review and all 37 trailer tests pass on both hosts, with focused quality checks. Final gates remain open. |
| A281 | P2 | DNS test-server failures are available to consumers | Receiver errors all become ICMP retries; reply task and send outcomes are discarded | Core verified at `35741043`; remaining returned-owner consumers and raw reply worker verified at `86fd68bc` by 101 selected DNS/ECH tests on each host, strict Clippy, Rust 1.88 and formatting. Original assertions precede explicit completion. Earlier errors and cancellation use nonjoining Drop fallback. See coverage.md#capture-and-dns-completion-batch. Final gates remain open. |
| A282 | P3 | Profile and QUIC code follows the layout and lint-exception rules | Selected roots declare modules before imports; three private QUIC modules have blanket dead-code allowances | Independently reviewed cleanup at `22a6eda8` orders imports and exports, removes the three blanket allowances, and gates the server-only pointer accessor and test-only rejection accessor by their actual consumers. Both hosts pass formatting, selected no-default-feature library and all-target/all-feature Clippy, Rust 1.88 and unsafe-boundary checks. Complete logs and separate clean-revision bindings are independently accepted. The earlier `a21824c3` lint failure remains recorded in local logs. No crate split or generic abstraction is justified by these boundaries; final gates remain open. |
| A283 | P2 | Capture process cleanup retains failed owners and original failures | Gate closure can skip cleanup; native closure results and POSIX permission failures are ignored; cleanup can replace launch errors | Locally verified at `86fd68bc`: private process ownership retains original launch, cleanup, worker and reporting failures. POSIX uses a retained custodian; invalid native handles are retired with their diagnostics. A late worker cannot acquire after stopped admission. See coverage.md#capture-and-dns-completion-batch for platform-qualified tests and limitations. Final gates remain open. |
| A284 | P2 | Snapshot normalization rejects malformed inputs | Ignored nested lengths can make malformed extensions match valid input; unbounded declared counts control allocation and iteration | Source-reviewed repair at `86fd68bc` validates normalized extents and duplicate extensions, bounds declared counts and requires indexed entries. Existing valid normalization and retained Firefox inputs pass the affected Python suite on both hosts. Count limits do not bound total file size or validate every TLS field. See coverage.md#capture-and-dns-completion-batch. Final gates remain open. |
| A285 | P2 | IP-literal capture bounds input, owns workers and reconstructs Initial CRYPTO accurately | Resetting TCP timeouts and unbounded recordings can retain workers indefinitely; partial startup lacks cleanup; errors disappear; truncated and overlapping CRYPTO input is mishandled; an unauthentic first packet fixes connection selection | Source and composition reviewed; at 74edd754 both hosts pass all 24 IP methods, Ruff check/format and docs. The owner preserves acquired sockets, actual workers and late failures, bounds recordings and parses CRYPTO overlaps accurately. The version probe has a finite deadline. Controls use real loopback sockets/threads with mocked browser boundaries; no pre-fix IP runtime baseline or fresh capture is claimed. Incomplete captures, unobserved starts, buffered probe output and native preemption remain qualified. See coverage.md#ip-literal-capture-completion; final gates open. |
| A286 | P2 | Capture tools validate extents before native QUIC header protection | Resolved aioquic 1.3.0 removes header protection before AEAD payload checks, reading a sixteen-byte sample and copying into a 1500-byte header buffer without validating packet/header extents | The analyzer uses a shared checked header/sample boundary. Root and independent C/Python/parser/caller reads establish the cause. At cc6e8fc2 five malformed subcases reach a safe intercepted decryption call on each host; two methods fail. At 33de1fc4 all 22 analyzer methods pass per host. The largest accepted header control mocks decryption and does not prove native authentication. Focused quality passes apart from formatting, corrected and checked at 327f18a3. The IP-literal caller also passes all 24 methods on both hosts at 74edd754; final gates remain open. See coverage.md#native-quic-input-and-dns-deadline-checks and coverage.md#ip-literal-capture-completion. |
| A287 | P2 | ECH capture bounds readiness and observes output failures | Readiness blocks before the timeout; daemon pipe readers hide reporting and decoding failures; output and policy waits are unbounded | Root whole-command review establishes the causes. The repair uses the existing process-tree owner, finite accepted output snapshots and a launch-to-completion deadline. New real-process controls preserve original reporting, decoding, launch and cleanup failures with mocked browser launch. Root and independent source/result reviews accept the repair at d7e89a26: all 41 focused methods, Ruff check/format and docs pass on both hosts. The earlier Windows newline failure is corrected while original server and compound cleanup failures remain available. File thresholds do not bound temporary disk use between polls or preempt blocking callbacks/native calls. Mocked browser launch does not establish a fresh capture; final gates remain open. See coverage.md#ech-command-process-repair. |
| A288 | P2 | Startup capture owns acquisition, readers and cleanup | Killing only the listener leaves descendant stderr handles and an unbounded reader join; worker errors and profile removal disappear; browser/certificate startup can leak earlier resources | The independently reviewed remedy retains original owners and errors. All 22 startup methods pass on both hosts at 42d9d3a0, including the unchanged Windows descendant control after the shared owner repair. Snapshot limits do not impose a disk quota; no fresh browser capture is measured. See coverage.md#startup-capture-review; final gates open. |
| A289 | P2 | Cookie fixtures exclude unused credential inserts | Encoder bytes retain literal authorization, proxy authorization and static authorization inserts that no request references | All three native-valid streams reproduce the leak on Windows and Linux at 7f7e6886. The independently reviewed fix at fcb848da passes all 10 cookie methods on both hosts, including publication, reference and duplicate controls. Focused quality checks pass. Final integration gates remain open. |
| A290 | P2 | Local capture callbacks have observed completion | Five capture tools close listeners without collecting all accepted callback outcomes; some callback errors are stringified or discarded | Client-hint 17/17 at 2928f1d0, preface 15/15 at bc37a5db and snapshot 45/45 at 1da2ba31 pass per host. At fafa0a4e, all 26 lifecycle and 21 cookie methods pass per host after independent source and original-log review. Original stream-close futures are observed even when writer setup fails. Final gates remain open. |
| A291 | P2 | Partial local capture startup releases acquired listeners | Cookie, snapshot and lifecycle setup can fail after acquiring an earlier listener or socket | Snapshot acquisition controls pass within its 45-method suite at 1da2ba31. Lifecycle and cookie acquisition controls pass within their 26/21-method suites at fafa0a4e on both hosts, observing registered original owners before test backup. The cookie factory control retains its injected pre-protocol native socket for explicit test backup outside this proof. Final gates remain open. |
| A292 | P2 | Local capture resource limits include completed input | Cookie, snapshot and lifecycle allow oversized heads when the terminator arrives in the same chunk; retained connection and request collections lack aggregate bounds | Snapshot literal 65536/65537-byte head and aggregate controls pass at 1da2ba31. Cookie literal head/aggregate boundaries and lifecycle completed-head, request, connection, frame and encrypted-channel bounds pass within the 21/26-method suites at fafa0a4e on both hosts. Root and independent readers inspect the original checks. Final gates remain open. |
| A293 | P2 | Local capture input and loop policy remain explicit | Client-hint names permit invalid header bytes; durations allow non-finite values; IPv6 URLs and completion tokens are unchecked; snapshot replaces the loop error handler without restoring it | Earlier client-hint, snapshot and preface repairs retain their recorded results. At fafa0a4e, exact original-target cookie tokens, lifecycle duration/token/fixture-input guards and canonical browser address launch policies pass within 21 cookie, 26 lifecycle and 12 QUIC methods per host. IPv6 preference retains IPv4 fallback. No fresh browser capture or final gate follows from these controls. |
| A294 | P2 | Browser navigation bounds connection setup | DevTools TCP connection and WebSocket upgrade can wait indefinitely before navigation deadlines apply | Independently reviewed setup deadline and cleanup cause retention pass all 38 remote methods on both hosts at 5ad5b8ac, plus focused quality checks. The original failed cancellation observation remains recorded; the corrected control observes the actual caller boundary. Final gates remain open. |
| A295 | P2 | Windows process cleanup observes descendant completion | Closing the job requests termination but waiting only for the exited bootstrap leaves descendant output handles pending | The original WinError 32 control and original-handle retry controls pass on Windows at 42d9d3a0 after independent review. All affected caller suites and focused quality checks pass on both hosts. Completion covers retained pre-termination member handles; already-terminating members absent before collection remain outside this proof. Final gates open. |
| A296 | P2 | Session fixtures collect tasks after caller failure | session_http3.rs and session_http2_lifecycle.rs create raw server/request/replacement handles inside consuming timeouts; early errors or expiry detach peers and bounded helpers replace original Elapsed causes | Independently reviewed repair at d4e2aa8d retains peers outside caller deadlines and preserves original causes and assertions. At d9e6b6e7, 80 Windows/79 Linux session methods and three peer controls per host pass. The sole strict-lint failure is corrected at 12422fcc. Blocking work and nonjoining Drop remain qualified; final gates open. |
| A297 | P2 | WebSocket profile servers own accepted children | TestServer in websocket_profile/server.rs owns only its listener task; accepted TLS/plain and HTTP/2 echo tasks detach and their errors are discarded | Root and source auditors confirm the listener/accepted-child ownership gap and trace profile, proxy and trust callers. Add explicit child collection and retain original failures at caller shutdown. Remediation and verification remain open. |
| A298 | P2 | WebSocket echo distinguishes disconnect from local failure | support/websocket_origin.rs ignores every read_to_end error after sending Close, allowing unrelated local I/O errors to become success | Whole-source and independent review approve the bounded drain at 12422fcc. Both hosts pass 19 origin controls, 16 proxy and 17 per-origin certificate methods, plus focused quality checks. Original wire assertions, unrelated I/O and Elapsed remain intact. Helper controls do not prove native retirement or whole caller ownership; final gates open. |
| A299 | P2 | WebSocket profile decoding bounds priority payloads | websocket_profile/server.rs indexes a complete HEADERS payload as five priority bytes without checking its length when the PRIORITY flag is set | Root reads the actual recorded-wire scan. Reject a short priority payload before indexing and preserve valid frame decoding. Assigned to the profile lane; remediation and verification remain open. |
| A300 | P2 | Resolver configuration errors retain original causes | System and builder failures are formatted into strings before address/HTTPS resolver errors are returned | Independently reviewed typed wrapper at a86c1f25 preserves original platform/build causes, public categories and messages. All 51 selected DNS tests pass on both hosts; corrected strict lint passes at 12422fcc. Tests exercise concrete causes rather than host configuration fault injection; final gates open. |
| A301 | P2 | QUIC profile failures retain the validation cause | QuicTlsProfileError replaces InvalidTlsSettings with its kind, field and message | Independently reviewed repair at d9e6b6e7 retains the original cause through the provider and public client build error. Fifteen provider and fifteen client methods pass per host; focused quality passes after the unrelated DNS assertion correction. Final gates open. |

At `400a900e`, the two additional A223 sibling and external-cancellation
controls do not execute: their fixture import fails compilation. The source
review missed that namespace prerequisite and its correction is separately
reviewed. Original nine-control outcomes remain authoritative until the
corrected baseline runs. The same compile prerequisite prevents a new A224
fallback result. See `quic-relay-root-native-baseline-400a900e.json`.

## Current proxy evidence

The six-file formatter correction at `e158bcb4` passes formatting and both
affected Rust 1.88 targets on Windows and Linux. It changes layout and
module order only. The earlier test results remain bound to `3b39526f`;
full integration gates and final architecture review are still open. See
`combined-format-root-checkpoint-e158bcb4.json`.

At `3b39526f`, the A222 delivery observation passes all six focused QUIC
controls and all 33 capture-example methods on both hosts. Original typed
error and payload identity assertions now pass. Incoming serving policy and
final gates remain open; the synthetic fault now follows actual page/FIN
delivery rather than server write completion.

The bounded A223 owner/result repair passes all 25 early-data methods and
seven session-resumption methods on both hosts. This includes the unchanged
abandonment, completed-read, two-sibling and external-cancellation controls,
plus ordinary relay and sniffer consumers. Adjacent raw serving tasks and
unexercised send, panic and combined-failure branches remain open. All six
strict Clippy/MSRV rows pass; formatting flags six reviewed files. See
`combined-remedies-root-native-3b39526f.json`.

At `0b018777`, the A222 outgoing-error repair still has one failing QUIC
control on both hosts. The controlled local error now reaches the aggregate
beside a remote `H3_NO_ERROR` close. The full example remains 31 passes and
one failure; all older 27 methods pass. The original missing-error assertion
is no longer reached, and final typed cause and payload identity are not
credited. Sender finish is not an observed client-delivery boundary. The
fixture needs a matching page-and-FIN observation before its synthetic fault.
Incoming-phase controls and final gates remain open. See
`quic-response-root-native-checkpoint-0b018777.json`.

At `a896be8b`, the A224 nested-driver repair passes all nineteen unchanged
fallback methods on both hosts. The original cancellation negative now
observes actual driver destruction and I/O closure before backup. Healthy
upload/204 and explicit driver-abort controls remain green. Outer, unpolled,
accepted and sibling ownership, A226 observations and final gates stay open.

The corrected A223 scaffold executes nine early-data controls with three
passes and six failures, plus two passing sniffer controls. The new sibling
and external-cancellation negatives reach their original missing-error
assertions. Later cause and task identities remain uncredited. Both hosts
pass formatting, strict HTTP3-test Clippy and Rust 1.88 checks. See
`relay-fallback-root-native-checkpoint-a896be8b.json`.

At `2fb596ad`, all thirty cookie methods pass on Windows and Linux. The
[root receipt](https://github.com/bywayhq/phantom/blob/1da2ba311d45645dcf8725d7153f13ac884069aa/docs/internals/architecture-audit/cookie-lifecycle-remedy-root-2fb596ad.md.txt) records the
unchanged baseline roster, including ten previously failing controls.
Typed aggregate assertions now execute and pass. Formatting, strict selected
Clippy and Rust 1.88 checks pass. Independent source and native reviews
approve these focused results. Full integration gates remain open.

The [CONNECT baseline](https://github.com/bywayhq/phantom/blob/1da2ba311d45645dcf8725d7153f13ac884069aa/docs/internals/architecture-audit/connect-route-baseline-root-2234a8c3.md.txt) runs
106 methods per host: one hundred pass and six intended negatives fail.
The substring filter also selects other proxy owners. Its exact public
CONNECT subset is 24 methods: eighteen pass and six fail. The
[independent native review](https://github.com/bywayhq/phantom/blob/1da2ba311d45645dcf8725d7153f13ac884069aa/docs/internals/architecture-audit/connect-route-baseline-native-independent-addendum-2234a8c3.md.txt)
confirms reached assertions and their prerequisites. The remedy is in progress.

The [request-session review](https://github.com/bywayhq/phantom/blob/1da2ba311d45645dcf8725d7153f13ac884069aa/docs/internals/architecture-audit/request-session-standards-review-5a28f55f-final.md.txt)
records complete reads of three owners and eight source candidates. Its H3
received-order dependency trace is partial. No new runtime result follows
from these source findings. Existing A90-A92 are reconciled separately.

The following evidence describes earlier revisions.

At `2cea08af`, Windows and Linux each pass all 41 selected H2 methods.
The signed-hex and two credential-oracle negatives now pass with their
original inputs and assertions. The reviewed parser and concrete deadline
repairs retain all original wire workflows. The
[root native receipt](https://github.com/bywayhq/phantom/blob/1da2ba311d45645dcf8725d7153f13ac884069aa/docs/internals/architecture-audit/h2-cookie-corrected-root-2cea08af.md.txt) records
complete logs, statuses and exact signed source identities. The
[independent native review](https://github.com/bywayhq/phantom/blob/1da2ba311d45645dcf8725d7153f13ac884069aa/docs/internals/architecture-audit/h2-cookie-corrected-native-independent-addendum-2cea08af.md.txt)
confirms the focused results. Cookie remedies and final gates remain open.

The corrected cookie selection runs thirty methods per host: twenty pass
and ten intended negatives fail. All seventeen previous methods and three
positive controls pass. Four H2 and six H3 failures reach the intended
ownership or error-preservation boundaries after actual responses. The
earlier five H2 setup failures at `78ec1aa6` remain preserved with no causal
credit. Aggregate-cause assertions after a missing combined type remain
unreached. Cookie lifecycle remedies are pending.

Formatting, strict selected Clippy and Rust 1.88 checks pass on both hosts.
Both combined runners terminate one because cookie lifecycle remains red.
These private fixture results do not establish a passing full gate.

The following evidence describes earlier revisions.

At `ed320379`, all twenty-two field-order methods pass on Windows and
Linux. At `9de0a354`, all nineteen negotiated methods pass on both hosts.
Formatting, strict selected Clippy, Rust 1.88 and both runners pass for each
candidate. Independent source and native reviews retain exact evidence.
The original compiler failure, eleven-pass/seven-failure field baseline,
seventeen-pass/two-failure negotiated baseline and later certificate/hex
nineteen-pass/three-failure baseline remain historical. Formerly unreached
typed template, rejection, combined-cause and certificate assertions now pass.

The current field parent has a fresh complete root read. Other exact source
bindings retain their original whole/partial qualifications. At that
checkpoint, HTTP/2 findings A141-A149 and cookie findings A151-A155 still
needed causal controls and repairs.
The cookie owner has a fresh whole 649-line source review, without runtime
credit. All final combined reviews and integration gates remain open.

At `1e23deb9`, both hosts pass all 51 SOCKS, seventeen credential,
fourteen proxy environment and seven streaming environment methods.
Formatting, selected strict Clippy and Rust 1.88 checks pass. The local
setup control now observes both destroyed peers. Credential controls reach
the concrete completed causes and poisoned-observer assertions. The
[root result](https://github.com/bywayhq/phantom/blob/1da2ba311d45645dcf8725d7153f13ac884069aa/docs/internals/architecture-audit/proxy-owner-remedies-root-1e23deb9.md.txt) retains the prior
compiler failure and its direct propagation correction.

The local setup, credential and environment changes have independent source
reviews. Negotiated and field-order selected remedies are verified.
Final gates remain open.
The following checkpoints describe their own historical revisions.

At `ff1d8452`, all 49 forward-proxy methods pass on Windows and Linux.
Formatting, selected strict Clippy and Rust 1.88 checks pass on both hosts.
The prior `08a64a01` run passed the same 49 methods but failed a single
Clippy branch-style check. The independently reviewed follow-up retains
the same 100 ms observation and propagates ready read errors.

The [current proxy baseline](https://github.com/bywayhq/phantom/blob/1da2ba311d45645dcf8725d7153f13ac884069aa/docs/internals/architecture-audit/proxy-fixture-native-independent-addendum-199fa9ad.md.txt)
records 51 SOCKS methods per host: 50 pass, and pretransfer local setup
cancellation fails at the origin witness. Its later proxy assertion is
unreached. The nineteen earlier local controls pass. The setup remedy is
held at `e7cc61e7` for independent review and native verification.

Credential fixtures pass eight controls and fail eight intended regressions
on each host. Completed CONNECT/TLS error checks fail before their concrete
cause assertions. Poisoned writer checks fail before later completion
assertions. The actual first boundaries are preserved in the native review.
All baseline formatting, strict Clippy and Rust 1.88 checks pass.

Earlier bounded checks follow. These records establish neither the final
workspace gate nor an integrated architecture sign-off.

The [target repair review](https://github.com/bywayhq/phantom/blob/1da2ba311d45645dcf8725d7153f13ac884069aa/docs/internals/architecture-audit/socks-target-observation-second-independent-review-81c61f13.json)
retains complete and partial source reads separately. At `81c61f13`,
the [native addendum](https://github.com/bywayhq/phantom/blob/1da2ba311d45645dcf8725d7153f13ac884069aa/docs/internals/architecture-audit/socks-target-native-independent-addendum-81c61f13.md.txt)
records 55 selected methods per host: 50 pass and five local ownership or
deadline regressions still fail. The five address-form controls pass.
DNS overrides, HTTP/3 SOCKS fallback and the mapped certificate caller pass.
Formatting, selected strict Clippy and Rust 1.88 checks pass without warnings.
The IPv6 literal control observes ATYP4 over IPv4 loopback forwarding.

The [forward baseline](https://github.com/bywayhq/phantom/blob/1da2ba311d45645dcf8725d7153f13ac884069aa/docs/internals/architecture-audit/forward-proxy-native-baseline-independent-addendum-54c60be7.md.txt)
records ten positives and seven intended failures on each host. Original
deadline context passes before the missing timer cause fails. The completed
peer-cause control reaches typed HTTP/1 and UnexpectedEof checks first.
The deliberate poison panic is joined before the unrecorded-response failure.
The cancellation control observes a finite 150 ms window with the client
alive. Reader errors are deliberate injections over actual socket seams.
Queued-request ownership still needs complete repair and verification.

The [remaining proxy review](https://github.com/bywayhq/phantom/blob/1da2ba311d45645dcf8725d7153f13ac884069aa/docs/internals/architecture-audit/proxy-remaining-whole-source-54c60be7.json)
records full manual reads of negotiated proxy, credential cache and field
order owners. Root confirms the credential owner and the cited negotiated
and field-order caller scopes. A134-A138 are source findings awaiting
controls and remedies. A125, A129 and A132 extend to these owners.
No production credential-cache, route, DNS or browser-order defect follows
from these test-fixture findings.

The [Alt-Svc remedy](https://github.com/bywayhq/phantom/blob/1da2ba311d45645dcf8725d7153f13ac884069aa/docs/internals/architecture-audit/alt-svc-remedy-native-independent-addendum-b6a5acc3.md.txt)
passes all 44 methods on each host. Its source review covers all three
changed owners. It closes the Alt-Svc caller scope of A132, while the
negotiated callers remain open. These focused runs do not prove the final
combined gate or whole-source audit. Earlier baselines remain unchanged.

## Initial source evidence

- A01: `crates/phantom/src/body.rs`, `poll_wire_frame` and
  `poll_decoded_frame`. Ready wire frames reset idle activity without
  checking total expiry. Decoded output checks expiry. Phase futures give
  a ready operation precedence; the body contract needs explicit review of
  that distinction before the remedy is chosen.
- A02: `crates/phantom/src/session.rs`, `validate_policies`, and
  `session/admission.rs`, `Admission::new`. Tokio 1.53.1's semaphore
  constructor panics above `Semaphore::MAX_PERMITS`. Check the effective
  profile bound as well as each caller override.
- A03: `crates/phantom-quic-btls/src/backend/client.rs`,
  `with_tls_profile` and `start_session`. Discarding the cache on disable
  also prevents a later early-data opt-in from using its old ticket.
- A04: `crates/phantom-net/src/address_cache.rs`, `clear`,
  `cached_or_pending`, and `Publisher`. Keep an outstanding-work reservation
  through clear and release it with the task, while excluding stale results.
- A05: `crates/phantom-net/src/proxy/http2_pool.rs`, `acquire`,
  `RouteState`, and `SetupReservation::fail`. Test two failures before an
  older waiter is polled; keep failure outcomes tied to their attempts.
- A06: `crates/phantom/src/sse/event_source/request.rs`, `SseRequest::send`,
  and `request/template.rs`, `expand_on_route`. Hook protection does not
  govern generated template defaults.
- A07: `crates/phantom/src/websocket/connection.rs`,
  `poll_pending_incoming`. Surrounding transport failure paths discard
  ownership; the stream-shutdown failure path does not.
- A08: `crates/phantom-profile/src/request_template.rs`, `websocket.rs`,
  and `proxy_connect.rs`. Redact arbitrary literal and conditional values
  rather than guessing sensitive header names.
- A09: `crates/phantom-quic-btls/src/key_schedule.rs`, `next_packet_keys`,
  compared with the implemented fallible backend key-update trait.
- A10: `crates/phantom-quic-btls/src/transport_parameters.rs` and `wire.rs`.
  Structural validation accepts narrow GREASE identifier widths, but the
  entropy draw uses the full reserved identifier range.
- A11: `scripts/ci/check-unsafe-boundaries.sh`. Injecting status 2 from the
  manifest `git grep` prints an error, then reports success and exits 0.
- A12: `crates/phantom-profile/src/request_template/capture.rs`,
  `decode_hex`. This is test infrastructure, not a runtime HTTP parser.
- A13: `crates/phantom-quic-btls/src/backend/client.rs`, `map_start_error`.
  Reconcile the pinned provider trait's error options before selecting a fix.
- A14: `scripts/dev/with-cargo-lock.sh`, `reclaim_stale_lock`. The dead
  owner check and later rename do not establish that the renamed directory
  still belongs to that owner. Reproduce the interleaving in an isolated
  repository before selecting the replacement ownership mechanism.
- A15: `crates/phantom-profile/src/browser/chrome/android.rs`,
  `model_value`, and the Edge and Opera constructors that use it. An
  embedded tab is a valid generic header value but not a structured string.
- A16: `scripts/ci/check-tool-pins.sh`, `search`, and its
  process-substitution loops. An injected ShellCheck search failure leaves
  the checker reporting agreement with exit status 0.
- A17: `scripts/ci/report-upstream-freshness.sh`,
  `built_in_chrome_recipe`, and the report arguments. The validated local
  fixture paths are unavailable in the caller. Valid mocked upstream inputs
  reach an unbound-variable failure before producing the report.
- A18: `crates/phantom-testkit/src/dns.rs`, `Drop` and `serve`.
  Aborting the main task does not abort detached delayed replies.
- A19 and A20: `crates/phantom-testkit/examples/capture_client_hello.rs`.
  Check parsed listener addresses before binding, and validate decoded SNI
  as single-line metadata before writing the capture document.
- A21: `fuzz/README.md`, `fuzz/src/http1_response/tests.rs`, and the
  fuzz workflow. The byte bound excludes the head-byte limit, but 101 short
  fields fit below 16 KiB. This is a coverage claim, not a parser defect.
- A22: `crates/phantom/src/header_hook.rs` and the customization/template
  guides. Redirect stripping names four credential headers; custom fields
  are not protected by that rule. Configured hint names have separate
  stripping, so the correction must not promise categorical retention.
- A23: `crates/phantom/src/session/alt_svc/https_records.rs`, `state` and
  `Cache::complete`. A custom resolver can remain pending indefinitely.
  Cache churn drops its bookkeeping without stopping or counting its work.
- A24: `crates/phantom/src/request/replay_buffer.rs`, `Shared::keep`.
  Examine replay cursor and wire contracts before dropping empty frames.
- A25: `crates/phantom/src/request/template.rs`, cached encodings and
  `expand_on_route`. Compare active forwarding defaults with response
  decoder policy, including malformed active values before I/O.
- A26: `crates/phantom/src/request/template.rs`, public prepared-template
  Debug. Its private cache copies arbitrary template header values, which
  bypass the profile field formatter's redaction.
- A27: `crates/phantom-net/src/proxy/socks5.rs`, `from_socks_error`.
  The resolved dependency uses `UnknownAuthMethod` both during method
  selection and for an unknown CONNECT reply status.
- A28: `vendor/quinn-proto/src/frame.rs`, ACK_FREQUENCY decoding and
  `read_as_draft02`. The older format's flag occupies one byte in
  [the IETF wire description](https://www.ietf.org/archive/id/draft-ietf-quic-ack-frequency-00.html#section-4).
  Investigate the advertised receive format and parsing boundaries before
  changing the canonical patch series or public format names.

## Executed evidence

The starting implementations fail the A01, A02, A03, and A04 regression
tests. A01 returned ready buffered data after a one-second deadline had
elapsed by two seconds. A02 accepted an oversized bound. A03 retained
resumption after disabling tickets. A04 kept two live resolver futures
under a shared-work limit of one after clear and caller cancellation.

The composed first four fixes pass 1,704 unit tests: 584 in the HTTP
client, 949 in the transport crate, and 171 in the QUIC backend. Independent
review approved their changed paths and test controls. A08's three
redaction regressions fail on the starting implementation and pass after
the fix. The documentation checker reports zero errors and warnings.

A05's original failure is replaced by a later attempt in the baseline
regression. The fixed proxy pool passes all seven unit tests, including
failure ownership and cancelled-setup controls. A10's baseline accepts a
narrow width but fails encoding. The fixed QUIC crate passes all 174 unit
tests, including the original captured-parameter and version fixtures.

A07's real reset HTTP/2 stream makes the post-Close shutdown fail while
the original WebSocket retains its socket and admission. The corrected
HTTP client passes 585 unit tests. A09 removes stale broad dead-code
allowances, confines the unused alternate constructor to tests, and
documents the implemented fallible key-update boundary. The QUIC crate's
174 unit tests also pass with that cleanup. Independent source review
approved both changes and the later Sink close-error repair. Both Sink
regressions fail on the original implementation; all three close-error
tests pass together and all-target, all-feature Clippy passes.

The isolated A14 race permits two live commands in one configured slot,
then deletes a live holder's lock when the displaced holder exits. No
Cargo command or active repository lock participates in this reproduction.
Recovery must not assume that a dead wrapper means its child work ended.

A06's original inherited-default regression stalls in network setup rather
than rejecting the default. The fixed stream binary passes all 40 SSE
tests, including active and inactive defaults, redirect activation, optional
slot order, ID reset, client-hint controls, and cross-origin redirects.
The composed client passes 593 unit tests and all-target, all-feature
Clippy. Two existing unit-test callers needed the new managed-field argument.

A12's six original profile readers fail malformed-input controls. The
corrected profile passes 307 unit tests and all-target, all-feature Clippy.
A seventh testkit reader accepts `+1` on the baseline; its strict-hex fix
passes all ten browser ClientHello fixture tests. These are fixture reader
contracts, not production TLS parsing claims.

A15's baseline accepts a tab in a model string. The checked constructors
pass the same 307 profile tests, including ASCII, quoting, escaping and
captured default-model controls. Independent source review approved them.

The complete development-tool suite passes all 35 tests on Windows and on
a native Linux checkout. The Linux run includes the offline freshness report
with jq. An initial WSL run against the Windows worktree failed because of
Windows Git paths and line endings. The native checkout also needed an
installed rustfmt toolchain; it passes with Rust 1.99.0. These failures and
the successful runs remain in the local logs.

A13's actual verification-disabled provider returns endpoint shutdown on
the original implementation. The corrected provider passes all 177 QUIC
unit tests, including invalid ECH safe formatting and valid startup.
The separate endpoint regression fails with one retained CID after failed
startup. The corrected endpoint passes its three Initial-key tests, with
repeated failures, existing connections and subsequent startup controls.
Independent source review approved the categories and CID cleanup.
Canonical archive replay and complete vendor builds remain separate checks.

The complete `quinn-proto`, `quinn`, and H3 vendor checks pass in a native
Linux checkout at `1e44399e`. That checkout preserves the four H3 license
symlinks that were flattened in Windows. These are real archive replay,
Clippy, build and selected-test checks, with no mocked Cargo steps. They
resolve the previously recorded H3 replay mismatch for this revision.

A18's baseline retains one reply socket owner after the main server task
is aborted. Its independent normal-delay control passes. A19's original
argument parser accepts a wildcard listener. A20's original UTF-8-only SNI
logic, extracted unchanged into a test helper, accepts both CR and LF.
The fixed testkit passes 88 library tests, ten fixture tests and six capture
example tests, plus a normal library build and all-target, all-feature
Clippy. The capture test iterator needed an owned-array correction to
compile, and the fixture test now returns an error rather than using a
forbidden panic shortcut. Independent review approved the production fix
and the owned-array correction.

A23's baseline starts another lookup with the configured capacity of one
while the first origin's lookup is still pending. The proposed remedy bounds
work per runtime, preserves sharing until a task ends, and keeps completed
records in the globally bounded cache. Runtime independence remains an
explicit contract; no global bound across caller-created runtimes is claimed.

The A23 fix passes all 597 client unit tests, seven HTTPS-discovery request
tests, and its 17 focused lookup tests after a fixture lint correction.
Independent review approved its task reservations and cancellation paths.

A24's baseline retains the first empty DATA frame at a zero-byte allowance.
All three new controls fail before the fix; the corrected buffer passes all
15 replay tests. This deliberately changes replayed empty-frame behavior,
with a breaking commit and migration note for both buffered APIs.

A25's loopback proxy captures `Accept-Encoding: deflate`, while the original
response reports no selected decoding. Its direct gzip control passes.
A26's generated canary appears in the original prepared-template Debug;
the nested builder control already passes after A08. The composed fixes pass
604 client unit tests, 21 response-decoding request tests, and 48 selected
SSE stream tests, plus all-target, all-feature Clippy. An initial stream
filter selected zero tests; only the corrected run supplies SSE evidence.

A27's actual no-auth SOCKS connection then receives an unknown CONNECT reply
and reports Authentication instead of Negotiation. The regression fails on
the starting implementation. The correction passes 98 proxy tests and
all-target, all-feature transport Clippy. Explicit authentication rejection
retains its category and typed source. Independent review approved the change.

## Further regression evidence

A28's real connection baseline accepts invalid flag `0x40` as a zero
threshold after consuming the following padding. Canonical flag controls
and the modern format's four varint widths pass on the same baseline.
The repair passes all 357 Quinn-proto unit tests, including every flag byte
and valid/invalid early-space controls. Independent review checks all three
parser sites and exact canonical patch replay. The renamed forks move to
Quinn-proto `.4`, Quinn `.4`, and the H3 family `.9`. Complete Windows
Quinn-proto and Quinn vendor checks pass. The full H3 vendor check passes
in the native Linux checkout at `27acd346`, with exact archive replay,
focused tests and dependent builds. Full integration gates remain pending.

A29 retains the real bound-socket option rejection and disabled-option
assertions. Its setup now uses the shared binder with no UDP options.
All 37 UDP tests pass on Windows, including the controlled reserved-port
retry and the actual `WSAEINVAL` check. No production socket behavior changes.
Independent review approves the test repair.

A30's Windows reproduction waits for an owned child before assigning its
parent to the attempt's job. The container reports containment, but the child
is outside that job and survives its close. The parent stops, and held
process handles safely stop the surviving test child. Ordinary attempt
cleanup also sweeps its temporary directory, so this does not establish
that every normal cancellation leaks. The confirmed gap is early child
creation before job assignment, including abrupt runner exit without the
sweep. A launch barrier or atomic ownership mechanism still needs design,
regression tests and independent review.

A31's separate Windows controls start harmless owned processes with profile
paths. The matching process stops, but a different profile whose path shares
the prefix also stops. An apostrophe in the target path prevents the matching
process from stopping. Every surviving control is safely terminated through
its own retained process handle. The matrix CLI rejects quoted work paths,
but the shared browser cleanup helper has no equivalent restriction.
The process-ownership lane is repairing matching and data transfer together.

A32 qualifies `EchConfig::is_supported` and its parser test comment. The
method checks supported parameters and names, while cryptographic public-key
validation happens later in HPKE setup. The native oracle in the parser test
checks configuration-list acceptance, rather than encryption or a completed
handshake. Independent review approves the source correction at `ba05c009`.
All seven existing ECH parser tests pass with the actual native oracle.

A33 moves the three short `accept_ch/tests.rs` tests inline in `accept_ch.rs`.
They need no separate fixture directory. The test bodies remain unchanged
apart from indentation, and the unnecessary path annotation is removed.
Independent review approves `44ae0f3e`; all three tests pass. No runtime
defect or broader abstraction change is established.

A34 traces the active HTTP/3 control stream through `FrameStream`,
`BufRecvStream` and frame decoding. The decoder waits for the complete
declared payload before discarding an unknown frame. The real decoder retains
16,389 bytes after the first independent 16 KiB payload chunk of an incomplete
2 MiB unknown frame. A separate oversized SETTINGS header returns Pending
instead of rejecting the declared payload before buffering. Those two tests
fail at `a077e28c`; 27 selected decoder tests pass, including a fragmented
unknown frame followed by coalesced GOAWAY. Independent review approves the
regression tests. The canonical repair remains in progress. Large unknown
frames must retain the protocol's ignore behavior. These observations concern
decoder retention, rather than a complete transport-memory measurement.

A35 compares the documented pre-split header bounds with HTTP/1.1 and HTTP/2
preparation and the actual HTTP/3 factories. One caller Cookie containing
101 short pairs passes the supplied-field bound, then fails when semantic
validation counts the emitted crumbs. A separate 100-pair Cookie whose
original name and value total exactly 32 KiB fails when repeated names count
toward the byte bound. Extended CONNECT uses the same validation path.
At `155fe999`, the three preparation regressions fail and ten controls pass,
including captured QPACK bytes and generated framing and capsule fields.
The facade's exact HTTP/3 request also fails before a successful exchange.
The remedy must retain protocol validation, supplied-field limits, generated
field accounting, and the separate peer SETTINGS field-section bound.

The initial capture repair's Windows run selects 85 tests but fails the
abrupt-runner-death control with the dependency-managed interpreter. A delayed
assignment regression then confirms that the Windows virtualenv redirector
creates the actual interpreter before job assignment. The repaired bootstrap
starts that actual interpreter, while the original tool keeps its virtualenv,
arguments, environment and exit status. Independent source review approves
those startup and matching paths. At `1d5f3f99`, all 86 focused capture tests
pass on Windows and on native Linux, where eleven Windows-only cases skip.
Shutdown after a separate cleanup failure remains open as A37.

The A34 repair at `6274e222` passes 36 decoder tests and 52 connection tests,
including actual QUIC peers, header-only excessive-load rejection and missing
SETTINGS. Independent review approves incremental skipping, cancellation,
EOF, following-frame parsing and request QPACK reservations. Identity refresh,
canonical full replay and integration gates remain pending. The declared
known-payload cap is not a whole-buffer claim; A36 examines complete malformed
known payloads separately.

The A35 repair at `a21cd99c` passes all 185 transport HTTP/3 tests and seven
facade cookie tests. Its original facade error source reports too many headers;
the correction observes all 101 distinct Cookie values in order and receives
204. Independent review confirms that original limits, generated fields,
protocol semantics and peer emitted-field limits remain enforced.

A36 concerns `proto/frame.rs`, its length-limited payload reader, and the
frame decoder's incomplete-input handling. A single-ID frame can parse its ID
without consuming the rest of its declared payload. A completely present
payload with an incomplete inner varint can also return Incomplete, even
though more outer bytes cannot repair that payload. PUSH_PROMISE shares the
inner-varint path. At `cb06e4af`, two real decoder regressions fail and 39
controls pass, including valid wide IDs and fragmented outer input. The QUIC
peer regression receives GOAWAY instead of the required frame error.
Independent review approves the regression stage; the runtime repair is in
progress through its separate canonical patch.

The A36 correction at `05357b29` maps inner truncation to a frame error only
after the declared outer payload is complete. Successful known-frame parsing
must consume that payload. Independent review approves the source and its
canonical patch. With the H3 family identity updated to `.10`, 41 decoder
tests and 53 connection tests pass. The latter includes the actual QUIC peer
that previously received GOAWAY. Final canonical vendor checks and integration
gates remain required.

A37 uses controlled failures in capture shutdown. At `ec51ac17`, both a first
container-close failure and a first profile-sweep failure leave the second
container unclosed. Two other tests show interruption propagating the cleanup
error before worker joins and publishable results. All three tests fail on
that baseline, with two failing subcases in the first test. No real processes
are killed by this fault injection. The repair must finish cleanup fan-out,
retain the original causes, join workers and publish unsuccessful results.
The first repair at `0afa0f4e` passes all four focused tests, including a success
racing interrupted cleanup and removal of its completion record. Independent
review identifies a remaining second-interruption path during cleanup or join
that can still skip reporting. That path remains open.

The final A37 correction at `e7ac6f87` protects main-thread cleanup and joins
from another SIGINT, then restores the previous handler. It matches the whole
owner name before the final attempt suffix, preserving overlapping names such
as `foo` and `foo.1`. Completed owners keep their results and resume records;
an active owner whose cleanup fails loses its success record. Independent
review approves the final source. All 96 focused capture tests pass on Windows
and native Linux at `0ad0d560`; eleven Windows-only cases skip on Linux.
The controls cover both cleanup operations, per-owner attribution, reporting,
resume, completion races and actual repeated SIGINT. Full integration remains
pending.

A38 examines the two historical server field-section failures. Both tests
install simulated peer limits before server accept polls real client SETTINGS.
The application-settings patch changed first-write state into replaceable
state, so actual default settings correctly replace those simulated limits.
The server still checks encoded field-section sizes before response and
trailer writes. The existing vendor caveat and roadmap interpret these mocks
as absent runtime enforcement without sufficient evidence. Corrected tests
must advertise real limits, assert their receipt and retain the client through
the server assertion. No production repair is supported by this source trace.

The historical two tests fail at `0ad0d560`. The first corrected source stage
does not compile because the generic builder needs a buffer type and a borrowed
header value cannot compare directly with a String. The follow-up at `0fdbaa16`
fixes both test type errors. Its two oversized-section rejections and two exact
42/539-byte acceptance controls pass on native Linux, with unchanged production
code. Independent review covers the original test design; the small compiler
correction is independently approved. Vendor notes and the roadmap now distinguish
the stale mock from actual enforcement. Final fork identity and vendor gates
remain required.

A39 traces `ConnectUdpProxy::expand`, the shared HTTP/3 proxy-path preparation,
and origin authority parsing. Explicit port zero reaches template expansion
and produces a `target_port` of zero. [RFC 9298 section 3](https://www.rfc-editor.org/rfc/rfc9298.html#section-3)
requires a target port from 1 through 65535. A pre-I/O request regression and
inclusive endpoint controls are still needed. Direct-route port policy is
outside this candidate's proposed remedy.

A40 reads the actual shared H3 `Pair` fixture. Its server and client endpoints
bind `[::]:0`, while their connection target is IPv6 loopback. This violates
the host guidance for loopback-only tests and bypasses the bounded Windows
reserved-port retry used by first-party fixtures. A standalone canonical
test-harness repair must bind loopback, retry only Windows error 10055 and
preserve every other error. This is a fixture defect, not a production listener
or fresh browser-fidelity finding.

The canonical A40 correction at `256b034a` prebinds both endpoints on IPv6
loopback, then constructs their existing Quinn configuration over those
sockets. Independent review confirms equivalent TLS and transport setup and
unchanged error returns. All 377 H3 unit tests pass on Windows with the `.11`
identity, including seven socket controls, the four real peer-limit controls,
and the earlier decoder and connection regressions. Native Linux and full
canonical vendor verification also pass at `70cf715d`: 377 package tests,
all-target/all-feature Clippy, canonical archive replay, byte comparison,
selected regression groups and dependent builds. Final integration remains
pending.

At `6b495664`, A39's unit test accepts zero instead of returning an error.
Five related template controls pass. All three public request regressions
observe an incoming proxy connection: TCP on the HTTP/1 and HTTP/2 legs,
and QUIC on the HTTP/3 leg. These are explicit failed I/O observations,
rather than timeouts or unrelated network failures. Independent review
approves the test design. The remedy rejects zero during shared preflight
with InvalidTarget and retains a distinct private cause.

A41 runs the real multi-thread stress test with
`PHANTOM_H3_STRESS_ITERATIONS=0` at `6b495664`. The runner reports success,
zero iterations, and zero outcomes for both scenarios. Invalid strings also
silently select the default in the current parser. Configuration must reject
zero and malformed values while retaining ten iterations when absent.
This is a test validity defect, not a production protocol failure.

A39's correction passes 17 focused unit tests and all 28 CONNECT-UDP
integration tests on Windows at `9f63a129`. The unit controls include private
typed causes and preserved origin-form errors. The three previously failed
requests now return InvalidTarget without the observed proxy connections;
valid requests still exercise every outer protocol. Independent review
approves the source, and its InvalidTarget documentation finding is fixed
at `779f28ea`.

A41's correction at `2cb59371` passes five parser controls on Windows.
The real stress test now fails immediately for zero. With seed 41, one
iteration observes each scenario once; the absent setting observes each
scenario ten times. These positive controls pass. Independent review
approves the function and confirms the Rust 1.88 APIs from resolved source;
that is not an executed MSRV check. The grouping finding is fixed at
`779f28ea`. Native verification initially stops on missing Cargo in PATH,
then on missing CMake before building. After supplying Cargo's path and
installing CMake 3.28.3, all A39 and A41 controls run on Linux at `2cb59371`:
17 unit and 28 CONNECT-UDP tests pass, as do five stress parser tests.
Zero exits 101 with its configuration error before either scenario runs.
The one-iteration and absent-setting controls observe both scenarios once
and ten times respectively. This remains focused evidence, not a full gate.

A42 corrects the selected fork formatter commands and package/lockfile
instructions at `01574f2e`. HTTP/2 notes now state the split-cookie and
explicit proxy-authorization exceptions to the sensitivity rule. Independent
review confirms the exceptions against the applied encoder and public docs.
The three selected package formatter checks and ShellCheck 0.11.0 pass on
native Linux. The documentation checker reports no errors or warnings.

A43 imports eleven real TLS fixture controls in `3e8d694e` and `8ab9482f`.
The initial compile fails because an example crate root needs an explicit
path to its companion test module. The corrected source compiles, but ten
controls fail while verifying the generated self-signed certificate, before
they reach the proposed resource contracts. The stalled-handshake control
reaches its outer timeout without a server operation deadline. Fixture
authentication must be corrected and positive controls must pass before
these failures can establish the remaining production defects.

A44 and A45 use canonical wrapper regression patches at `a16ab215`.
The isolated SNI test aborts inside `raw_msg_callback`: the replacement
context contains no data for the retained native callback. The test
executable exits with `0xc0000409`; the outer command reports 127. This
is an observed non-unwinding callback panic, not an observation timeout.
The separate Debug test exits 101 because the decimal ClientHello canary
appears in formatted output. The existing key-update control passes.

The production correction at `cb98b391` retrieves callback data from the
original context owned by `Ssl::new`, as the session callback already does.
`SslMessage` Debug retains direction, version, content type and byte length,
while the public message bytes remain accessible. All three controls pass
on Windows. Independent review verifies ownership against the pinned
native construction and context-switch paths and reconstructs the canonical
patch. `a80d417c` advances both wrapper-family identities to `.6`, updates
their exact pins and three lockfiles, and documents the changes. Final
native vendor checks pass, including all-target Clippy, nine selected test
groups and Rust 1.85 checks. Windows checks also exit zero and pass those
tests, but Git emits a README symlink permission error during staging.
The staging script verifies that exact link target and materializes its
contents as a regular file on Windows. Full patched-tree byte comparison
then passes. This explains the flagged line; it does not make the log clean.
Final composed gates and CI remain pending.

After fixture authentication is corrected at `03e712bc`, A43's positive
EOF, released-slot and wrong-CA controls pass. Nine production regressions
fail for the intended resource and ownership contracts. The correction at
`5fe62ee4` passes all 20 Windows and Linux tests, including actual TLS peers, corrupt
TLS versus speculative EOF, origin-error cleanup, shutdown failure retention
and a sustained body drip. Independent production review approves the
ownership and error paths. Cancellation Drop aborts owned tasks; awaited shutdown
explicitly drains them. Fixture encoding and DNS answers remain unchanged.

A46's four independent cookie-cache regressions fail at `625c85d8` because
formatted retained entries expose their canary. The canonical correction
at `bc27b126` and `5584135e` marks inserted and reused dynamic entries after
encoding, preserving the wire policy. All four tests pass. Independent
review approves the index-to-slot mapping, lookup equality and proxy rules.
With the `.11` identities, all 14 first-party captured HPACK replay tests
pass on Windows at `56fd2cf7` plus the restored lock selections committed
in `0407bc1a`. These checks do not promise redaction of every connection
buffer. Final `.11` HTTP/2 and HTTP/1 dependent vendor checks pass on Windows
and Linux at `5fe62ee4`, including canonical archive replay, byte comparison,
selected formatting and Clippy. HTTP/2 runs 47 client controls and all 157
packaged non-fixture unit tests, with one existing ignored test; HTTP/1 runs
all 61 unit tests. Whole integration and platform CI remain pending.

A47's baseline executes a harmless marker substitution through both image
roles in the exact pinned runner shell boundary. No real Docker command is
executed. The regression suite has 18 failed subcases at `e6447d5b`.
The correction at `a678ec76` permits only shell-safe image characters before
either registry mutation. All eight test methods pass, including atomic
failure and legal spelling controls. Independent source review approves
the actual assignment contexts. This validates a shell boundary, rather
than every Docker reference or an external interoperability run. All 25
conformance tests and pinned Ruff checks pass on Windows at `5fe62ee4`.

A48 traces a legal `SETTINGS_HEADER_TABLE_SIZE = u32::MAX` through frame
decode, peer settings, the writer and HPACK resize. The profile's three-quarter
choice evaluates `max_size * 3`, which can overflow usize on 32-bit targets.
Current CI uses 64-bit hosts; no explicit 64-bit-only restriction was found.
At test-only `14110f94`, the actual i686 build passes its threshold control
and fails both large-table tests with multiplication overflow. A release
build also fails the smaller large-table control: the encoded field begins
with 0 rather than the independently expected incremental-indexing byte 64.
No large allocation is needed. The correction must preserve the declared
Rust 1.68 source API and existing inclusive/fractional thresholds. The first
release launcher fails before Cargo; the corrected launcher produces this
actual optimized-build result.

The focused correction at `9f62282e` replaces both multiplications with an
exact integer threshold using subtraction and division. All three tests
pass on actual i686 debug and release builds, including maximum peer size
and twelve inclusive/fractional boundary cases. The source retains the
fork's declared Rust 1.68 API. Independent review and final composed fork
identity, replay and integration checks remain required.

A49 traces raw WebSocket extension responses from the HTTP/1, HTTP/2 and
HTTP/3 callers into compression negotiation. Unicode `str::trim` can remove
NBSP around a recognized parameter name or numeric value. RFC 6455 section
9.1 requires HTTP whitespace and token or quoted-string grammar. The
tests at `13e89d3a` pass seven controls and fail two cases because NBSP is
accepted in recognized names and values. The focused correction at
`d1319fc3` trims only space/tab and passes all nine controls. Independent
review approves the canonical source and direct handshake callers. This is
configuration/parser execution, rather than actual opening over all three
protocols. Inherited full-file formatting outside the changed block remains
unchanged. Fork identity, full replay and integration gates remain pending.

A50 traces the QUIC interoperability example's partial-file cleanup.
`create_new` rejects an existing partial file before a request starts, but
the caller then deletes that same path. Batch cleanup also removes every
planned partial path, including paths this invocation never created.
A pre-existing sentinel test can establish this without a network request.
The remedy must retain exclusive creation and clean up only owned files.

At `753ef8c0`, the actual Windows example test run passes seven controls and
fails both sentinel-preservation regressions because the existing file was
deleted. The passing controls include an authenticated loopback HTTP/3
download and a 503 response that removes its created partial. The baseline
establishes file-ownership defects. The first correction passes fourteen
Windows controls. At `c34401e7`, two further real-peer tests replace an
in-flight partial path. A 503 response deletes the replacement. A successful
response publishes its bytes instead of the body written to the original
file. Fourteen controls still pass; these two fail. Path ownership remains
unresolved, and the first correction is not final approval.

The replacement at `9cc681ad` uses an exclusive private staging directory,
leaving the shared legacy path outside its write and cleanup namespace.
Create-only hard-link publication refuses a competing output. At `73a08ed8`,
eighteen tests pass on Windows and Linux, including actual HTTP/3 peers,
two owners targeting one output, cancellation and platform-specific failure
or permission controls. Linux Rust 1.88 compilation passes. Independent
source review approves private staging and the added two-owner test. Final
integration remains pending. The filesystem must support hard links.
Deliberate mutation inside private staging and ancestor replacement are
outside the documented ordinary-concurrency contract.

A51 is the manual Rust version-report client accepting a zero request count.
An authenticated baseline exits successfully without any request or report.
The Rust correction parses `NonZeroUsize` before reading the CA or building
the connector. The Python CLI also rejects non-positive counts before
starting its runner. Two Rust parser tests and seven Python methods pass.
The composed executable rejects zero before CA-file I/O, and actual
loopback runs finish with three default observations and one explicit
observation. Independent review approves the source. Ticket availability
wording now describes the origin-wide cache rather than promising a ticket
from the most recent connection. These runs do not refresh browser evidence.

A52 traces successful Autobahn results into a finally block that ignores
the force-removal exit code. Inspect, log collection and removal also lack
operation deadlines. A detached launch timeout occurs before the cleanup
flag is set. Controlled subprocess failures must establish these paths
before a remedy. No Docker failure or surviving-container claim is made.

At `753ef8c0`, ten controlled test methods execute the real run, CLI and
readiness orchestration. Four methods pass. Six fail, with seven reported
failures because both log and removal deadline subcases fail separately.
The results reproduce ignored cleanup statuses, missing deadlines, lost CLI
cause text and omitted cleanup after uncertain launch. External commands
are controlled fixtures; no real Docker execution is claimed.

The correction verifies a run-specific ownership label and immutable
container ID before collecting logs or removing a container. Cleanup
operations have finite deadlines. Log failures still allow removal, and
suite and cleanup failures survive together in diagnostics. Twenty focused
methods and the composed forty-four-method conformance suite pass on
Windows. Independent source review approves the correction. Real daemon
cleanup, actual signals and late creation after a timeout remain unverified.

A53 traces the outer QUIC runner timeout into file restoration without an
external resource owner. The pinned runner's ordinary timeout does stop
its case, but compliance can be interrupted before that path. Fixed global
container names make blind removal unsafe for concurrent owners. A remedy
needs verifiable ownership and scoped cleanup; actual container survival
has not been measured.

The initial A53 composition at `cb935f2f` passes the applicable 143-method
conformance controls on Windows and Linux, including an actual Linux
descendant-exit observation. Independent review then reproduces two omitted
recovery contracts. A denied log existence check bypasses restores and loses
the primary timeout. A failed automatic-checkout removal drops previously
retained scratch paths from the summary. The signed test-only checkpoint at
`9fd7b1a7` passes eighteen controls and fails those two contracts. The repair
at `de146f12` guards the log probe and combines recovery paths after checkout
cleanup failure. Independent review approves that source and repeats both
recovery controls. The composed 145-method suites pass all applicable checks
on Windows and Linux, including actual Linux descendant exit before restore.
Final gates and live Docker verification remain separate.

A54 executes the version-report Python runner with controlled certificate
and server boundaries and actual filesystem publication. A normal run
closes its server and retains caller outputs, but leaks internal certificate
scratch space. Preparation failure also leaks it. A real port-file write
failure after acquisition skips server close. One positive control passes
and three intended ownership controls fail. The remedy must own scratch
space for the server lifetime and cover publication with close-finally.
These controls do not prove real QUIC shutdown.

The A54 correction owns internal scratch through synchronous acquired-server
close and includes address lookup and caller port publication in close-finally.
Independent source review approves the source. The composed 51-method suite
passes on Windows and Linux. Actual default-three and explicit-one loopback
runs retain caller outputs and remove certificate scratch. Final composed
review and gates remain pending.

A55's configuration regression observes a forbidden sixth iterator read
after five values and still receives InvalidRequest. Four independent
compression controls pass at the test-only checkpoint; the iterator test
fails. Its remedy takes at most five values before applying the existing
four-parameter validation and checks profile length before copying.

A56's signed WPT baseline runs all 29 full-manifest cases through controlled
boundaries. Seven methods pass and eight fail for resource lifetime,
startup, cleanup, interruption and retained-summary contracts. The pinned
server uses an unbounded shutdown wait and daemon request threads. The
remedy places it in an owned child process with bounded startup and reaping,
retains infrastructure errors separately from observed case failures, and
keeps scratch until reaping. This is not a measured native thread leak.

The final A56 correction at `91caf511` retains the acquired native process
before CPython spawn initialization can raise. It preserves the first parent
interruption and accompanying errors across construction, startup, shutdown,
file removal and summary publication. Independent review approves that source.
Composition at `d0ee3e97` passes the 122-method conformance suites on Windows
and Linux, with one explicit platform skip each. Actual native controls cover
Windows post-spawn serialization and Linux post-spawn bootstrap writing.
Those fixtures establish child lifetime and reporting, without TLS sockets or
live WPT acceptance. The breaking summary migration is documented. Final
combined architecture review and integration gates remain open.

A57's signed TLS-Anvil baseline observes the exact two required IDs and
strict counts. Five methods pass; failed-removal and deadline controls fail.
The remedy verifies a unique ownership label and immutable container ID,
bounds removal, and retains suite and cleanup causes together. Controlled
subprocess fixtures do not establish actual Docker daemon behavior.

Root review of A57 at `2c9dbead` reproduces another interruption gap:
log-retention KeyboardInterrupt skips
the second log and summary, losing an observed suite exit of 7 and removal
exit of 9. Eighteen existing lifecycle methods pass; the added controlled
regression fails because the retained summary is absent. Three further
retention controls fail at the test-only checkpoint. The remedy at
`78e664a0` passes all 37 owner and TLS methods and has independent source
approval. Composition retains both failure causes and valid suite results,
shares verified removal with Autobahn, and adds both shared paths to the
TLS-Anvil push filter. The initial 84-method suite passes on Windows and
Linux. Its composed review then exposes two Autobahn retention gaps:
interrupted summary writing loses prior suite and removal causes, and
interrupted log writing loses a failed log command's status and diagnostic.
The signed `9b778907` baseline has 22 passes and two intended failures.
At `54ebd468`, both existing retention handlers preserve these causes and
lone interruption identity. All 88 composed methods pass on Windows and
Linux. Independent review approves the corrected source and confirms both
CLI paths with 21 passing controls. Final integration remains pending.
An absent container
inspection does not prove that a timed-out daemon launch cannot create it
later. Initial whole-log reads also remain outside the retained-size cap.

The [WPT independent review](https://github.com/bywayhq/phantom/blob/1da2ba311d45645dcf8725d7153f13ac884069aa/docs/internals/architecture-audit/a56-production-independent-review.json)
requires changes at `18319655` despite its 25 passing controls. An actual
Windows child starts before Python installs its process handle. The injected
acquisition interruption returns while that child is alive and its source
and certificate files are absent. The child later exits with status 1, which
the summary does not observe. Signed acquisition baselines also fail real
SIGINT and post-spawn serialization controls. A further constructor
interruption with a control-close failure loses original interruption
identity. These repairs remain under independent review; no WPT composition
or native scenario acceptance is claimed.

A53's signed test-only checkpoint `e8bd054f` preserves four parser/registry
controls and an independent literal result/restoration control. Windows
passes those five and fails twelve cleanup, restoration and failure-report
contracts; its Linux-only process control skips. Linux passes the same five
and fails thirteen, including the actual held descendant remaining alive
when restoration begins. The fixture owns and reaps only its harmless child.
No Docker resource survival is measured. Production repair remains in its
owned lane, and composition must retain the separate image-input guard.

## Recent standards evidence

A67 retains the existing 200 ms nextest output-detection interval and changes
its result to failure. The gate also rejects both LEAK labels. Actual finite
child controls on Windows and Linux succeed under the old policy and fail
under the strict policy; their waited-child positives pass. Completion records
identify all four Linux children. A later PID-only census finds all eight
recorded parent and child paths absent. This does not prove native process
identity or reaping, and the original retry warning's cause remains unproven.
The policy is committed at `ff788ea6`; final full gates remain required.

A71's native Linux mutation changes only the early-data client setting.
Disabling it fails the selected rejected-early-data control after 20 seconds.
Restoring the exact original bytes passes. The immutable source hashes and
logs remain alongside the earlier 28-test Windows/Linux results.

A72's initial composed baseline does not compile because the explicitly
located parent changes child module resolution. A separate path-registration
commit establishes the runnable baseline at `cc5452b9`. Its seven controls
complete authenticated QUIC and H3 setup: the clean-close positive passes,
and six cancellation controls fail on each host. The remedy at `b0891f1c`
passes all 36 selected ownership and CONNECT-UDP controls on Windows and
Linux, plus formatting and targeted Clippy. Independent review approves
the remedy, explicit zero-close ordering and preserved stream-proxy tests.

A74-A76's baseline at `6535bd75` fails three controls on each host. They
observe a real pending handshake, an unrelated typed request error and two
Initial identities using one UDP address. The first remedy passes 30 of 31
controls: the remaining assertion incorrectly expects InvalidUri for an
InvalidAuthority input. Changing only that expected category at `585ba5ab`
passes all 31 controls on both hosts. Earlier failure logs and the source
review correction are retained. Header identity counting does not authenticate
the ciphertext or prove arbitrary connection-ID uniqueness. Independent
review identifies A77 as a further observer-health gap.

Fresh production standards reviews at `6535bd75` cover eight address, proxy
and platform files and eight body, driver and capsule files. Supporting
caller and resolved-dependency reads retain their own scopes. An independent
pass at `ff788ea6` confirms A78-A80. The continued source import reconciles
these records with current bytes where supported. Historical and partial
records retain those scopes; reconciliation does not constitute another
manual source review.

At `d9b1746b`, five actual Windows and Linux controls pass two positives and
fail both A78 publication cases and A81's peer completion check. A78 retains
the real resolver call, addresses and publication before rejecting the false
cache-hit flag. A81 observes the actual 200000-byte upload and exact response
before rejecting completion while the client is live. The corresponding
repairs at `3af0404e` pass all 38 cache, route and peer controls on each host,
plus formatting and targeted Clippy with warnings denied. Independent source
review approves both bounded remedies, with one cache-test paragraph repair.
The peer's existing outer handle still detaches on exceptional exit; normal
completion joins its now-inline driver. Independent review records that
remaining defect separately as A83.

A79-A80's first baseline attempt at `77646c8c` fails to compile on both hosts:
two source-search helpers need explicit borrowed lifetimes. The correction
at `2c40f126` changes only those helper signatures. The runnable baseline at
`bf6cb33d` runs 66 network controls: 53 pass and thirteen intended cause
regressions fail on each host. Five failures cover cached resolver delivery,
and eight cover interface and source binding. The uncached typed-cause
positive passes. The shared-error and typed-context remedies at `7ae9a390`
pass all 66 on each host. The client docs now describe retained original
resolver errors. Independent source review approves the composed changes.
Formatting, focused Clippy, Rust 1.88 library checks and all-feature rustdoc
also pass on both hosts at that exact revision.

A77's runnable baseline at `bf6cb33d` first observes a real literal UDP
datagram. Two identity positives pass and three observer-health regressions
fail on each host. The negative controls inject a handler receive error,
abort and await the actual receiver, and poison the actual observation lock.
They do not induce a native OS receive failure. The remedy retains fatal
causes and rejects failed or stopped observers. A fallible guard correction
preserves real lock poison without an `expect`. All 34 Alt-Svc controls pass
on Windows and Linux at `7ae9a390`. Final combined gates remain required.

A83's exceptional-owner baseline at `bdc528a5` passes two positive HTTP/2
controls and fails cancellation after an actual readiness byte on both
hosts. The owner repair passes that control. A second baseline at `5e58564f`
passes four controls and fails preservation of simultaneous typed causes
after the actual peer completes. At `7e358667`, the final correction passes
all 71 selected network controls on each host, including five peer cases.
Formatting, all-target network Clippy and Rust 1.88 checks also pass.
Independent review reads both final files and all retained logs. Synchronous
Drop requests cancellation; it cannot itself await a child task.

Fresh request and diagnostic standards passes examine actual fixture
ownership, operation grouping and independent assertions. At `7c6ff2fc`,
both hosts run 23 controls: fourteen pass and nine intended regressions fail.
A84's four negatives drive the actual plaintext and 100-continue peers.
A85's three negatives drive accepted TCP and CONNECT relays before checking
cancellation or typed late failure. A86's two negatives retain real files
and directories before checking Drop and failed removal. The eleven existing
request controls and three explicit cleanup or relay positives pass. The
original EOF-only disconnect controls are corrected separately before the
diagnostic remedy comparison. This is test-fixture evidence, not a claim
that production connections leak.

The corrected diagnostic baseline at `4e018d29` retains all five intended
failures and three passing controls on each host. Its disconnect assertions
accept the established peer-close categories and bound the post-join read.
A84's remedy at `6e55867e` replaces spawned request peers with lexical
concurrency. All fifteen plaintext and query controls pass on each host,
including the unchanged four regressions. Formatting, request-test Clippy
and Rust 1.88 checks also pass. Source review approves the scoped repair;
the shared proxy and diagnostic repairs remain separate.

The continued import records 96 evidence appends and 175 discoveries. Its
42 original reports retain byte-identical copies. Independent replay
confirms the exact updates and their scopes. The 142 discovery-only pointers
leave those rows pending. Git text attributes preserve raw report bytes and
LF inventory bytes across checkouts. The storage correction at `f081be5d`
restores the original sixteen report, plan and receipt objects after the
earlier checkpoint normalized their line endings. Original recorded hashes
remain unchanged; storage verification adds no source or runtime approval.

## Crate boundaries

The bounded crate review finds supported consumers for all five crates,
with no runtime dependency cycle or testkit dependency in production. It
does not justify a crate split or merge. Shared request, TLS-error and
source-binding types instead have redundant public paths within the network
crate. Profile settings also have module and root paths.

A58 makes shared request syntax canonical under `phantom_net::request` and
shared TLS errors and source bindings canonical at the network crate root.
Profile settings become root exports, including the twelve QUIC types and
five existing TCP bounds. Three hidden client-hint placement items remain
available for the facade. Browser recipes keep their public modules.
Callers, compile-check tests and examples migrate together. This changes
import paths without changing transport operation bodies.

Windows workspace Clippy passes with warnings denied. The selected profile
and transport error-category suite passes all 339 tests. Workspace doctests
pass 143 cases and retain five ignored peer-library examples. All-feature
rustdoc and both workspace format checks pass. The eight inventories use
the pinned generator and nightly. After canonicalizing the deliberately
retired aliases, the network inventory has no added or removed signatures.
The profile changes beyond aliases record earlier reviewed fallible Android
factories and redacted Debug implementations. Provider and testkit snapshots
are unchanged. Linux also passes the selected 339 tests, 143 doctests,
Clippy, both rustdoc configurations and Rust 1.88 checks. Path and Git
downstream checks pass on both hosts. The final combined gate remains pending.

A59 corrects the design statement about runtime ownership. The existing
deadline service starts lazily and lives for the process. Request I/O still
uses the caller's Tokio runtime. Runtime implementation changes are outside
this audit's scope.

## Rejected candidates

- Nonempty `Bytes` may share a larger backing allocation. The replay limit
  explicitly counts data bytes, so this is a documented boundary rather than
  proof of a violated whole-allocation limit.
- An empty relayed datagram has stride zero. The pinned Quinn endpoint skips
  its processing loop for length zero, so this path does not divide by zero
  or spin. This is source evidence, without a new runtime test.
- TLS profile Debug includes ECH configuration. Those records contain public
  server configuration, and inspection did not establish a private-key or
  password disclosure. Arbitrary request header values remain a separate
  redaction contract.

## Integration state

The audit lane is in [draft PR 197](https://github.com/bywayhq/phantom/pull/197).
All 43 PR checks pass at `7c88d128`, including macOS and Windows. Later
changes need their own CI results. No audit change has merged into `main`,
which remains at `df2ae9b7`.

At `a9c7ebbc`, Windows and Linux each pass 79 existing trailer, client and
environment-route tests. Formatting, strict all-target/all-feature Clippy
and Rust 1.88 checks pass for both touched crates. Independent source,
complete-log and exact clean-revision reviews accept this cleanup.

The earlier Linux reuse failure remains in its original evidence; its
historical cause was not captured. The proxy diagnostic established
`TooLarge` without proving the oversized packets were MTU probes.
Earlier test failures and passing repairs remain in their linked records.

Local logs remain under `C:/code/phantom/target/architecture-audit`. Focused
results do not establish a full integration gate. Remaining findings, final
composition review, exact-candidate gates and integration CI remain open.

Entries distinguish source findings, candidates and locally verified repairs.
Local verification does not close the final integration requirements.

## Required evidence

Each entry records severity, affected contract, exact source locations,
cause, reproduction or inspection evidence, remedy, tests, independent
review, integration revision, and any verification limits.

Rejected candidates record the source or contract that disproves them.
Uncertain candidates remain open for investigation. A confirmed finding
cannot move to later work merely because it is difficult to fix.

## Next

- [Coverage](coverage.md): reviewed paths and gaps.
- [Audit plan](../architecture-audit.md): scope and completion criteria.
