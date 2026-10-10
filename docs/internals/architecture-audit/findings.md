# Audit findings

Use this ledger to connect each finding to its cause, change, and evidence.
No finding is resolved by an assignment or a proposed fix.

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
| A67 | P2 | Gate and CI reject leaked test output | Nextest can report LEAK with a successful exit and the gate's log scan omits it | Independently approved same-interval failure policy and scanner; finite-child negative fails and waited-child positive passes on Windows/Linux; policy committed; original retry cause remains unproven; final gates pending |
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
| A149 | P3 | H2 proxy fixtures group imports and independent operations | Both owners have mixed import groups and dense operation boundaries | Independently reviewed lexical blocks remove both introduced closure diagnostics; at `a0d2c622` combined strict Clippy rejects only separate cookie nesting and has no H2 diagnostic; full gate remains pending |
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
| A160 | P2 | Cookie and hint fixture tasks remain owned on all exits | Raw server, proxy and request handles span fallible work | Reviewed cookie remedy at `42858688` passes all 50 request methods on both hosts, including both former actual origin/proxy lifetime failures; ordinary wire assertions preserved; independent current native review pending, hint ownership remains open |
| A161 | P2 | Cookie redirect cleanup observes both H2 drivers | Raw drivers are aborted without inspecting completed outcomes | Reviewed remedy at `42858688` passes all five redirect controls on both hosts, including formerly unreached concrete first/second/combined causes; all 50 request methods and focused checks pass; compiler-only history retained; independent current native review and final gates pending |
| A162 | P3 | Cookie and hint expiry retains concrete Elapsed | Both contextual wrappers substitute text | Two actual paused expiry failures at33715620 become green after reviewed private wrapper repair at85f2d58b on both hosts; all31 selected methods and focused checks pass; independent native review approved, final gates pending; existing client A92 remains separate |
| A163 | P2 | ALPS quiet observation preserves accept errors | Only a successful unexpected request is rejected | REQ-ST4 source-supported fixture candidate; real postresponse fault and finite quiet controls pending |
| A164 | P2 | Hint admission tests observe readiness before learning | A fixed sleep substitutes for actual preparation/admission readiness | REQ-ST5 source-supported determinism candidate; no current flake measured, delayed-scheduling control pending |
| A165 | P2 | Hint order assertions observe decoded ordinary wire order | HeaderMap keys have arbitrary unique-name order | Reviewed decoded-order observer passes both actual H2/H3 negatives within all 41 methods on both hosts at `121bbf19`; independent focused native assessment approved, missing/mismatched extensions remain errors; final gates pending |
| A166 | P3 | Learned hint assertions check actual values and absence | High-entropy positives test presence; H1 absence checks only an expected literal | Reviewed exact singleton-value and complete-absence assertions pass all four actual-client negatives within all 41 methods on both hosts at `121bbf19`; independent focused native assessment approved, positives preserved; final gates pending |
| A167 | P3 | Request fixtures group imports and use one drain helper | Local imports precede external imports; two hint helpers have identical operations | REQ-ST8 manual standards candidate; narrow source cleanup pending, no crate split justified |
| A168 | P2 | Received H3 requests retain documented ordered headers | Request parts and resolver discard the decoded ordinary sidecar | Real QPACK baseline 772b9c73 fails both order controls; reviewed named RequestParts and resolver repair at e6f01439 passes all three controls on both hosts; Linux full vendor check and Windows package checks pass; Windows archive replay unavailable locally, final gates pending |
| A169 | P2 | Trust-rejection server assertions distinguish unrelated failures | Three CONNECT TLS servers accept any handshake failure | Source-supported oracle candidate retained separately from verified caller ownership; expected client categories pass, actual server alert categories and substitution controls remain unmeasured |

## Current proxy evidence

At `2fb596ad`, all thirty cookie methods pass on Windows and Linux. The
[root receipt](cookie-lifecycle-remedy-root-2fb596ad.md.txt) records the
unchanged baseline roster, including ten previously failing controls.
Typed aggregate assertions now execute and pass. Formatting, strict selected
Clippy and Rust 1.88 checks pass. Independent source and native reviews
approve these focused results. Full integration gates remain open.

The [CONNECT baseline](connect-route-baseline-root-2234a8c3.md.txt) runs
106 methods per host: one hundred pass and six intended negatives fail.
The substring filter also selects other proxy owners. Its exact public
CONNECT subset is 24 methods: eighteen pass and six fail. The
[independent native review](connect-route-baseline-native-independent-addendum-2234a8c3.md.txt)
confirms reached assertions and their prerequisites. The remedy is in progress.

The [request-session review](request-session-standards-review-5a28f55f-final.md.txt)
records complete reads of three owners and eight source candidates. Its H3
received-order dependency trace is partial. No new runtime result follows
from these source findings. Existing A90-A92 are reconciled separately.

The following evidence describes earlier revisions.

At `2cea08af`, Windows and Linux each pass all 41 selected H2 methods.
The signed-hex and two credential-oracle negatives now pass with their
original inputs and assertions. The reviewed parser and concrete deadline
repairs retain all original wire workflows. The
[root native receipt](h2-cookie-corrected-root-2cea08af.md.txt) records
complete logs, statuses and exact signed source identities. The
[independent native review](h2-cookie-corrected-native-independent-addendum-2cea08af.md.txt)
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
[root result](proxy-owner-remedies-root-1e23deb9.md.txt) retains the prior
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

The [current proxy baseline](proxy-fixture-native-independent-addendum-199fa9ad.md.txt)
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

The [target repair review](socks-target-observation-second-independent-review-81c61f13.json)
retains complete and partial source reads separately. At `81c61f13`,
the [native addendum](socks-target-native-independent-addendum-81c61f13.md.txt)
records 55 selected methods per host: 50 pass and five local ownership or
deadline regressions still fail. The five address-form controls pass.
DNS overrides, HTTP/3 SOCKS fallback and the mapped certificate caller pass.
Formatting, selected strict Clippy and Rust 1.88 checks pass without warnings.
The IPv6 literal control observes ATYP4 over IPv4 loopback forwarding.

The [forward baseline](forward-proxy-native-baseline-independent-addendum-54c60be7.md.txt)
records ten positives and seven intended failures on each host. Original
deadline context passes before the missing timer cause fails. The completed
peer-cause control reaches typed HTTP/1 and UnexpectedEof checks first.
The deliberate poison panic is joined before the unrecorded-response failure.
The cancellation control observes a finite 150 ms window with the client
alive. Reader errors are deliberate injections over actual socket seams.
Queued-request ownership still needs complete repair and verification.

The [remaining proxy review](proxy-remaining-whole-source-54c60be7.json)
records full manual reads of negotiated proxy, credential cache and field
order owners. Root confirms the credential owner and the cited negotiated
and field-order caller scopes. A134-A138 are source findings awaiting
controls and remedies. A125, A129 and A132 extend to these owners.
No production credential-cache, route, DNS or browser-order defect follows
from these test-fixture findings.

The [Alt-Svc remedy](alt-svc-remedy-native-independent-addendum-b6a5acc3.md.txt)
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

The [WPT independent review](a56-production-independent-review.json)
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

At `6d6cd85e`, Windows and Linux each pass all 31 selected SOCKS methods.
The Alt-Svc selection passes four controls and fails its simultaneous-error
control at the intended missing-peer-cause assertion. The concrete HTTP/1
body error and unexpected-EOF checks precede that failure. Formatting,
focused Clippy and Rust 1.88 checks pass. Both combined runners remain
nonzero. The [independent native review](socks-alt-native-independent-addendum-6d6cd85e.md.txt)
records the exact source and test scope.

At `482e75dd`, Windows and Linux each pass ten H3 proxy controls, six
early-response deadline controls, 39 CONNECT-UDP origin methods and the two
previously failing H3 WebSocket callers. Formatting, focused Clippy and
Rust 1.88 checks pass. These 57 focused methods do not establish a passing
whole client suite or a full integration gate.

The earlier Linux reuse failure remains in its original evidence. It passes
in the complete current origin selection, but its historical cause was not
captured. The proxy diagnostic establishes `TooLarge` for the two WebSocket
failures without proving the oversized packets were MTU probes.

All local verification so far applies to the audit lane. Integration main
remains at the starting revision. No audit change has been pushed or merged.

Local logs are retained under `target/architecture-audit` in the integration
checkout. These are focused test results, not a full gate or integration
claim. Every finding above still needs final composition and CI evidence.

These entries are source findings or candidates. Tests, independent review,
and integration evidence remain required; none is closed.

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
