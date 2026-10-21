import { AttemptBudget, TransferControl, Client, ClientCertificate, PhantomError, PreparedBody, Profile, RequestDiagnostics, Response, profiles, type ClientOptions, type ProfileValue, type RequestTimeline, type ResponseTrailers, type StreamingMultipartOptions, type StreamingMultipartPart } from '../index.cjs';
import {Readable} from 'node:stream';

async function use(): Promise<void> {
  const client = new Client({profile: profiles()[0]!, route: 'direct', cookies: true,
    baseUrl: 'https://example.com/api/', additionalProxyRoots: [Buffer.from('DER')],
    timeouts: {connectMs: 1000, totalMs: null}});
  const controller = new AbortController();
  const response = await client.request('https://example.com/', {
    method: 'GET', protocol: 'negotiated', context: 'navigation',
    timeouts: {responseHeadMs: 0},
    headers: [{name: 'x-example', value: Buffer.from('bytes'), sensitive: true}],
    attemptBudget: new AttemptBudget(4), signal: controller.signal, timeoutMs: 5000,
  });
  for await (const bytes of response) bytes.toString();
  const actual: 'http1' | 'http2' | 'http3' = response.protocol;
  const finalUrl: string = response.url;
  const redirects: number = response.redirects;
  const retries: number = response.connectionRetries;
  void actual; void finalUrl; void redirects; void retries;
  await client.closeIdleConnections(); await client.refreshConnections();
  client.clearDnsCache(); client.clearAltSvc(); client.clearAltSvcRacingHistory(); client.clearClientHints();
  client.clearCookies(); client.clearSessionTickets();
  // @ts-expect-error Timeout values use numbers or null.
  await client.request('child', {method: 'GET', protocol: 'http1', context: 'raw', timeouts: {totalMs: '100'}});
  await client.close();
}
void use;
function pinnedClients(): void {
  const pins: readonly Uint8Array[] = [Buffer.alloc(32)];
  const options: ClientOptions = {profile: 'exact', route: 'direct', serverSpkiPins: pins, proxyServerSpkiPins: pins};
  new Client(options);
  // @ts-expect-error Pin configuration is readonly.
  options.serverSpkiPins = [];
  // @ts-expect-error Pins are raw digest bytes, not strings.
  new Client({...options, serverSpkiPins: ['sha256/base64']});
  // @ts-expect-error A digest list is required, not one byte buffer.
  new Client({...options, proxyServerSpkiPins: Buffer.alloc(32)});
}
void pinnedClients;
const code = (error: PhantomError): string => error.code;
void code;
async function checkpoints(client: Client, key: Uint8Array): Promise<void> {
  const bytes: Buffer = await client.exportSession(key);
  const restored: Client = await client.restoreSession(bytes, key, {receivingRoutes: [
    {route: 'direct'}, {route: 'proxy', proxy: 'http://127.0.0.1:8080'},
  ]});
  await restored.close();
  // @ts-expect-error A key must be bytes, not text.
  await client.exportSession('key');
  // @ts-expect-error Checkpoints contain encoded bytes, not configuration.
  await client.restoreSession({}, key);
  // @ts-expect-error Direct receiving routes cannot include proxy configuration.
  await client.restoreSession(bytes, key, {receivingRoutes: [{route: 'direct', proxy: 'http://proxy.invalid'}]});
  // @ts-expect-error CPU checkpoint operations do not expose AbortSignal.
  await client.restoreSession(bytes, key, {signal: new AbortController().signal});
}
void checkpoints;
const socks4 = new Client({profile: 'exact', route: 'proxy', proxy: 'socks4a://127.0.0.1:1080', proxyUserId: 'user'});
void socks4;
// @ts-expect-error SOCKS4 user IDs are strings, never byte buffers.
new Client({profile: 'exact', route: 'proxy', proxy: 'socks4://127.0.0.1:1080', proxyUserId: Buffer.from('user')});
const phase = (error: PhantomError): string | undefined => error.timeoutPhase;
const protocol = (error: PhantomError): string | undefined => error.protocol;
void phase; void protocol;

async function readers(response: Response): Promise<void> {
  const text: string = await response.text(1024);
  const value: unknown = await response.json(1024);
  if (typeof value === 'object' && value !== null && 'answer' in value) {
    const answer: unknown = value.answer;
    void answer;
  }
  // @ts-expect-error JSON needs caller validation before typed use.
  const unchecked: { answer: number } = await response.json(1024);
  // @ts-expect-error A generic argument does not validate JSON.
  await response.json<{ answer: number }>(1024);
  // @ts-expect-error The input byte limit is mandatory.
  await response.text();
  // @ts-expect-error Byte bounds are numbers.
  await response.json('1024');
  void text; void unchecked;
}
void readers;

function profileAuthoring(): void {
  const exact = Profile.fromCatalog(profiles()[0]!, 'navigation');
  const document: {[key: string]: ProfileValue} = exact.describe();
  const large: ProfileValue = 9007199254740993n;
  const custom = Profile.fromDescription(document);
  const exported: Buffer = custom.exportJson();
  const id: string | null = custom.catalogId;
  const owner = new Client({profile: custom, route: 'direct'});
  void owner.request('https://example.com/', {method: 'GET', protocol: 'http2', context: 'profile'});
  // @ts-expect-error A JSON object is not bounded encoded input.
  Profile.importJson(document);
  // @ts-expect-error Descriptions cannot contain functions.
  Profile.fromDescription({invalid: () => 1});
  // @ts-expect-error A raw request has no catalog template to attach.
  Profile.fromCatalog('exact/id', 'raw');
  // @ts-expect-error Profiles are constructed from validated input.
  new Profile();
  // @ts-expect-error Context metadata cannot be mutated.
  custom.contexts.push('navigation');
  void exported; void id; void large;
}
void profileAuthoring;

function sessionSharing(client: Client): void {
  const separate: Client = client.fork();
  const shared: Client = client.fork({cookies: true, dns: false, clientHints: true,
    discovery: true, tickets: true});
  // @ts-expect-error Sharing selectors are booleans.
  client.fork({cookies: 'yes'});
  // @ts-expect-error Pools cannot be selected for sharing.
  client.fork({pools: true});
  // @ts-expect-error Null is not a selector record.
  client.fork(null);
  void separate; void shared;
}
void sessionSharing;

function attemptBudgets(): void {
  const budget = new AttemptBudget(9007199254740993n);
  const remaining: number | bigint = budget.remaining;
  const admitted: void = budget.tryAdmit();
  // @ts-expect-error Large remaining counts cannot always be represented as number.
  const rounded: number = budget.remaining;
  // @ts-expect-error Counts are numbers or bigint, never parsed strings.
  new AttemptBudget('1');
  void remaining; void admitted; void rounded;
}
void attemptBudgets;

async function decoding(client: Client): Promise<void> {
  const response = await client.request('https://example.com/', {
    method: 'GET', protocol: 'http2', context: 'raw',
    contentDecoding: {mode: 'advertised', maximumDecodedBytes: 18446744073709551615n},
  });
  const codings: readonly ('gzip' | 'deflate' | 'br' | 'zstd')[] = response.decodedContentCodings;
  // @ts-expect-error Decoded-byte bounds are required when enabling decoding.
  await client.request('https://example.com/', {method: 'GET', protocol: 'http2', context: 'raw', contentDecoding: {mode: 'advertised'}});
  // @ts-expect-error None has no decoded-byte bound.
  await client.request('https://example.com/', {method: 'GET', protocol: 'http2', context: 'raw', contentDecoding: {mode: 'none', maximumDecodedBytes: 5}});
  // @ts-expect-error Recorded coding metadata is immutable.
  response.decodedContentCodings.push('gzip');
  // @ts-expect-error Content decoding is request-only.
  new Client({profile: 'exact/id', route: 'direct', contentDecoding: {mode: 'none'}});
  void codings;
}
void decoding;

async function redirects(client: Client, response: Response): Promise<void> {
  await client.request('https://example.com/', {method: 'GET', protocol: 'http2', context: 'raw',
    redirectPolicy: {mode: 'limited', maximumHops: 3n}, redirectHistoryLimit: 2});
  const destination: string | undefined = response.redirectHistory?.entries[0]?.toUrl;
  // @ts-expect-error Limited redirects require a hop bound.
  new Client({profile: 'exact/id', route: 'direct', redirectPolicy: {mode: 'limited'}});
  // @ts-expect-error None cannot specify a hop bound.
  await client.request('https://example.com/', {method: 'GET', protocol: 'http1', context: 'raw', redirectPolicy: {mode: 'none', maximumHops: 1}});
  // @ts-expect-error History bounds are exact integers, not strings.
  await client.request('https://example.com/', {method: 'GET', protocol: 'http1', context: 'raw', redirectHistoryLimit: '1'});
  // @ts-expect-error History entries are immutable.
  response.redirectHistory?.entries.push({fromUrl: '', toUrl: '', method: 'GET', nextMethod: 'GET', status: 302});
  // @ts-expect-error Hop metadata is immutable.
  if (response.redirectHistory?.entries[0]) response.redirectHistory.entries[0].status = 200;
  void destination;
}
void redirects;

async function retries(client: Client): Promise<void> {
  await client.request('https://example.com/', {method: 'GET', protocol: 'http2', context: 'raw', retryPolicy: {
    connectionFailures: {maximum: 2n, delayMs: 0.5, maximumDelayMs: 100, fullJitter: true},
    statusRetry: {statuses: [429, 503], maximum: 2, delayMs: 0, retryAfterLimitMs: 1000},
    reusedConnectionReplay: true, unprocessedReplays: 1, maximumRetries: 0n, http2Fallback: false,
  }});
  // @ts-expect-error Retry schedules require an explicit delay.
  new Client({profile: 'exact/id', route: 'direct', retryPolicy: {connectionFailures: {maximum: 1}}});
  // @ts-expect-error Retry selectors are booleans.
  await client.request('https://example.com/', {method: 'GET', protocol: 'http1', context: 'raw', retryPolicy: {http2Fallback: 1}});
  // @ts-expect-error Status retry lists contain numeric status codes.
  await client.request('https://example.com/', {method: 'GET', protocol: 'http1', context: 'raw', retryPolicy: {statusRetry: {statuses: ['503'], maximum: 1, delayMs: 0}}});
}
void retries;

function compactProfiles(base: Profile, bytes: Uint8Array): void {
  const result = Profile.importJa3('771,...', {base});
  const owner: Profile = result.profile;
  const observed: readonly string[] = result.observedFields;
  const supplied: readonly string[] = result.supplementedFields;
  Profile.importAkamai('1:65536;4:65535|0|0|m,a,s,p', {base});
  Profile.importClientHello(bytes.subarray(4), {base});
  Profile.importQuicTransport(bytes, {base});
  Profile.importJa4('raw', {base, format: 'sorted'});
  Profile.importJa4('raw', {base, format: 'original'});
  // @ts-expect-error No implicit default base.
  Profile.importJa3('771,...');
  // @ts-expect-error A catalog string is not an explicitly instantiated base.
  Profile.importAkamai('raw', {base: 'chrome'});
  // @ts-expect-error JA4 interpretation must be explicit.
  Profile.importJa4('raw', {base});
  // @ts-expect-error Hash formats cannot reconstruct settings.
  Profile.importJa4('hash', {base, format: 'hashed'});
  // @ts-expect-error ClientHello input is binary.
  Profile.importClientHello('hex', {base});
  // @ts-expect-error Reports are immutable.
  result.observedFields.push('invented');
  // @ts-expect-error The result owner is immutable.
  result.profile = base;
  void owner; void observed; void supplied;
}
void compactProfiles;

async function uploadBodies(client: Client): Promise<void> {
  async function* body(): AsyncGenerator<Uint8Array> { yield Buffer.from('hello'); }
  await client.request('https://example.com/', {method: 'POST', protocol: 'http2', context: 'raw', body: body(), bodyLength: 5n});
  const readable = (await import('node:stream')).Readable.from(body());
  await client.request('https://example.com/', {method: 'POST', protocol: 'http2', context: 'raw', body: readable});
  // @ts-expect-error Upload producers must yield byte arrays.
  await client.request('https://example.com/', {method: 'POST', protocol: 'http2', context: 'raw', body: (async function* () { yield 'text'; })()});
  // @ts-expect-error Lengths are exact integers, not strings.
  await client.request('https://example.com/', {method: 'POST', protocol: 'http2', context: 'raw', body: body(), bodyLength: '5'});
}
void uploadBodies;

function uploadErrorDetails(failure: PhantomError): void {
  const original: unknown = failure.cause;
  const cleanup: unknown = failure.cleanupError;
  // @ts-expect-error Caller-thrown values require narrowing before use.
  failure.cause.message;
  // @ts-expect-error Cleanup details are read-only.
  failure.cleanupError = new Error('replacement');
  void original; void cleanup;
}
void uploadErrorDetails;

async function transfers(client: Client): Promise<void> {
  const control = new TransferControl({uploadBytes: 0, downloadBytes: 18446744073709551615n,
    uploadBytesPerSecond: 1, downloadBytesPerSecond: 1n});
  const counts = control.snapshot();
  const uploaded: bigint = counts.uploadBodyBytes;
  const downloaded: bigint = counts.downloadDecodedBytes;
  await client.request('https://example.com/', {method: 'GET', protocol: 'http2', context: 'raw', transferControl: control});
  // @ts-expect-error Counters are read-only.
  counts.downloadEncodedBytes = 0n;
  // @ts-expect-error Counters are always bigint, never an imprecise number.
  const rounded: number = counts.uploadReservedBytes;
  // @ts-expect-error Limits are exact integer values, not strings.
  new TransferControl({downloadBytes: '1'});
  // @ts-expect-error A native owner is required.
  await client.request('https://example.com/', {method: 'GET', protocol: 'http2', context: 'raw', transferControl: {}});
  void uploaded; void downloaded; void rounded;
}
void transfers;

async function requestControls(client: Client): Promise<void> {
  const options = {method: 'POST', protocol: 'http1' as const, context: 'raw' as const,
    body: Buffer.from('data'), trailers: [{name: 'X-Result', value: Buffer.from('done'), sensitive: true}]};
  await client.request('https://example.com/', {...options, expectContinueMs: 0});
  await client.request('https://example.com/', {...options, expectContinueMs: 5000n});
  // @ts-expect-error Waits are exact integer values, not strings.
  await client.request('https://example.com/', {...options, expectContinueMs: '5000'});
  // @ts-expect-error Trailer values are bytes, not strings.
  await client.request('https://example.com/', {...options, trailers: [{name: 'x', value: 'done'}]});
}
void requestControls;

async function preparedBodies(client: Client): Promise<void> {
  const body = await PreparedBody.form([['tag', 'first'], ['tag', 'last']] as const, {maximumBytes: 1024n});
  const length: bigint = body.byteLength;
  await client.request('https://example.com/', {method: 'POST', protocol: 'http1', context: 'raw', body,
    headers: [{name: 'Content-Type', value: Buffer.from(body.contentType)}], bodyLength: length});
  await PreparedBody.multipart([{name: 'x', text: 'text'}, {name: 'x', bytes: new Uint8Array(), filename: 'file'}], {boundary: 'explicit', maximumBytes: 4096});
  // @ts-expect-error Prepared bodies have read-only metadata.
  body.byteLength = 1n;
  // @ts-expect-error Multipart requires exactly one payload mode.
  await PreparedBody.multipart([{name: 'x', text: 'x', bytes: Buffer.alloc(0)}], {boundary: 'x', maximumBytes: 128});
  // @ts-expect-error Encoded output maximum is required.
  await PreparedBody.form([]);
}
void preparedBodies;

async function diagnostics(client: Client): Promise<void> {
  const trace = new RequestDiagnostics({maximumEvents: 128});
  await client.request('https://example.com/', {method: 'GET', protocol: 'http1', context: 'raw', diagnostics: trace});
  const snapshot: RequestTimeline | null = trace.snapshot();
  const elapsed: bigint | null | undefined = snapshot?.sendElapsedNs;
  // @ts-expect-error Capacity is an exact integer, never text.
  new RequestDiagnostics({maximumEvents: '128'});
  // @ts-expect-error A native observer cannot be replaced with a plain object.
  await client.request('https://example.com/', {method: 'GET', protocol: 'http1', context: 'raw', diagnostics: {}});
  void elapsed;
}
void diagnostics;

async function clientIdentities(chain: Uint8Array, key: Uint8Array): Promise<void> {
  const owner = await ClientCertificate.fromPem(chain, key);
  const der = await ClientCertificate.fromDer([chain] as const, key);
  new Client({profile: 'exact', route: 'direct', clientCertificate: owner,
    clientCertificatesFor: [['https://example.com', der]] as const});
  // @ts-expect-error Identities cannot be fabricated.
  new ClientCertificate();
  // @ts-expect-error PEM input is explicit bytes, never file paths.
  await ClientCertificate.fromPem('private-key.pem', key);
  // @ts-expect-error Native identity owner is required.
  new Client({profile: 'exact', route: 'direct', clientCertificate: {}});
  // @ts-expect-error Origin mappings are ordered pairs.
  new Client({profile: 'exact', route: 'direct', clientCertificatesFor: {origin: owner}});
}
void clientIdentities;

function responseTrailers(response: Response): void {
  const trailers: ResponseTrailers = response.trailers;
  if (trailers.state === 'complete') {
    const bytes: Buffer | undefined = trailers.headers[0]?.value;
    // @ts-expect-error Retained field order is immutable.
    trailers.headers.push({name: 'x', value: Buffer.alloc(0), sensitive: false});
    // @ts-expect-error Retained names cannot be reassigned.
    trailers.headers[0]!.name = 'other';
    const sensitive: boolean | undefined = trailers.headers[0]?.sensitive;
    void sensitive;
    void bytes;
  } else {
    const absent: null = trailers.headers;
    void absent;
  }
  // @ts-expect-error Snapshot state is read-only.
  trailers.state = 'complete';
  // @ts-expect-error Getter cannot be overwritten.
  response.trailers = {state: 'pending', headers: null};
}
void responseTrailers;


async function* chunks(): AsyncGenerator<Uint8Array, void, unknown> {yield Buffer.from('x');}
async function streamingMultipartExample(client: Client): Promise<void> {
  const parts: readonly StreamingMultipartPart[] = [
    {name: 'duplicate', text: 'one'}, {name: 'duplicate', bytes: Buffer.alloc(0)},
    {name: 'upload', stream: chunks(), filename: 'x.bin'},
    {name: 'stream', stream: Readable.from([Buffer.from('x')])},
    {name: 'file', file: {path: 'x.bin', maximumBytes: 100}, contentType: 'application/custom'},
  ];
  const descriptor: StreamingMultipartOptions = {boundary: 'b', maximumBytes: 1000n, parts};
  const response = await client.request('https://example.test', {method: 'POST', protocol: 'http2', context: 'raw', multipart: descriptor});
  await response.bytes(100);
  // @ts-expect-error One arm per ordered part.
  const conflicting: StreamingMultipartPart = {name: 'x', text: 'x', stream: chunks()};
  // @ts-expect-error A mere async iterable has no explicit close ownership.
  const uncloseable: StreamingMultipartPart = {name: 'x', stream: {[Symbol.asyncIterator]: chunks}};
  // @ts-expect-error Multipart fields are immutable.
  descriptor.parts = [];
  // @ts-expect-error Native file limits use the existing number API.
  const file: StreamingMultipartPart = {name: 'x', file: {path: 'x', maximumBytes: 1n}};
  void conflicting; void uncloseable; void file;
}
void streamingMultipartExample;

function receivedHead(response: Response): void {
  const sensitive: boolean = response.headers[0]!.sensitive;
  const bytes: Buffer = response.headers[0]!.value;
  // @ts-expect-error Received markers are required booleans.
  const wrong: typeof response.headers[number] = {name: 'x', value: Buffer.alloc(0)};
  // @ts-expect-error Received headers are immutable ordered records.
  response.headers[0]!.sensitive = false;
  // @ts-expect-error Received header list is immutable.
  response.headers.push({name: 'x', value: Buffer.alloc(0), sensitive: false});
  void sensitive; void bytes; void wrong;
}
void receivedHead;

function networkConfiguration(): void {
  new Client({profile: 'exact', route: 'direct', network: {
    hostOverrides: [{host: 'example.invalid', addresses: ['127.0.0.1', '::1']}],
    localAddresses: ['127.0.0.1'], interface: 'lo',
  }});
  // @ts-expect-error addresses are IP strings, not port-bearing objects
  new Client({profile: 'exact', route: 'direct', network: {localAddresses: [{address: '::1'}]}});
  // @ts-expect-error unknown network policies are not accepted
  new Client({profile: 'exact', route: 'direct', network: {fallbackToUnbound: true}});
}
