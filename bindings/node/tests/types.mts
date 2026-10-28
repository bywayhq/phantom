import { AttemptBudget, TransferControl, Client, ClientCertificate, PreparedBody, Profile, RequestDiagnostics, type PoolOptions, type RequestTimeline, type Response, type ResponseTrailers } from '../index.mjs';

const resources = new Client({profile: 'chrome-156-windows', route: 'direct', context: 'navigation'});
void resources.eventSource('https://example.com/events', {protocol: 'http2', maximumReconnects: 0});
void resources.get('https://example.com/image.png', {context: 'image'});
void Profile.fromCatalog('chrome-156-windows', 'font');

const pinned = new Client({profile: 'exact', route: 'direct',
  network: {publicOnly: true}, redirectPolicy: {mode: 'none', credentialHeaders: ['x-api-key']},
  serverSpkiPins: [new Uint8Array(32)] as const, proxyServerSpkiPins: [Buffer.alloc(32)] as const});
void pinned;
async function websocketUse(): Promise<void> {
  const socket = await pinned.websocket('wss://example.com/events', {protocol: 'http1'});
  await socket.send('hello');
  const event = await socket.receive();
  if (event?.type === 'text') event.data.toUpperCase();
  else if (event?.type === 'binary') event.data.readUInt8(0);
  await socket.close(); socket.abort();
}
void websocketUse;
// @ts-expect-error Digest contents must be bytes, never numeric lists.
new Client({profile: 'exact', route: 'direct', serverSpkiPins: [[1, 2, 3]]});

function compactProfiles(base: Profile, bytes: Uint8Array): void {
  const imported = Profile.importClientHello(bytes, {base});
  const profile: Profile = imported.profile;
  const fields: readonly string[] = imported.observedFields;
  Profile.importJa3('raw', {base});
  Profile.importAkamai('raw', {base});
  Profile.importQuicTransport(bytes, {base});
  Profile.importJa4('raw', {base, format: 'original'});
  // @ts-expect-error Both base and JA4 format are required.
  Profile.importJa4('raw', {format: 'sorted'});
  // @ts-expect-error Reports cannot be reassigned.
  imported.supplementedFields = [];
  // @ts-expect-error QUIC transport input is binary.
  Profile.importQuicTransport('hex', {base});
  void profile; void fields;
}
void compactProfiles;

async function use(): Promise<void> {
  await using client = new Client({profile: 'exact/profile/id', route: 'proxy', proxy: 'http://127.0.0.1:8080'});
  await using response = await client.request('https://example.com/', {
    method: 'POST', protocol: 'http1', context: 'raw',
    file: {path: 'input.bin', maximumBytes: 1024},
  });
  const bytes: Buffer = await response.bytes(1024);
  const text: string = await response.text(1024);
  const value: unknown = await response.json(1024);
  // @ts-expect-error The input byte limit is mandatory.
  await response.json();
  // @ts-expect-error Parsed JSON cannot be used as validated text.
  const unchecked: string = await response.json(1024);
  // @ts-expect-error Text is not a byte buffer.
  const binary: Buffer = await response.text(1024);
  void text; void value; void unchecked; void binary;
  void bytes;
}
void use;
async function requestConveniences(): Promise<void> {
  await using client = new Client({profile: Profile.fromCatalog('exact', 'navigation'), route: 'direct'});
  const response: Response = await client.get(new URL('https://example.com/'));
  await client.request('child');
  await client.post('child', {json: {word: 'hello'}, query: [['tag', 'one'], ['tag', 'two']] as const});
  await client.put('child', {body: 'text'});
  await client.patch('child', {form: new URLSearchParams([['name', 'value']])});
  await client.delete('child'); await client.head('child'); await client.options('child');
  // @ts-expect-error Ordered form values must be strings.
  await client.post('child', {form: [['count', 1]]});
  // @ts-expect-error Method helpers select their own method.
  await client.post('child', {method: 'GET'});
  void response;
}
void requestConveniences;
const custom: Profile = Profile.importJson(Profile.fromCatalog('exact/profile/id').exportJson());
void custom;
function fork(client: Client): Client {
  return client.fork({cookies: true, tickets: true});
}
void fork;

const budget = new AttemptBudget(4294967296n);
const remaining: number | bigint = budget.remaining;
budget.tryAdmit();
void remaining;
async function checkpoints(client: Client, key: Buffer): Promise<void> {
  const checkpoint: Buffer = await client.exportSession(key);
  const restored: Client = await client.restoreSession(checkpoint, key);
  await restored.close();
  // @ts-expect-error Restore accepts byte input only.
  await client.restoreSession('checkpoint', key);
}
void checkpoints;

const transfer = new TransferControl({downloadBytes: 0n});
const transferred: bigint = transfer.snapshot().downloadEncodedBytes;
void transferred;

async function requestControls(client: Client): Promise<void> {
  await client.request('https://example.com/', {method: 'POST', protocol: 'http2', context: 'raw',
    trailers: [{name: 'x-check', value: new Uint8Array(), sensitive: false}], expectContinueMs: 0n});
  // @ts-expect-error Waits do not accept booleans.
  await client.request('https://example.com/', {method: 'GET', protocol: 'http1', context: 'raw', expectContinueMs: true});
}
void requestControls;

async function preparedBodies(): Promise<void> {
  const body: PreparedBody = await PreparedBody.multipart([{name: 'x', text: 'value'}], {boundary: 'caller', maximumBytes: 256n});
  const mediaType: string = body.contentType;
  // @ts-expect-error Boundaries are explicit, never generated.
  await PreparedBody.multipart([], {maximumBytes: 128});
  // @ts-expect-error Form values are strings without coercion.
  await PreparedBody.form([['x', 1]], {maximumBytes: 128});
  void mediaType;
}
void preparedBodies;

async function diagnostics(client: Client): Promise<void> {
  const trace = new RequestDiagnostics({maximumEvents: 128n});
  await client.request('https://example.com/', {method: 'GET', protocol: 'http2', context: 'raw', diagnostics: trace});
  const snapshot: RequestTimeline | null = trace.snapshot();
  if (snapshot) {
    const elapsed: bigint | null = snapshot.sendElapsedNs;
    // @ts-expect-error Snapshot counters are exact bigint, never number.
    const rounded: number = snapshot.admittedAttempts;
    // @ts-expect-error Event records are immutable.
    snapshot.events[0]!.outcome = 'completed';
    const state = snapshot.events[0]!.connection?.originTls;
    if (state?.state === 'established') {
      const verified: boolean = state.info.peerVerified;
      void verified;
    }
    void elapsed; void rounded;
  }
  // @ts-expect-error Capacity does not accept booleans.
  new RequestDiagnostics({maximumEvents: true});
  // @ts-expect-error A plain snapshot is not an observer owner.
  await client.request('https://example.com/', {method: 'GET', protocol: 'http2', context: 'raw', diagnostics: {snapshot() {return null;}}});
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
  new Client({profile: 'exact', route: 'direct', network: {unixSocket: '/run/service.sock'}});
  // @ts-expect-error Unix socket paths are text, not buffers
  new Client({profile: 'exact', route: 'direct', network: {unixSocket: Buffer.from('/socket')}});
  new Client({profile: 'exact', route: 'direct', network: {
    hostOverrides: [{host: 'example.invalid', addresses: ['127.0.0.1', '::1']}],
    localAddresses: ['127.0.0.1'], interface: 'lo',
  }});
  // @ts-expect-error addresses are IP strings, not port-bearing objects
  new Client({profile: 'exact', route: 'direct', network: {localAddresses: [{address: '::1'}]}});
  // @ts-expect-error unknown network policies are not accepted
  new Client({profile: 'exact', route: 'direct', network: {fallbackToUnbound: true}});
}

const poolLimits: PoolOptions = {
  maxConcurrentHttp1RequestsPerOrigin: 4, maxPendingHttp1RequestsPerOrigin: 12,
  maxHttp2ConnectionsPerOrigin: 2, maxHttp3ConnectionsPerOrigin: 2,
  negotiatedSetupWaitLimitMs: 0,
};
new Client({profile: 'exact', route: 'direct', pool: poolLimits});
// @ts-expect-error Pool fields are immutable.
poolLimits.maxConcurrentHttp1RequestsPerOrigin = 2;
// @ts-expect-error Counts use safe numbers, not bigint.
new Client({profile: 'exact', route: 'direct', pool: {maxRetainedHttp1Connections: 1n}});
// @ts-expect-error Omit a setup wait to retain defaults; null is not a duration.
new Client({profile: 'exact', route: 'direct', pool: {negotiatedSetupWaitLimitMs: null}});

async function shutdownClient(client: Client): Promise<void> {
  await client.close({timeoutMs: 10});
  await client.destroy({timeoutMs: 0});
  // @ts-expect-error shutdown deadlines use numbers, not bigint
  await client.destroy({timeoutMs: 1n});
}

async function serverSentEvents(response: Response): Promise<void> {
  const stream = response.events({maximumLineBytes: 65536, maximumEventBytes: 1048576});
  const retry: bigint | null = stream.retryMs;
  const id: string = stream.lastEventId;
  for await (const event of stream) {
    const data: string = event.data;
    const name: string = event.event;
    const eventRetry: bigint | null = event.retryMs;
    void data; void name; void eventRetry;
    break;
  }
  await stream[Symbol.asyncDispose]();
  // @ts-expect-error Limits are bounded numbers, not bigint.
  response.events({maximumLineBytes: 1n});
  // @ts-expect-error SSE decoding does not reconnect.
  response.events({reconnect: true});
  void retry; void id;
}
void serverSentEvents;
