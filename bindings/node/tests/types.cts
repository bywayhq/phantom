import { AttemptBudget, Client, PhantomError, Profile, Response, profiles, type ProfileValue } from '../index.cjs';

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
const code = (error: PhantomError): string => error.code;
void code;
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
