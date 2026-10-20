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
  client.clearDnsCache(); client.clearAltSvc(); client.clearClientHints();
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
