import { AttemptBudget, Client, PhantomError, Response, profiles } from '../index.cjs';

async function use(): Promise<void> {
  const client = new Client({profile: profiles()[0]!, route: 'direct', cookies: true});
  const controller = new AbortController();
  const response = await client.request('https://example.com/', {
    method: 'GET', protocol: 'http2', context: 'navigation',
    headers: [{name: 'x-example', value: Buffer.from('bytes'), sensitive: true}],
    attemptBudget: new AttemptBudget(4), signal: controller.signal, timeoutMs: 5000,
  });
  for await (const bytes of response) bytes.toString();
  await client.close();
}
void use;
const code = (error: PhantomError): string => error.code;
void code;

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
