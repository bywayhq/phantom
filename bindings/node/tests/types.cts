import { AttemptBudget, Client, PhantomError, profiles } from '../index.cjs';

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
