import { AttemptBudget, Client, Profile } from '../index.mjs';

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
