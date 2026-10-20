/// <reference types="node" />

export class PhantomError extends Error {
  readonly code: string;
  readonly protocol?: 'http1' | 'http2' | 'http3';
  readonly timeoutPhase?: 'poolAdmission' | 'connect' | 'responseHead' | 'readIdle' | 'total' | 'webSocketHandshake';
  /** Core profile-document category, when code is ProfileImport/ProfileExport. */
  readonly kind?: string;
  /** Canonical document field path; supplied values are omitted. */
  readonly field?: string;
}
/** Large unsigned integers use bigint rather than rounded JavaScript numbers. */
export type ProfileValue = null | boolean | number | bigint | string | ProfileValue[] | { [key: string]: ProfileValue };
export type CatalogContext = 'navigation' | 'fetch' | 'fetchNoStore' | 'fetchUpload';
export type RequestContext = 'raw' | 'profile' | CatalogContext;
/** Immutable native settings. Imported documents never acquire catalog evidence. */
export class Profile {
  private constructor();
  static fromCatalog(identifier: string, context?: CatalogContext): Profile;
  static importJson(input: Uint8Array): Profile;
  /** Validates an editable data document through the native importer. */
  static fromDescription(document: { [key: string]: ProfileValue }): Profile;
  readonly catalogId: string | null;
  readonly contexts: readonly RequestContext[];
  exportJson(): Buffer;
  /** Returns a fresh editable document, including configured literal headers. */
  describe(): { [key: string]: ProfileValue };
}
export class AttemptBudget {
  /** Exact nonnegative count within the native platform's usize range. */
  constructor(maximum: number | bigint);
  /** A number through MAX_SAFE_INTEGER; larger counts are bigint. Not a reservation. */
  readonly remaining: number | bigint;
  /** Charges an attempt outside Phantom; exhaustion throws AttemptBudgetExhausted. */
  tryAdmit(): void;
}
export interface Header { name: string; value: Uint8Array; sensitive?: boolean; }
/** Omit to inherit; null disables; zero is finite (a ready core phase can win). */
export interface Timeouts {
  poolAdmissionMs?: number | null;
  connectMs?: number | null;
  responseHeadMs?: number | null;
  readIdleMs?: number | null;
  totalMs?: number | null;
}
export interface ClientOptions {
  profile: string | Profile;
  route: 'direct' | 'proxy';
  proxy?: string;
  proxyUsername?: string;
  proxyPassword?: string;
  cookies?: boolean;
  maximumActiveRequests?: number;
  additionalRoots?: Uint8Array[];
  additionalProxyRoots?: Uint8Array[];
  baseUrl?: string;
  timeouts?: Timeouts;
}
/** Selected live state only; pools and cancellation stay independent. */
export interface SessionSharing {
  cookies?: boolean;
  dns?: boolean;
  clientHints?: boolean;
  discovery?: boolean;
  tickets?: boolean;
}
export interface RequestOptions {
  method: string;
  protocol: 'http1' | 'http2' | 'http3' | 'negotiated';
  context: RequestContext;
  headers?: Header[];
  body?: Uint8Array;
  file?: { path: string; maximumBytes: number };
  timeoutMs?: number;
  timeouts?: Timeouts;
  signal?: AbortSignal;
  attemptBudget?: AttemptBudget;
}
export class Response implements AsyncIterable<Buffer> {
  private constructor();
  readonly status: number;
  readonly protocol: 'http1' | 'http2' | 'http3';
  readonly url: string;
  readonly redirects: number;
  /** Connection-setup retries only; excludes status retries and protocol replays. */
  readonly connectionRetries: number;
  readonly headers: Header[];
  read(maximumBytes?: number): Promise<Buffer | null>;
  bytes(maximumBytes: number): Promise<Buffer>;
  text(maximumBytes: number): Promise<string>;
  json(maximumBytes: number): Promise<unknown>;
  close(): void;
  [Symbol.asyncIterator](): AsyncIterator<Buffer>;
  [Symbol.asyncDispose](): Promise<void>;
}
export class Client {
  constructor(options: ClientOptions);
  /** Creates an open client with independent pools, even from a closed source. */
  fork(sharing?: SessionSharing): Client;
  request(url: string, options: RequestOptions): Promise<Response>;
  setCookie(url: string, setCookie: string): void;
  cookieValue(url: string): string | null;
  clearCookies(): void;
  clearDnsCache(): void;
  clearAltSvc(): void;
  clearAltSvcRacingHistory(): void;
  clearClientHints(): void;
  clearSessionTickets(): number;
  closeIdleConnections(): Promise<void>;
  refreshConnections(): Promise<void>;
  close(options?: { timeoutMs?: number }): Promise<void>;
  [Symbol.asyncDispose](): Promise<void>;
}
export function profiles(): string[];
