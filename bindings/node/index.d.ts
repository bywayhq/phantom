/// <reference types="node" />

export class PhantomError extends Error {
  readonly code: string;
  readonly protocol?: 'http1' | 'http2' | 'http3';
  readonly timeoutPhase?: 'poolAdmission' | 'connect' | 'responseHead' | 'readIdle' | 'total' | 'webSocketHandshake';
  /** Core profile-document or session checkpoint category. */
  readonly kind?: string;
  /** Canonical document field path; supplied values are omitted. */
  readonly field?: string;
  /** Caller upload failure, available only through explicit inspection. */
  readonly cause?: unknown;
  /** Iterator cleanup failure; may become available after request settlement. */
  readonly cleanupError?: unknown;
}
/** Large unsigned integers use bigint rather than rounded JavaScript numbers. */
export type ProfileValue = null | boolean | number | bigint | string | ProfileValue[] | { [key: string]: ProfileValue };
export type CatalogContext = 'navigation' | 'fetch' | 'fetchNoStore' | 'fetchUpload';
export type RequestContext = 'raw' | 'profile' | CatalogContext;
/** A compact description establishes only observed fields; the base supplies the rest. */
export interface ImportedProfile {
  readonly profile: Profile;
  readonly observedFields: readonly string[];
  readonly supplementedFields: readonly string[];
}
export interface ProfileImportOptions { readonly base: Profile; }
export interface JA4ImportOptions extends ProfileImportOptions { readonly format: 'sorted' | 'original'; }
/** Immutable native settings. Imported documents never acquire catalog evidence. */
export class Profile {
  private constructor();
  static fromCatalog(identifier: string, context?: CatalogContext): Profile;
  static importJson(input: Uint8Array): Profile;
  /** Validates an editable data document through the native importer. */
  static fromDescription(document: { [key: string]: ProfileValue }): Profile;
  /** Imports raw five-part JA3; hashes cannot recover settings. */
  static importJa3(description: string, options: ProfileImportOptions): ImportedProfile;
  /** Complete handshake message including its four-byte header, excluding the TLS record header. */
  static importClientHello(handshake: Uint8Array, options: ProfileImportOptions): ImportedProfile;
  static importAkamai(description: string, options: ProfileImportOptions): ImportedProfile;
  /** Sorted JA4 checks membership while retaining the base's explicit ordering. */
  static importJa4(description: string, options: JA4ImportOptions): ImportedProfile;
  /** TLS extension 57 payload; this is neither a QUIC packet nor a ClientHello. */
  static importQuicTransport(parameters: Uint8Array, options: ProfileImportOptions): ImportedProfile;
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
  redirectPolicy?: RedirectPolicy;
  retryPolicy?: RetryPolicy;
}
/** Selected live state only; pools and cancellation stay independent. */
export interface SessionSharing {
  cookies?: boolean;
  dns?: boolean;
  clientHints?: boolean;
  discovery?: boolean;
  tickets?: boolean;
}
/** Ticket validation only; these routes do not change later request routing. */
export type SessionRoute = Readonly<{route: 'direct'}> | Readonly<{
  route: 'proxy'; proxy: string; proxyUsername?: string; proxyPassword?: string;
}>;
export interface RestoreSessionOptions { readonly receivingRoutes?: readonly SessionRoute[]; }
export type ContentDecoding = Readonly<{mode: 'none'}>
  | Readonly<{mode: 'advertised'; maximumDecodedBytes: number | bigint}>;
export type ContentCoding = 'gzip' | 'deflate' | 'br' | 'zstd';
export type RedirectPolicy = Readonly<{mode: 'none'}>
  | Readonly<{mode: 'limited'; maximumHops: number | bigint}>;
export interface ConnectionRetry {
  readonly maximum: number | bigint;
  readonly delayMs: number;
  readonly maximumDelayMs?: number;
  readonly fullJitter?: boolean;
}
export interface StatusRetry extends ConnectionRetry {
  readonly statuses: readonly number[];
  readonly retryAfterLimitMs?: number;
}
export interface RetryPolicy {
  readonly connectionFailures?: ConnectionRetry;
  readonly reusedConnectionReplay?: boolean;
  readonly unprocessedReplays?: number | bigint;
  readonly statusRetry?: StatusRetry;
  readonly maximumRetries?: number | bigint;
  readonly http2Fallback?: boolean;
}
export interface RedirectHop {
  readonly fromUrl: string;
  readonly toUrl: string;
  readonly method: string;
  readonly nextMethod: string;
  readonly status: number;
}
export interface RedirectHistory {
  readonly entries: readonly RedirectHop[];
  readonly omittedHops: number;
}
export interface RequestOptions {
  method: string;
  protocol: 'http1' | 'http2' | 'http3' | 'negotiated';
  context: RequestContext;
  headers?: Header[];
  /** Async iterables are one-shot, pulled with native backpressure. */
  body?: Uint8Array | AsyncIterable<Uint8Array>;
  /** Optional exact byte length. Only demanded bytes are checked; an early response can leave an unread suffix. */
  bodyLength?: number | bigint;
  file?: { path: string; maximumBytes: number };
  timeoutMs?: number;
  timeouts?: Timeouts;
  signal?: AbortSignal;
  attemptBudget?: AttemptBudget;
  contentDecoding?: ContentDecoding;
  redirectPolicy?: RedirectPolicy;
  retryPolicy?: RetryPolicy;
  redirectHistoryLimit?: number | bigint;
}
export class Response implements AsyncIterable<Buffer> {
  private constructor();
  readonly status: number;
  readonly protocol: 'http1' | 'http2' | 'http3';
  readonly url: string;
  readonly redirects: number;
  /** Connection-setup retries only; excludes status retries and protocol replays. */
  readonly connectionRetries: number;
  /** Selected chain in wire Content-Encoding order; not a completion signal. */
  readonly decodedContentCodings: readonly ContentCoding[];
  readonly redirectHistory: RedirectHistory | null;
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
  /** Encrypted supported state, at most 32 MiB; key must contain exactly 32 bytes. CPU work is not abortable. */
  exportSession(key: Uint8Array): Promise<Buffer>;
  /** Restores independent pools using this client's configuration; leaves this client unchanged. */
  restoreSession(snapshot: Uint8Array, key: Uint8Array, options?: RestoreSessionOptions): Promise<Client>;
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
