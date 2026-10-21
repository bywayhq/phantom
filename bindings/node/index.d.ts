/// <reference types="node" />

export class PhantomError extends Error {
  readonly code: string;
  readonly protocol?: 'http1' | 'http2' | 'http3';
  readonly timeoutPhase?: 'poolAdmission' | 'connect' | 'responseHead' | 'readIdle' | 'total' | 'webSocketHandshake';
  /** Core profile-document, prepared-body or session checkpoint category. */
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
/** Immutable shared body-byte caps and rates; omission leaves a direction unlimited. */
export interface TransferLimits {
  readonly uploadBytes?: number | bigint;
  readonly downloadBytes?: number | bigint;
  readonly uploadBytesPerSecond?: number | bigint;
  readonly downloadBytesPerSecond?: number | bigint;
}
export interface TransferSnapshot {
  readonly uploadReservedBytes: bigint;
  readonly uploadBodyBytes: bigint;
  readonly downloadReservedBytes: bigint;
  readonly downloadEncodedBytes: bigint;
  /** Core frames delivered to the binding; can include a buffered unread remainder. */
  readonly downloadDecodedBytes: bigint;
}
export class TransferControl {
  /** Exact unsigned u64 caps (zero allowed); rates must be positive. */
  constructor(limits?: TransferLimits);
  /** Coherent frozen counters across all attached requests and attempts. */
  snapshot(): Readonly<TransferSnapshot>;
}
export interface Header { name: string; value: Uint8Array; sensitive?: boolean; }
export interface PreparedBodyOptions { readonly maximumBytes: number | bigint; }
export interface MultipartBodyOptions extends PreparedBodyOptions { readonly boundary: string; }
export type MultipartPart = Readonly<{name: string; filename?: string; contentType?: string} & (
  {text: string; bytes?: never} | {bytes: Uint8Array; text?: never}
)>;
/** Immutable, replayable bytes encoded by the native core, with no generated boundary. */
export class PreparedBody {
  private constructor();
  static form(pairs: readonly (readonly [string, string])[], options: PreparedBodyOptions): Promise<PreparedBody>;
  static multipart(parts: readonly MultipartPart[], options: MultipartBodyOptions): Promise<PreparedBody>;
  readonly contentType: string;
  readonly byteLength: bigint;
}
/**
 * Omit to inherit; null disables. Total zero rejects before sending;
 * other zero phase timers can race ready work.
 */
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
  /** Single-use live observer; keep it to inspect failed/cancelled sends. */
  diagnostics?: RequestDiagnostics;
  method: string;
  protocol: 'http1' | 'http2' | 'http3' | 'negotiated';
  context: RequestContext;
  headers?: Header[];
  /** Ordered static trailers; H2/H3 names must be lowercase. Sent only after successful body completion. */
  trailers?: Header[];
  /** Opt-in 100-continue wait in exact nonnegative milliseconds, including zero. */
  expectContinueMs?: number | bigint;
  /** Prepared bodies are reusable; async iterables are one-shot and pulled with native backpressure. */
  body?: Uint8Array | AsyncIterable<Uint8Array> | PreparedBody;
  /** Optional exact byte length. Only demanded bytes are checked; an early response can leave an unread suffix. */
  bodyLength?: number | bigint;
  file?: { path: string; maximumBytes: number };
  timeoutMs?: number;
  timeouts?: Timeouts;
  signal?: AbortSignal;
  attemptBudget?: AttemptBudget;
  transferControl?: TransferControl;
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

export type RequestTimelineOutcome = 'not_started' | 'pending' | 'response_head' | 'failed' | 'cancelled';
export type RequestTimingPhase = 'attempt_admission' | 'pool_admission' | 'connection_acquisition'
  | 'connection_use' | 'resolution_wait' | 'tcp_connect' | 'tls_handshake' | 'quic_handshake'
  | 'send_response_head' | 'response_body';
export type RequestTimingOutcome = 'pending' | 'completed' | 'failed' | 'interrupted' | 'abandoned' | 'cached' | 'early_data';
export interface TLSConnectionInfo {
  readonly peerVerified: boolean;
  readonly versionId: number | null;
  readonly cipherSuiteId: number | null;
  /** Owned bytes; snapshot records are frozen, Buffer contents remain editable. */
  readonly alpn: Buffer | null;
  readonly sessionResumed: boolean;
  /** Available leaf-first DER, not a constructed trust chain; null means unavailable. */
  readonly peerCertificatesDer: readonly Buffer[] | null;
}
export type TLSConnectionState = Readonly<{state: 'not_used' | 'unavailable' | 'pending'; info: null}>
  | Readonly<{state: 'established'; info: TLSConnectionInfo}>;
export interface RequestConnection {
  /** Earlier HTTP dispatch on this connection, separate from TLS resumption. */
  readonly reused: boolean;
  readonly endpointScope: 'unavailable' | 'tcp_socket' | 'quic_endpoint';
  readonly localAddress: string | null;
  /** May identify a proxy rather than the origin. */
  readonly peerAddress: string | null;
  readonly originTls: TLSConnectionState;
  readonly proxyTls: TLSConnectionState;
}
export interface RequestTiming {
  readonly id: bigint;
  readonly hop: bigint;
  readonly admission: bigint | null;
  readonly protocol: 'h1' | 'h2' | 'h3' | null;
  readonly phase: RequestTimingPhase;
  readonly startedNs: bigint;
  readonly finishedNs: bigint | null;
  readonly outcome: RequestTimingOutcome;
  readonly connection: RequestConnection | null;
}
export interface RequestTimeline {
  /** Send outcome only: response_head does not mean the body completed. */
  readonly outcome: RequestTimelineOutcome;
  readonly sendElapsedNs: bigint | null;
  /** Start order; intervals can overlap. Missing phases are unobserved, not zero. */
  readonly events: readonly RequestTiming[];
  readonly droppedEvents: bigint;
  /** Admission does not prove bytes were sent. */
  readonly admittedAttempts: bigint;
}
export class RequestDiagnostics {
  private readonly _owner: never;
  constructor(options?: {maximumEvents?: number | bigint});
  /** Null before core attachment. Copies do not clear events; binary/record copies are capped at 16 MiB. */
  snapshot(): RequestTimeline | null;
}
