/// <reference types="node" />

import type { Readable } from 'node:stream';

export class PhantomError extends Error {
  readonly code: string;
  readonly protocol?: 'http1' | 'http2' | 'http3';
  readonly timeoutPhase?: 'poolAdmission' | 'connect' | 'responseHead' | 'readIdle' | 'total' | 'webSocketHandshake';
  /** Core profile-document, client-certificate, prepared-body or session checkpoint category. */
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
/** One part of a request-only, one-shot multipart encoder. */
export type StreamingMultipartPart = MultipartPart | Readonly<{
  name: string; filename?: string; contentType?: string;
} & (
  {stream: Readable | (AsyncIterableIterator<Uint8Array> & {return(value?: unknown): Promise<IteratorResult<Uint8Array>>}); file?: never; text?: never; bytes?: never}
  | {file: {readonly path: string; readonly maximumBytes: number}; stream?: never; text?: never; bytes?: never}
)>;
export interface StreamingMultipartOptions extends MultipartBodyOptions {
  /** Ordered duplicate fields; at most 1024, with at most 64 KiB metadata. */
  readonly parts: readonly StreamingMultipartPart[];
}
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
/** Immutable parsed identity; factories copy bytes before off-thread parsing. No private-key export. */
export class ClientCertificate {
  private constructor();
  private readonly _clientCertificate: void;
  static fromPem(certificateChain: Uint8Array, privateKey: Uint8Array): Promise<ClientCertificate>;
  static fromDer(certificateChain: readonly Uint8Array[], privateKey: Uint8Array): Promise<ClientCertificate>;
}
export interface ClientOptions {
  profile: string | Profile;
  route: 'direct' | 'proxy';
  proxy?: string;
  proxyUsername?: string;
  proxyPassword?: string;
  /** SOCKS4/4a only: at most 255 UTF-8 bytes, no NUL. Empty is allowed; passwords are unsupported. */
  proxyUserId?: string;
  cookies?: boolean;
  maximumActiveRequests?: number;
  additionalRoots?: Uint8Array[];
  additionalProxyRoots?: Uint8Array[];
  /** One to 32 raw SHA-256 digests of origin leaf DER SubjectPublicKeyInfo; verification remains required. */
  readonly serverSpkiPins?: readonly Uint8Array[];
  /** Independent leaf SPKI restrictions for HTTPS proxies, with normal verification. */
  readonly proxyServerSpkiPins?: readonly Uint8Array[];
  /** Default origin TLS client identity; normal server verification remains required. */
  readonly clientCertificate?: ClientCertificate;
  /** Ordered overrides; the last core-canonical matching origin wins. */
  readonly clientCertificatesFor?: readonly (readonly [string, ClientCertificate])[];
  baseUrl?: string;
  timeouts?: Timeouts;
  redirectPolicy?: RedirectPolicy;
  retryPolicy?: RetryPolicy;
  /** Copied during construction; omitted settings use OS/core defaults. */
  readonly network?: NetworkOptions;
  /** Operational pool overrides; omission retains core/profile defaults. */
  readonly pool?: PoolOptions;
}
/** Positive safe-integer counts. Core limits also apply. */
export interface PoolOptions {
  /** Retained HTTP/1.1 pool entries. */
  readonly maxRetainedHttp1Connections?: number;
  /** Active HTTP/1.1 requests per origin and route. */
  readonly maxConcurrentHttp1RequestsPerOrigin?: number;
  /** Waiting HTTP/1.1 requests per origin and route. */
  readonly maxPendingHttp1RequestsPerOrigin?: number;
  /** Retained HTTP/2 pool entries. */
  readonly maxRetainedHttp2Connections?: number;
  /** Active HTTP/2 requests across a pool key’s connections. */
  readonly maxConcurrentHttp2RequestsPerOrigin?: number;
  /** Waiting HTTP/2 requests per origin and route. */
  readonly maxPendingHttp2RequestsPerOrigin?: number;
  /** HTTP/2 connections per origin and route. */
  readonly maxHttp2ConnectionsPerOrigin?: number;
  /** Retained HTTP/3 pool entries. */
  readonly maxRetainedHttp3Connections?: number;
  /** Active HTTP/3 requests across a pool key’s connections. */
  readonly maxConcurrentHttp3RequestsPerOrigin?: number;
  /** Waiting HTTP/3 requests per origin and route. */
  readonly maxPendingHttp3RequestsPerOrigin?: number;
  /** QUIC connections per transport location (at most 8). */
  readonly maxHttp3ConnectionsPerOrigin?: number;
  /** Safe-integer milliseconds before another negotiated TLS setup; zero is valid. */
  readonly negotiatedSetupWaitLimitMs?: number;
}
/** A domain override affects local resolution, retaining TLS identity and HTTP authority. */
export interface HostOverride {
  readonly host: string;
  /** Ordered unscoped IP literals. Empty intentionally fails local resolution. */
  readonly addresses: readonly string[];
}
/** At most 1024 combined records/addresses and 65536 UTF-8 bytes. */
export interface NetworkOptions {
  /** Last core-canonical hostname wins; proxy-owned target resolution is unchanged. */
  readonly hostOverrides?: readonly HostOverride[];
  /** Last IP of each family wins; a single family excludes the other with no unbound fallback. */
  readonly localAddresses?: readonly string[];
  /** OS interface name; resolver queries are not source-bound. */
  readonly interface?: string;
  /** Fixed UTF-8 Unix socket path. Direct H1/H2 only; URL authority and TLS identity stay unchanged.
   * Unsupported on Windows and with host/source overrides, proxies, discovery or encrypted session checkpoints. */
  readonly unixSocket?: string;
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
  route: 'proxy'; proxy: string; proxyUsername?: string; proxyPassword?: string; proxyUserId?: string;
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
  /**
   * Exclusive with body, bodyLength and file. Core encoded maximum includes framing.
   * Unknown total length; one-shot, including buffered parts. Only the demanded
   * stream is pulled, with one native frame (<=64 KiB). Caller-yielded chunks
   * and Readable internal buffering remain caller-owned. File opens are lazy.
   * After validation the request owns all streams: direct self-iterators require
   * return(); Node Readables are destroyed on cleanup. Cleanup is cooperative.
   * Reuse of a descriptor or repeated source within it is rejected; wrapping the
   * same source in another descriptor does not transfer a second valid owner.
   */
  multipart?: StreamingMultipartOptions;
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
export interface ResponseHeader {
  readonly name: string;
  readonly value: Buffer;
  /** True for a preserved compression marker. False also covers decoders that omit markers. */
  readonly sensitive: boolean;
}
export type ResponseTrailers = Readonly<{state: 'pending' | 'unavailable'; headers: null}>
  | Readonly<{state: 'complete'; headers: readonly ResponseHeader[]}>;
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
  readonly headers: readonly ResponseHeader[];
  /** Non-draining snapshot. Complete requires validated body EOF; Buffers are owned copies. */
  readonly trailers: ResponseTrailers;
  /** Reads up to 1–65,536 bytes (default 65,536); returns null at EOF. */
  read(maximumBytes?: number): Promise<Buffer | null>;
  /** Collects the remaining body; exceeding the limit closes it and fails. */
  bytes(maximumBytes: number): Promise<Buffer>;
  /** Decodes the remaining body as strict UTF-8 within the byte limit. */
  text(maximumBytes: number): Promise<string>;
  /** Parses the remaining body within the byte limit; validate the returned value. */
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
