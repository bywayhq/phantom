/// <reference types="node" />

import type { Readable } from 'node:stream';

export class PhantomError extends Error {
  readonly code: string;
  readonly protocol?: 'http1' | 'http2' | 'http3';
  readonly timeoutPhase?: 'poolAdmission' | 'connect' | 'responseHead' | 'readIdle' | 'total' | 'webSocketHandshake';
  /** Core profile-document, SSE, client-certificate, prepared-body or state transfer category. */
  readonly kind?: string;
  /** Canonical document field path; supplied values are omitted. */
  readonly field?: string;
  /** Zero-based rejected cookie or Alt-Svc entry; no supplied values are exposed. */
  readonly entryIndex?: number;
  /** Underlying host/native failure, available through explicit inspection. */
  readonly cause?: unknown;
  /** Failure while observing the primary error; its cause retains the host thrown value. */
  readonly hookError?: PhantomError;
  readonly origin?: Readonly<{scheme: string; host: string; port: number}>;
  /** HTTP status when a WebSocket opening response rejects the upgrade. */
  readonly status?: number;
  /** Rejected WebSocket opening; read or close its body to release the request slot. */
  readonly response?: Response;
  /** Iterator cleanup failure; may become available after request settlement. */
  readonly cleanupError?: unknown;
}
/** Large unsigned integers use bigint rather than rounded JavaScript numbers. */
export type ProfileValue = null | boolean | number | bigint | string | ProfileValue[] | { [key: string]: ProfileValue };
export type CatalogContext = 'navigation' | 'fetch' | 'fetchNoStore' | 'fetchUpload'
  | 'script' | 'stylesheet' | 'image' | 'font';
export type RequestContext = 'raw' | 'profile' | CatalogContext;
export type RequestProtocol = 'http1' | 'http2' | 'http3' | 'negotiated';
/** Order and duplicate names are preserved. Values are encoded as form fields. */
export type OrderedFields = URLSearchParams | readonly (readonly [string, string])[];
/** Imported fields and the settings supplied by the base profile. */
export interface ImportedProfile {
  readonly profile: Profile;
  readonly observedFields: readonly string[];
  readonly supplementedFields: readonly string[];
}
export interface ProfileImportOptions { readonly base: Profile; }
export interface JA4ImportOptions extends ProfileImportOptions { readonly format: 'sorted' | 'original'; }
/** Immutable native profile settings. */
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
  /** QUIC transport parameters encoded as a TLS extension 57 payload. */
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
/** Runs once before the first HTTP attempt, after request fields are prepared. */
export type HeaderHook = (context: HeaderHookContext) => void | Promise<void>;

/** One logical send: redirects/retries do not repeat phases. Dropping or cancelling
 * a send creates no terminal callback. An exhausted deadline may prevent terminal
 * host dispatch. Callback awaits share the total deadline.
 * Response callbacks observe the final head; later body failures have no callback.
 * A failed request callback enters onError once. Response/error callback failures
 * never recurse. Errors retain host causes, with hookError for a secondary failure. */
export interface RequestHooks {
  readonly onRequest?: (context: RequestHookContext) => void | Promise<void>;
  readonly onResponse?: (context: ResponseHookContext) => void | Promise<void>;
  readonly onError?: (context: RequestErrorHookContext) => void | Promise<void>;
}
export interface RequestHookContext {
  readonly method: string;
  readonly url: string;
  readonly signal: AbortSignal;
}
export interface ResponseHookContext {
  readonly request: RequestHookContext;
  readonly signal: AbortSignal;
  readonly status: number;
  readonly protocol?: 'http1' | 'http2' | 'http3';
  /** Owned HeaderMap copies, preserving duplicates without a wire-order claim. */
  readonly headers: readonly ResponseHeader[];
  readonly url?: string;
  readonly redirects?: number;
  readonly connectionRetries?: number;
  readonly decodedContentCodings: readonly string[];
}
export interface RequestErrorHookContext {
  readonly request: RequestHookContext;
  readonly signal: AbortSignal;
  readonly error: PhantomError;
}
/** Ordered caller fields for one callback. Mutations expire when the callback returns. */
export class HeaderHookContext {
  private constructor();
  readonly method: string;
  readonly url: string;
  /** Aborted when the request is cancelled or its total deadline expires. */
  readonly signal: AbortSignal;
  /** Fresh copies in wire preparation order, including duplicate names. */
  readonly headers: readonly Readonly<Header>[];
  append(header: Header): void;
  /** Replaces matching fields at their first position, ignoring name case. */
  set(header: Header): void;
  remove(name: string): void;
}
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
  /** Copied callback bundle; inherited by fork and restore, before request callbacks. */
  readonly requestHooks?: RequestHooks;
  /** Ordered caller-header hooks for request/get/post and the other HTTP methods. */
  readonly headerHooks?: readonly HeaderHook[];
  profile: string | Profile;
  /** Default negotiated protocol; an explicit request choice overrides it. */
  protocol?: RequestProtocol;
  /** Defaults to an attached Profile template; otherwise set this or a request context. */
  context?: RequestContext;
  /** Copied at construction. Request fields replace same-name defaults, ignoring case. */
  headers?: readonly Header[];
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
  /** Positive capacity opts into Alt-Svc discovery; omission keeps it disabled. */
  readonly maxAltSvcOrigins?: number | bigint;
  /** Separate direct, verified encrypted address resolver. */
  readonly dns?: EncryptedDns;
  /** Disable address caching; omission retains the profile policy. */
  readonly dnsCache?: false;
  /** Restrict new direct connections to public IPs; proxies/custom streams are unsupported. */
  readonly publicOnly?: boolean;
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
/** DNS endpoint settings share 1024 bootstrap/root entries and 65536 UTF-8/DER bytes. */
export interface DnsLookupOptions {
  /** IP literals for HTTPS; IP:port socket addresses for TLS, with brackets around IPv6. */
  readonly bootstrap: readonly string[];
  /** Positive finite milliseconds for the whole lookup. */
  readonly timeoutMs: number;
  /** Positive exact lookup count; DNS-over-TLS permits at most 32767. */
  readonly maxConcurrent: number | bigint;
  readonly families?: 'dual' | 'ipv4';
  /** Additional DNS-only DER trust anchors; verification remains required. */
  readonly roots?: readonly Uint8Array[];
  /** Omission keeps the preset; null disables padding; 1..65535 sets block bytes. */
  readonly paddingBlock?: number | null;
}
export type EncryptedDns = (DnsLookupOptions & Readonly<{
  kind: 'https'; endpoint: string; method?: 'post' | 'get';
  wire?: 'standard' | 'chromium154'; queryId?: number;
}>) | (DnsLookupOptions & Readonly<{kind: 'tls'; serverName: string}>);
/** Selected live state only; pools and cancellation stay independent. */
export interface SessionSharing {
  cookies?: boolean;
  dns?: boolean;
  clientHints?: boolean;
  discovery?: boolean;
  tickets?: boolean;
}
/** An explicit direct or proxy route, including proxy credentials. */
export type SessionRoute = Readonly<{route: 'direct'}> | Readonly<{
  route: 'proxy'; proxy: string; proxyUsername?: string; proxyPassword?: string; proxyUserId?: string;
}>;
export interface RestoreSessionOptions {
  /** Request-only routes; at most 256 entries and 64 KiB aggregate UTF-8 proxy/credential/user-ID text. */
  readonly receivingRoutes?: readonly SessionRoute[];
}
/** Caller-owned backend. Bound reads to 32 MiB before collecting bytes; null only means absence.
 * Honor signal and own admission, ordering and durability. Accepted writes cannot be rolled back. */
export interface SessionStore {
  load(name: string, options: {readonly signal: AbortSignal}): Promise<Uint8Array | null>;
  save(name: string, snapshot: Uint8Array, options: {readonly signal: AbortSignal}): Promise<void>;
}
export interface SessionStorageOptions {
  /** One total finite bound, in milliseconds; positive and at most 2147483647. */
  readonly timeoutMs: number;
  readonly signal?: AbortSignal;
}
export interface LoadSessionOptions extends SessionStorageOptions, RestoreSessionOptions {}
export type ContentDecoding = Readonly<{mode: 'none'}>
  | Readonly<{mode: 'advertised'; maximumDecodedBytes: number | bigint}>;
export type ContentCoding = 'gzip' | 'deflate' | 'br' | 'zstd';
/** Custom credential names are stripped permanently on cross-origin hops. */
export type RedirectPolicy = (Readonly<{mode: 'none'}>
  | Readonly<{mode: 'limited'; maximumHops: number | bigint}>
  | Readonly<{mode: 'custom'; maximumHops: number | bigint; callback: RedirectCallback}>)
  & Readonly<{credentialHeaders?: readonly string[]}>;
export const RedirectDecision: Readonly<{Follow: 'follow'; Stop: 'stop'; Reject: 'reject'}>;
export type RedirectDecision = 'follow' | 'stop' | 'reject';
/** Owned immutable metadata for an eligible hop in an ordinary HTTP request.
 * Dedicated EventSource does not support custom redirect defaults. */
export interface RedirectAttempt {
  readonly fromUrl: string;
  readonly toUrl: string;
  readonly status: number;
  readonly method: string;
  readonly nextMethod: string;
  readonly hop: bigint;
  /** Aborted when the native request ends. Callbacks must cooperate with I/O
   * cancellation; client shutdown waits for their actual settlement. */
  readonly signal: AbortSignal;
}
/** Core replay, credential, hop, budget and total-deadline rules still apply. */
export type RedirectCallback = (attempt: RedirectAttempt) => RedirectDecision | Promise<RedirectDecision>;
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
  /** Client callbacks run first, once per logical phase across retries/redirects. */
  readonly requestHooks?: RequestHooks;
  /** Runs after client hooks, once across retries and redirects. */
  readonly headerHooks?: readonly HeaderHook[];
  readonly skipClientHeaderHooks?: boolean;
  /** Single-use live observer; keep it to inspect failed/cancelled sends. */
  diagnostics?: RequestDiagnostics;
  /** Defaults to GET. Method helpers set their own method. */
  method?: string;
  protocol?: RequestProtocol;
  context?: RequestContext;
  headers?: readonly Header[];
  /** Appended to the URL without changing existing query spelling. */
  query?: OrderedFields;
  /** JSON.stringify semantics; prepared application/json body. Exclusive with other payloads and bodyLength. */
  json?: unknown;
  /** Prepared application/x-www-form-urlencoded;charset=UTF-8 body. Exclusive with other payloads and bodyLength. */
  form?: OrderedFields;
  /** Ordered static trailers; H2/H3 names must be lowercase. Sent only after successful body completion. */
  trailers?: Header[];
  /** Opt-in 100-continue wait in exact nonnegative milliseconds, including zero. */
  expectContinueMs?: number | bigint;
  /** Prepared bodies are reusable; async iterables are one-shot and pulled with native backpressure. */
  body?: string | Uint8Array | AsyncIterable<Uint8Array> | PreparedBody;
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
export type MethodOptions = Omit<RequestOptions, 'method'>;
export interface ResponseHeader {
  readonly name: string;
  readonly value: Buffer;
  /** True for a preserved compression marker. False also covers decoders that omit markers. */
  readonly sensitive: boolean;
}
export type ResponseTrailers = Readonly<{state: 'pending' | 'unavailable'; headers: null}>
  | Readonly<{state: 'complete'; headers: readonly ResponseHeader[]}>;
export interface SseOptions {
  /** Encoded bytes per line, excluding its terminator; default 65,536. Zero rejects nonempty lines. */
  readonly maximumLineBytes?: number;
  /** Encoded bytes per event block, excluding terminators; default 1,048,576. Zero rejects nonempty blocks. */
  readonly maximumEventBytes?: number;
}
export interface SseEvent {
  /** Data fields joined by newlines; invalid UTF-8 is replaced. */
  readonly data: string;
  /** Defaults to message. */
  readonly event: string;
  /** Persistent last-event ID at dispatch. */
  readonly id: string;
  /** Latest valid retry in milliseconds at dispatch; null until observed, including exact zero. */
  readonly retryMs: bigint | null;
}
export type EventSourceHeader = Header | Readonly<{lastEventId: string}>;
export interface EventSourceOptions {
  /** Client-first logical callbacks for each GET; redirects/retries stay inside it. */
  readonly requestHooks?: RequestHooks;
  /** Client hooks precede these hooks on every fresh GET, once across redirects/retries. Managed Last-Event-ID cannot be edited. */
  readonly headerHooks?: readonly HeaderHook[];
  readonly skipClientHeaderHooks?: boolean;
  /** Exact protocol; negotiated selection is not supported by the core source. */
  readonly protocol: 'http1' | 'http2' | 'http3';
  /** Ordered fields plus an optional managed ID position. Omission adds SSE Accept/cache fields. Client headers are inherited unless replaced by name. */
  readonly headers?: readonly EventSourceHeader[];
  readonly limits?: SseOptions;
  /** Response-body inactivity. Omission disables it; zero is an immediate deadline. */
  readonly idleTimeoutMs?: number;
  /** Finite nonnegative milliseconds; default 3000. */
  readonly initialRetryMs?: number;
  readonly minimumRetryMs?: number;
  /** Reconnects after the first attempt, including setup retries; default 3, zero disables. */
  readonly maximumReconnects?: number;
  /** Per-attempt limits end at the response head. Use idleTimeoutMs for body inactivity. */
  readonly timeouts?: Omit<Timeouts, 'readIdleMs'>;
  /** Inherited by every reconnect; omission retains the client route. */
  readonly route?: SessionRoute;
  /** Cancels the whole source, including setup, reads and reconnect sleep. */
  readonly signal?: AbortSignal;
}
export type EventSourceEvent = Pick<SseEvent, 'data' | 'event' | 'id'>;
export class EventSource implements AsyncIterableIterator<EventSourceEvent> {
  private constructor();
  readonly status: number;
  readonly protocol: 'http1' | 'http2' | 'http3';
  readonly url: string;
  readonly headers: readonly ResponseHeader[];
  readonly lastEventId: string;
  /** Effective reconnect delay, including any configured minimum. */
  readonly retryMs: bigint;
  readonly reconnects: number;
  readonly closed: boolean;
  /** One pending read; terminal errors occur once, then EOF. Per-read cancellation retains the source, GET and callback pump. */
  read(options?: {readonly signal?: AbortSignal}): Promise<EventSourceEvent | null>;
  /** Interrupts setup, a pending read or backoff and releases this source. */
  close(): void;
  /** Closes and awaits actual native/host cleanup within one deadline; retry after timeout. Cannot await from its own callback. Late errors retain the thrown value in cause. */
  closeAsync(options?: {readonly timeoutMs?: number}): Promise<void>;
  next(): Promise<IteratorResult<EventSourceEvent>>;
  return(): Promise<IteratorResult<EventSourceEvent>>;
  throw(error: unknown): Promise<never>;
  [Symbol.asyncIterator](): AsyncIterableIterator<EventSourceEvent>;
  [Symbol.dispose](): void;
  [Symbol.asyncDispose](): Promise<void>;
}
export class EventStream implements AsyncIterableIterator<SseEvent> {
  private constructor();
  /** Latest committed ID, including ID-only blocks consumed before EOF. */
  readonly lastEventId: string;
  /** Latest valid retry delay in milliseconds, or null before one is observed. */
  readonly retryMs: bigint | null;
  /** One read at a time; null at EOF. Terminal errors are returned once. */
  read(): Promise<SseEvent | null>;
  /** Cancels this response and interrupts a pending read. */
  close(): void;
  next(): Promise<IteratorResult<SseEvent>>;
  return(): Promise<IteratorResult<SseEvent>>;
  throw(error: unknown): Promise<never>;
  [Symbol.asyncIterator](): AsyncIterableIterator<SseEvent>;
  [Symbol.dispose](): void;
  [Symbol.asyncDispose](): Promise<void>;
}
export class Response implements AsyncIterable<Buffer> {
  private constructor();
  readonly status: number;
  readonly protocol: 'http1' | 'http2' | 'http3';
  readonly url: string;
  readonly redirects: number;
  /** Connection-setup retries only; null on a WebSocket rejection without attempt metadata. */
  readonly connectionRetries: number | null;
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
  /** Transfers an unread 200 text/event-stream response to the Rust decoder.
   * Invalid metadata leaves the body readable. No reconnect or new request.
   */
  events(options?: SseOptions): EventStream;
  close(): void;
  [Symbol.asyncIterator](): AsyncIterator<Buffer>;
  [Symbol.asyncDispose](): Promise<void>;
}
export interface WebSocketOptions {
  /** Default http1; profile uses the recipe's connection policy. */
  readonly protocol?: 'profile' | 'http1' | 'http2' | 'http3';
  /** Omission inherits the client route; this changes only the opening. */
  readonly route?: SessionRoute;
  /** Fills the Rust opening template; also inherits client headers. */
  readonly headers?: readonly Header[];
  /** Covers opening and the entire connection lifetime. */
  readonly signal?: AbortSignal;
  /** Omit for the recipe's timer; null disables it. */
  readonly handshakeTimeoutMs?: number | null;
  /** Defaults to min(16 MiB, maximumMessageBytes). */
  readonly maximumFrameBytes?: number;
  /** At most 64 MiB; decompressed bytes count against this limit. */
  readonly maximumMessageBytes?: number;
  readonly maximumMessageFragments?: number;
  /** Only connection-setup failures; no implicit reconnect or resend. */
  readonly maximumConnectionFailures?: number;
  readonly retryDelayMs?: number;
}
export type WebSocketMessage = Readonly<{type: 'text'; data: string}>
  | Readonly<{type: 'binary' | 'ping' | 'pong'; data: Buffer}>
  | Readonly<{type: 'close'; code: number | null; reason: string | null}>;
export interface WebSocketHandshake {
  readonly status: number;
  readonly protocol: 'http1' | 'http2' | 'http3';
  readonly selectedProtocol: string | null;
  readonly headers: readonly Readonly<Header>[];
}
export class WebSocketConnection implements AsyncIterable<WebSocketMessage> {
  private constructor();
  readonly handshake: Readonly<WebSocketHandshake>;
  /** Pulls one complete message or control event; null follows clean completion. */
  receive(): Promise<WebSocketMessage | null>;
  /** Resolves after flush; await each send for backpressure. */
  send(data: string | Uint8Array): Promise<void>;
  ping(data?: Uint8Array): Promise<void>;
  pong(data?: Uint8Array): Promise<void>;
  /** Flushes a Close frame (empty when code is omitted); receive the peer's reply to finish. */
  close(code?: number, reason?: string): Promise<void>;
  /** Cancels setup or I/O and releases this connection without a Close frame. */
  abort(): void;
  [Symbol.dispose](): void;
  /** Breaking iteration aborts this connection. */
  [Symbol.asyncIterator](): AsyncIterator<WebSocketMessage>;
}
/** Plain credential-bearing cookie data, in creation order. */
export interface CookieSnapshotEntry {
  readonly sourceScheme: 'http' | 'https';
  readonly name: string;
  readonly value: string;
  readonly domain: string;
  readonly path: string;
  readonly hostOnly: boolean;
  readonly secure: boolean;
  readonly httpOnly: boolean;
  readonly sameSite: 'strict' | 'lax' | 'none' | null;
  readonly partitionKey: string | null;
  /** Signed Unix nanoseconds; null denotes a session cookie. Core cookies use whole seconds. */
  readonly expiresAtNanoseconds: bigint | null;
}
/** Direct-route alternatives, least recently used first; alternatives retain field order. */
export interface AltSvcSnapshotEntry {
  readonly origin: string;
  readonly alternativeHost: string;
  readonly alternativePort: number;
  /** Signed Unix nanoseconds. Core export rounds down to whole seconds. */
  readonly expiresAtNanoseconds: bigint;
}
export class Client {
  /** Opens a pull-driven reconnecting GET source using the client's profile, defaults and state. */
  eventSource(url: string | URL, options: EventSourceOptions): Promise<EventSource>;
  constructor(options: ClientOptions);
  /** Creates an open client with independent pools, even from a closed source. */
  fork(sharing?: SessionSharing): Client;
  /** Encrypted supported state, at most 32 MiB; key must contain exactly 32 bytes. CPU work is not abortable. */
  exportSession(key: Uint8Array): Promise<Buffer>;
  /** null means disabled; [] means enabled and empty. Cookie data is unencrypted. */
  exportCookies(): readonly CookieSnapshotEntry[] | null;
  /** Atomic validation; existing cookies win. At most 16384 entries and 32 MiB UTF-8 text. */
  importCookies(entries: readonly CookieSnapshotEntry[]): void;
  /** null means disabled. Excludes proxy-owned alternatives and validation state. */
  exportAltSvc(): readonly AltSvcSnapshotEntry[] | null;
  /** Atomic validation; existing origins win. At most 32768 entries and 32 MiB UTF-8 text. */
  importAltSvc(entries: readonly AltSvcSnapshotEntry[]): void;
  /** Encrypted ticket-only state, at most 16 MiB, using a 32-byte key. Non-consuming; CPU work is not abortable. */
  exportSessionTickets(key: Uint8Array): Promise<Buffer>;
  /** Authenticates before mutation. Receiving routes select compatible owners, not routing; at most 256 routes/64 KiB UTF-8 text. CPU work is not abortable. */
  importSessionTickets(snapshot: Uint8Array, key: Uint8Array, options?: RestoreSessionOptions): Promise<void>;
  /** Restores independent pools using this client's configuration; leaves this client unchanged. */
  restoreSession(snapshot: Uint8Array, key: Uint8Array, options?: RestoreSessionOptions): Promise<Client>;
  /** Saves encrypted state. Backend errors retain cause; CPU encoding cannot be interrupted. */
  saveSession(store: SessionStore, name: string, key: Uint8Array, options: SessionStorageOptions): Promise<void>;
  /** null only means absence; late cancelled restored clients are destroyed before delivery. */
  loadSession(store: SessionStore, name: string, key: Uint8Array, options: LoadSessionOptions): Promise<Client | null>;
  request(url: string | URL, options?: RequestOptions): Promise<Response>;
  websocket(url: string | URL, options?: WebSocketOptions): Promise<WebSocketConnection>;
  get(url: string | URL, options?: MethodOptions): Promise<Response>;
  head(url: string | URL, options?: MethodOptions): Promise<Response>;
  post(url: string | URL, options?: MethodOptions): Promise<Response>;
  put(url: string | URL, options?: MethodOptions): Promise<Response>;
  patch(url: string | URL, options?: MethodOptions): Promise<Response>;
  delete(url: string | URL, options?: MethodOptions): Promise<Response>;
  options(url: string | URL, options?: MethodOptions): Promise<Response>;
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
  /** Stops new requests and waits for admitted work, including open WebSockets.
   * A timeout leaves existing responses and sockets usable. Close can be retried.
   * Concurrent calls join the pending close and its original timeout.
   */
  close(options?: { timeoutMs?: number }): Promise<void>;
  /** Aborts admitted work, then waits for cleanup within the close timeout. */
  destroy(options?: { timeoutMs?: number }): Promise<void>;
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
  /** Includes attempts that fail before sending bytes. */
  readonly admittedAttempts: bigint;
}
export class RequestDiagnostics {
  private readonly _owner: never;
  constructor(options?: {maximumEvents?: number | bigint});
  /** Null before core attachment. Copies do not clear events; binary/record copies are capped at 16 MiB. */
  snapshot(): RequestTimeline | null;
}
