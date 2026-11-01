import type {
  ClientOptions, NetworkOptions, PoolOptions, RequestContext, CookieSnapshotEntry, AltSvcSnapshotEntry,
  RequestProtocol, SessionRoute, SessionSharing, TransferSnapshot,
  WebSocketHandshake,
} from '../index.js';
import type { NativeResponse } from './response.cjs';
import type { NativeUpload as UploadPump } from './upload.cjs';
import type { NativeRejection, NativeSocket } from './websocket.cjs';

type PhaseTimeout = { disabled: boolean; milliseconds: number };
type PhaseTimeouts = Partial<Record<
  'poolAdmission' | 'connect' | 'responseHead' | 'readIdle' | 'total', PhaseTimeout
>>;
export type NativeRedirectPolicy = {
  mode: string; maximumHops?: bigint; credentialHeaders?: readonly string[];
};
export type NativeConnectionRetry = {
  maximum: bigint; delayMs: number; maximumDelayMs?: number; fullJitter?: boolean;
};
export type NativeRetryPolicy = {
  connectionFailures?: NativeConnectionRetry; reusedConnectionReplay?: boolean;
  unprocessedReplays?: bigint; maximumRetries?: bigint; http2Fallback?: boolean;
  statusRetry?: NativeConnectionRetry & { statuses: number[]; retryAfterLimitMs?: number };
};

export interface NativeProfile { readonly contexts: string[]; }
export interface NativePreparedBody { readonly byteLength: bigint; readonly contentType: string; }
export interface NativeCancellation { cancel(): void; }
export interface NativeAttemptBudget { readonly remaining: number | bigint; tryAdmit(): void; }
export interface NativeTransferControl { snapshot(): TransferSnapshot; }
export interface NativeRequestDiagnostics { snapshot(): object | null; }
export interface NativeHeader { name: string; value: Buffer; sensitive?: boolean; }
export interface NativeHeaderInvocation {
  index: number; method: string; uri: string; headers: NativeHeader[]; serial?: bigint | null;
  redirect?: Omit<import('../index.js').RedirectAttempt, 'signal'> | null;
  logical?: NativeLogicalInvocation | null;
}
export interface NativeLogicalInvocation {
  phase: number; method: string; url: string; status?: number | null;
  protocol?: 'http1' | 'http2' | 'http3' | null; headers: NativeHeader[];
  effectiveUrl?: string | null; redirects?: number | null; retries?: number | null;
  decodedContentCodings: string[]; error?: string | null;
  originScheme?: string | null; originHost?: string | null; originPort?: number | null;
}
export type NativeHeaderEdit = {action: 'append' | 'set'; name: string; value: Buffer; sensitive?: boolean}
  | {action: 'remove'; name: string};
export interface NativeHeaderHooks {
  next(): Promise<NativeHeaderInvocation | null>;
  complete(index: number, edits: NativeHeaderEdit[], serial?: bigint): void;
  fail(index: number, serial?: bigint): void;
  nextCancelled(after: bigint): Promise<bigint | null>;
  isActive(serial: bigint): boolean;
  completeRedirect(hop: bigint, decision: import('../index.js').RedirectDecision, serial?: bigint): void;
  failRedirect(hop: bigint, serial?: bigint): void;
  completeLogical(serial: bigint, failed: boolean): void;
  closed(): Promise<void>;
  stop(): void;
  settled(): void;
}
interface MultipartField {
  name: string; text?: string; bytes?: Buffer; stream?: boolean;
  file?: { path: string; maximumBytes: number }; filename?: string; contentType?: string;
}
export interface NativeUpload extends UploadPump {
  configureMultipart(boundary: string, fields: MultipartField[], maximumBytes: bigint): void;
}

type NativeNetworkOptions = Omit<NetworkOptions, 'dns'> & {
  readonly dns?: import('./dns.cjs').NativeDnsOptions;
};

export type NativeClientOptions = Omit<ClientOptions,
  'profile' | 'protocol' | 'context' | 'headers' | 'additionalRoots' |
  'additionalProxyRoots' | 'serverSpkiPins' | 'proxyServerSpkiPins' |
  'clientCertificate' | 'clientCertificatesFor' | 'timeouts' |
  'redirectPolicy' | 'retryPolicy' | 'network' | 'pool' | 'headerHooks' | 'requestHooks'
> & {
  profile?: string; defaultContext?: RequestContext; additionalRoots?: Buffer[]; additionalProxyRoots?: Buffer[];
  serverSpkiPins?: Buffer[]; proxyServerSpkiPins?: Buffer[];
  clientCertificate?: object;
  clientCertificatesFor?: { origin: string; certificate: object }[];
  timeouts?: PhaseTimeouts; redirectPolicy?: NativeRedirectPolicy; retryPolicy?: NativeRetryPolicy;
  network?: NativeNetworkOptions; pool?: PoolOptions;
};

export interface NativeRequestOptions {
  url: string; method: string; protocol: RequestProtocol; context: RequestContext;
  headers?: readonly NativeHeader[]; trailers?: readonly NativeHeader[];
  expectContinueMs?: bigint; body?: Buffer; preparedBody?: NativePreparedBody;
  file?: { path: string; maximumBytes: number }; timeoutMs?: number;
  timeouts?: PhaseTimeouts; redirectPolicy?: NativeRedirectPolicy; retryPolicy?: NativeRetryPolicy;
  redirectHistoryLimit?: bigint;
  contentDecoding?: { mode: string; maximumDecodedBytes?: bigint };
}

export interface NativeClient {
  eventSource(options: object, source: import('./event-source.cjs').NativeSource, hooks?: NativeHeaderHooks): Promise<import('./event-source.cjs').NativeHead>;
  request(options: NativeRequestOptions, cancellation: NativeCancellation,
    budget?: NativeAttemptBudget, upload?: NativeUpload, transfer?: NativeTransferControl,
    diagnostics?: NativeRequestDiagnostics, headerHooks?: NativeHeaderHooks): Promise<NativeResponse>;
  websocket(settings: object, socket: NativeSocket): Promise<WebSocketHandshake | NativeRejection>;
  exportSession(key: Buffer): Promise<Buffer>;
  exportCookies(): readonly CookieSnapshotEntry[] | undefined;
  importCookies(entries: readonly CookieSnapshotEntry[]): void;
  exportAltSvc(): readonly AltSvcSnapshotEntry[] | undefined;
  importAltSvc(entries: readonly AltSvcSnapshotEntry[]): void;
  exportSessionTickets(key: Buffer): Promise<Buffer>;
  importSessionTickets(snapshot: Buffer, key: Buffer, routes: readonly SessionRoute[]): Promise<void>;
  setCookie(url: string, cookie: string): void;
  cookieValue(url: string): string | null;
  clearCookies(): void;
  clearDnsCache(): void;
  clearAltSvc(): void;
  clearAltSvcRacingHistory(): void;
  clearClientHints(): void;
  clearSessionTickets(): number;
  closeIdleConnections(): Promise<void>;
  refreshConnections(): Promise<void>;
  close(timeoutMs: number): Promise<void>;
  destroy(): void;
}

export interface NativeEnvironment {
  client(options: NativeClientOptions, profile?: NativeProfile): NativeClient;
  fork(source: NativeClient, sharing: SessionSharing): NativeClient;
  restoreSession(source: NativeClient, snapshot: Buffer, key: Buffer,
    routes: readonly SessionRoute[]): Promise<NativeClient>;
}
