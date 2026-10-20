/// <reference types="node" />

export class PhantomError extends Error {
  readonly code: string;
  readonly protocol?: 'http1' | 'http2' | 'http3';
  readonly timeoutPhase?: 'poolAdmission' | 'connect' | 'responseHead' | 'readIdle' | 'total' | 'webSocketHandshake';
}
export class AttemptBudget {
  constructor(maximum: number);
  readonly remaining: number;
}
export interface Header { name: string; value: Uint8Array; sensitive?: boolean; }
/** Omit a phase to inherit it. null disables it; zero is an immediate limit. */
export interface Timeouts {
  poolAdmissionMs?: number | null;
  connectMs?: number | null;
  responseHeadMs?: number | null;
  readIdleMs?: number | null;
  totalMs?: number | null;
}
export interface ClientOptions {
  profile: string;
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
export interface RequestOptions {
  method: string;
  protocol: 'http1' | 'http2' | 'http3' | 'negotiated';
  context: 'raw' | 'navigation' | 'fetch' | 'fetchNoStore' | 'fetchUpload';
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
  request(url: string, options: RequestOptions): Promise<Response>;
  setCookie(url: string, setCookie: string): void;
  cookieValue(url: string): string | null;
  clearCookies(): void;
  clearDnsCache(): void;
  clearAltSvc(): void;
  clearClientHints(): void;
  clearSessionTickets(): number;
  closeIdleConnections(): Promise<void>;
  refreshConnections(): Promise<void>;
  close(options?: { timeoutMs?: number }): Promise<void>;
  [Symbol.asyncDispose](): Promise<void>;
}
export function profiles(): string[];
