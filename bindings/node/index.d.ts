/// <reference types="node" />

export class PhantomError extends Error { readonly code: string; }
export class AttemptBudget {
  constructor(maximum: number);
  readonly remaining: number;
}
export interface Header { name: string; value: Uint8Array; sensitive?: boolean; }
export interface ClientOptions {
  profile: string;
  route: 'direct' | 'proxy';
  proxy?: string;
  proxyUsername?: string;
  proxyPassword?: string;
  cookies?: boolean;
  maximumActiveRequests?: number;
  additionalRoots?: Uint8Array[];
}
export interface RequestOptions {
  method: string;
  protocol: 'http1' | 'http2' | 'http3';
  context: 'raw' | 'navigation' | 'fetch' | 'fetchNoStore' | 'fetchUpload';
  headers?: Header[];
  body?: Uint8Array;
  file?: { path: string; maximumBytes: number };
  timeoutMs?: number;
  signal?: AbortSignal;
  attemptBudget?: AttemptBudget;
}
export class Response implements AsyncIterable<Buffer> {
  private constructor();
  readonly status: number;
  readonly headers: Header[];
  read(maximumBytes?: number): Promise<Buffer | null>;
  bytes(maximumBytes: number): Promise<Buffer>;
  close(): void;
  [Symbol.asyncIterator](): AsyncIterator<Buffer>;
  [Symbol.asyncDispose](): Promise<void>;
}
export class Client {
  constructor(options: ClientOptions);
  request(url: string, options: RequestOptions): Promise<Response>;
  setCookie(url: string, setCookie: string): void;
  cookieValue(url: string): string | null;
  close(options?: { timeoutMs?: number }): Promise<void>;
  [Symbol.asyncDispose](): Promise<void>;
}
export function profiles(): string[];
