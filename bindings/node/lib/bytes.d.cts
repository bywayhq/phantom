/// <reference types="node" />

/** Rejects shared or detached storage before returning a byte view. */
export function bytes(value: unknown): Buffer;
export const apply: typeof Reflect.apply;
/** Captured intrinsic TypedArray accessors on every supported Node host. */
export function lengthOf(this: Uint8Array): number;
export function offsetOf(this: Uint8Array): number;
export function backingOf(this: Uint8Array): ArrayBuffer | SharedArrayBuffer;
