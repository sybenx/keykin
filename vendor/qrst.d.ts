// Loose types for the bundled QRST library (see tools/build-qrst.mjs). The real ones are in qr-secret-transfer.
export type CodeCheck = 'none' | 'compare' | 'type';
export interface PairingParams { v: number; mode: 'offer' | 'request'; profile: string; pub: string; check: CodeCheck; token: string; relays: string[]; origin?: string }
export type Check<T> = { ok: true; value: T } | { ok: false; reason: string };
export interface Profile<T> {
  readonly id: string; readonly maxPayloadBytes: number; readonly revocable: boolean; readonly minCheck?: CodeCheck;
  encode(value: T): string; check(content: string): Check<T>; render(value: T): string;
  readonly direction: { offer: string; request: string };
  readonly release: { heading: string; body: string; confirm(origin: string | undefined): string; decline: string };
  readonly accept: { heading: string; confirm: string; decline: string };
}
export interface SessionView { role: string; phase: 'waiting' | 'code' | 'release' | 'accept' | 'sent' | 'ended'; outcome?: string; check: CodeCheck; code?: string; compare?: string; rendering?: string; released: boolean }
export interface TransferView<T> { stage: 'relays' | 'session' | 'ended'; session: SessionView; uri?: string; connected: boolean; peerOrigin?: string; viaCamera: boolean; value?: T; log: string[] }
export interface Env { random: (n: number) => Uint8Array; now: () => number }
export class Store { constructor(storage: unknown, now: () => number, seeds?: readonly string[], configured?: readonly string[]); }
export interface TransferDeps<T> { profile: Profile<T>; store: Store; env: Env; baseUrl: string; origin: string; check?: CodeCheck; replenish?: boolean; timing?: Record<string, number>; discoveryHints?: readonly string[] }
export class Transfer<T> {
  onChange: () => void;
  static refusal<T>(deps: TransferDeps<T>, params: PairingParams): string | undefined;
  static show<T>(deps: TransferDeps<T>, role: 'sender' | 'receiver', payload?: T): Transfer<T>;
  static join<T>(deps: TransferDeps<T>, params: PairingParams, how: { viaCamera: boolean }, payload?: T): Transfer<T>;
  view(): TransferView<T>;
  enterCode(digits: string): void; confirmMatch(): void; rejectMatch(): void; release(): void; decline(): void; accept(): void; cancel(): void; dispose(): void;
}
export function parseUri(input: string): PairingParams;
export const relayPolicy: { loopback: boolean };
export function isPrivateHost(hostname: string): boolean;
export const DEFAULT_MAX_PAYLOAD: number;
export function publicKey(secretKey: Uint8Array): string;
export function npubEncode(publicKeyHex: string): string;
export function isValidPublicKey(publicKeyHex: string): boolean;
export function bytesToHex(bytes: Uint8Array): string;
export function hexToBytes(hex: string): Uint8Array;
