import type { JWK } from 'jose';

export type KeyAlgorithm = 'Ed25519' | 'P-256';
export const KEY_ALGORITHMS: KeyAlgorithm[] = ['Ed25519', 'P-256'];
export const KEY_PROVIDER = Symbol('KEY_PROVIDER');

// A signing boundary. Implementations MUST NOT return or log private key material.
// Ed25519: sign() is PureEdDSA over `data`, returns 64 raw bytes.
// P-256:   sign() is ECDSA over SHA-256(data), returns 64-byte IEEE-P1363 r||s.
export interface KeyProvider {
  readonly name: string;
  capabilities(): Promise<KeyAlgorithm[]>;
  createKey(keyRef: string, alg: KeyAlgorithm): Promise<JWK>;
  getPublicKey(keyRef: string, alg: KeyAlgorithm): Promise<JWK>;
  sign(keyRef: string, alg: KeyAlgorithm, data: Uint8Array): Promise<Uint8Array>;
  // Optional: import an existing private key (PKCS#8 DER) for migration.
  importKey?(keyRef: string, alg: KeyAlgorithm, pkcs8Der: Buffer): Promise<JWK>;
}
