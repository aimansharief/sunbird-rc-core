import * as crypto from 'crypto';
import type { JWK } from 'jose';
import { KeyAlgorithm, KeyProvider } from '../key-provider';

// TEST ONLY. Holds private keys in process memory, which is exactly what C7 forbids in production.
export class InMemoryKeyProvider implements KeyProvider {
  readonly name = 'in-memory';
  private readonly keys = new Map<string, { alg: KeyAlgorithm; priv: crypto.KeyObject; pub: crypto.KeyObject }>();

  constructor(private readonly caps: KeyAlgorithm[] = ['Ed25519', 'P-256']) {}

  async capabilities(): Promise<KeyAlgorithm[]> {
    return [...this.caps];
  }

  async createKey(keyRef: string, alg: KeyAlgorithm): Promise<JWK> {
    this.assertAlg(alg);
    if (this.keys.has(keyRef)) throw new Error(`Key '${keyRef}' already exists`);
    const pair = alg === 'Ed25519'
      ? crypto.generateKeyPairSync('ed25519')
      : crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    this.keys.set(keyRef, { alg, priv: pair.privateKey, pub: pair.publicKey });
    return this.getPublicKey(keyRef, alg);
  }

  async getPublicKey(keyRef: string, alg: KeyAlgorithm): Promise<JWK> {
    const { x, y, kty, crv } = this.get(keyRef, alg).pub.export({ format: 'jwk' } as any) as any;
    return alg === 'Ed25519' ? { kty, crv, x } : { kty, crv, x, y };
  }

  async sign(keyRef: string, alg: KeyAlgorithm, data: Uint8Array): Promise<Uint8Array> {
    const { priv } = this.get(keyRef, alg);
    const sig = alg === 'Ed25519'
      ? crypto.sign(null, Buffer.from(data), priv)
      : crypto.sign('sha256', Buffer.from(data), { key: priv, dsaEncoding: 'ieee-p1363' } as any);
    return new Uint8Array(sig);
  }

  async importKey(keyRef: string, alg: KeyAlgorithm, pkcs8Der: Buffer): Promise<JWK> {
    this.assertAlg(alg);
    const priv = crypto.createPrivateKey({ key: pkcs8Der, format: 'der', type: 'pkcs8' });
    this.keys.set(keyRef, { alg, priv, pub: crypto.createPublicKey(priv) });
    return this.getPublicKey(keyRef, alg);
  }

  private assertAlg(alg: KeyAlgorithm) {
    if (!this.caps.includes(alg)) throw new Error(`Algorithm ${alg} not supported by in-memory provider`);
  }

  private get(keyRef: string, alg: KeyAlgorithm) {
    const k = this.keys.get(keyRef);
    if (!k) throw new Error(`Key '${keyRef}' not found`);
    if (k.alg !== alg) throw new Error(`Key '${keyRef}' is ${k.alg}, not ${alg}`);
    return k;
  }
}
