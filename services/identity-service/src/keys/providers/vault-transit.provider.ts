import axios, { AxiosInstance } from 'axios';
import type { JWK } from 'jose';
import { KeyAlgorithm, KeyProvider } from '../key-provider';
import { ed25519JwkFromRaw, fromB64url, publicJwkFromPem } from '../encoding';
import { wrapForVaultImport } from './vault-import-wrap';

export interface VaultTransitOptions {
  baseUrl: string;     // e.g. http://vault:8200/v1 (same as VAULT_BASE_URL)
  token: string;
  mount?: string;      // default 'transit'
  timeoutMs?: number;
}

// Keys are never rotated inside Transit: identity-service rotates by creating a new key and a new DID
// verification method. So the version published in the DID document is always 1, and signing is pinned
// to it; a Vault-side rotation (which would otherwise switch signing to v2) cannot silently break signatures.
const PUBLISHED_KEY_VERSION = 1;

export class VaultTransitProvider implements KeyProvider {
  readonly name = 'vault-transit';
  private readonly http: AxiosInstance;

  constructor(opts: VaultTransitOptions) {
    this.http = axios.create({
      baseURL: `${opts.baseUrl.replace(/\/$/, '')}/${opts.mount || 'transit'}`,
      headers: { 'X-Vault-Token': opts.token },
      timeout: opts.timeoutMs || 5000,
    });
  }

  async capabilities(): Promise<KeyAlgorithm[]> {
    return ['Ed25519', 'P-256'];
  }

  async createKey(keyRef: string, alg: KeyAlgorithm): Promise<JWK> {
    await this.http.post(`/keys/${encodeURIComponent(keyRef)}`, {
      type: this.vaultType(alg),
      exportable: false,
      allow_plaintext_backup: false,
    });
    return this.getPublicKey(keyRef, alg);
  }

  async getPublicKey(keyRef: string, alg: KeyAlgorithm): Promise<JWK> {
    const { data } = await this.http.get(`/keys/${encodeURIComponent(keyRef)}`);
    const key = data.data;
    if (key.type !== this.vaultType(alg)) {
      throw new Error(`Vault key '${keyRef}' is ${key.type}, expected ${this.vaultType(alg)}`);
    }
    const publicKey: string = key.keys[String(PUBLISHED_KEY_VERSION)].public_key;
    return alg === 'Ed25519'
      ? ed25519JwkFromRaw(Buffer.from(publicKey, 'base64'))
      : publicJwkFromPem(publicKey);
  }

  async sign(keyRef: string, alg: KeyAlgorithm, data: Uint8Array): Promise<Uint8Array> {
    const body: Record<string, string | number> = {
      input: Buffer.from(data).toString('base64'),
      key_version: PUBLISHED_KEY_VERSION,
    };
    let path = `/sign/${encodeURIComponent(keyRef)}`;
    if (alg === 'P-256') {
      path += '/sha2-256';
      body.marshaling_algorithm = 'jws';
    }
    const { data: res } = await this.http.post(path, body);
    const encoded = String(res.data.signature).split(':')[2]; // vault:v1:<sig>
    return alg === 'Ed25519' ? new Uint8Array(Buffer.from(encoded, 'base64')) : fromB64url(encoded);
  }

  async importKey(keyRef: string, alg: KeyAlgorithm, pkcs8Der: Buffer): Promise<JWK> {
    const { data } = await this.http.get('/wrapping_key');
    const ciphertext = wrapForVaultImport(data.data.public_key, pkcs8Der);
    await this.http.post(`/keys/${encodeURIComponent(keyRef)}/import`, {
      type: this.vaultType(alg),
      ciphertext,
      hash_function: 'SHA256',
      exportable: false,
    });
    return this.getPublicKey(keyRef, alg);
  }

  private vaultType(alg: KeyAlgorithm): string {
    if (alg === 'Ed25519') return 'ed25519';
    if (alg === 'P-256') return 'ecdsa-p256';
    throw new Error(`Unsupported algorithm ${alg}`);
  }
}
