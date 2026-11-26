import type { KeyClient } from '@azure/keyvault-keys';
import type { JWK } from 'jose';
import { KeyAlgorithm, KeyProvider } from '../key-provider';
import { b64url } from '../encoding';

export type AzureKeyClient = Pick<KeyClient, 'createEcKey' | 'getKey' | 'listPropertiesOfKeyVersions' | 'getCryptographyClient'>;

export interface AzureKeyVaultOptions {
  client: AzureKeyClient;
  hsm: boolean;   // EC-HSM (Premium, Managed HSM) or EC (Standard, software)
}

// One provider for Key Vault Standard, Premium and Managed HSM: same API, only the vault URL and key type differ.
// Keys are created without a release policy, so Key Vault never lets them be exported.
// Azure has no Ed25519, so only P-256 (ES256) is offered.
//
// A replacement key is always a new key, never a new version. Signing is pinned to the key's first
// version (the one published in the DID document), so a version added in Azure cannot silently break signatures.
export class AzureKeyVaultProvider implements KeyProvider {
  readonly name = 'azure-keyvault';
  private readonly client: AzureKeyClient;
  private readonly hsm: boolean;
  private readonly pinnedVersion = new Map<string, string>();

  constructor(opts: AzureKeyVaultOptions) {
    this.client = opts.client;
    this.hsm = opts.hsm;
  }

  async capabilities(): Promise<KeyAlgorithm[]> {
    return ['P-256'];
  }

  async createKey(keyRef: string, alg: KeyAlgorithm): Promise<JWK> {
    this.assertAlg(alg);
    if (await this.exists(keyRef)) throw new Error(`Key '${keyRef}' already exists in Azure Key Vault`);
    const key = await this.client.createEcKey(keyRef, { curve: 'P-256', hsm: this.hsm, keyOps: ['sign', 'verify'] });
    this.pinnedVersion.set(keyRef, key.properties.version!);
    return this.toJwk(keyRef, key.key);
  }

  async getPublicKey(keyRef: string, alg: KeyAlgorithm): Promise<JWK> {
    this.assertAlg(alg);
    const key = await this.client.getKey(keyRef, { version: await this.version(keyRef) });
    return this.toJwk(keyRef, key.key);
  }

  async sign(keyRef: string, alg: KeyAlgorithm, data: Uint8Array): Promise<Uint8Array> {
    this.assertAlg(alg);
    const crypto = this.client.getCryptographyClient(keyRef, { keyVersion: await this.version(keyRef) });
    // signData hashes locally (SHA-256) and sends only the digest; the result is the 64-byte r||s
    const { result } = await crypto.signData('ES256', data);
    if (result?.length !== 64) throw new Error(`Azure returned a ${result?.length}-byte signature for '${keyRef}', expected 64`);
    return new Uint8Array(result);
  }

  private async version(keyRef: string): Promise<string> {
    let version = this.pinnedVersion.get(keyRef);
    if (!version) {
      let first: { version?: string; createdOn?: Date } | undefined;
      for await (const p of this.client.listPropertiesOfKeyVersions(keyRef)) {
        if (!first || (p.createdOn?.getTime() ?? Infinity) < (first.createdOn?.getTime() ?? Infinity)) first = p;
      }
      if (!first?.version) throw new Error(`Azure key '${keyRef}' has no versions`);
      version = first.version;
      this.pinnedVersion.set(keyRef, version);
    }
    return version;
  }

  private async exists(keyRef: string): Promise<boolean> {
    try {
      await this.client.getKey(keyRef);
      return true;
    } catch (e: any) {
      if (e?.statusCode === 404) return false;
      throw e;
    }
  }

  private toJwk(keyRef: string, key: any): JWK {
    if (!['EC', 'EC-HSM'].includes(key?.kty) || key.crv !== 'P-256' || !key.x || !key.y) {
      throw new Error(`Azure key '${keyRef}' is not a P-256 EC key`);
    }
    return { kty: 'EC', crv: 'P-256', x: b64url(key.x), y: b64url(key.y) };
  }

  private assertAlg(alg: KeyAlgorithm): void {
    if (alg !== 'P-256') throw new Error(`azure-keyvault does not support ${alg}`);
  }
}
