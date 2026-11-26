import * as crypto from 'crypto';

// TEST ONLY. Mimics the parts of @azure/keyvault-keys KeyClient used by AzureKeyVaultProvider,
// including Key Vault semantics: creating an existing key name adds a new version, and getKey
// without a version returns the latest one.
type Version = { version: string; createdOn: Date; hsm: boolean; priv: crypto.KeyObject; pub: crypto.KeyObject };

export class FakeAzureKeyClient {
  readonly keys = new Map<string, Version[]>();
  readonly createCalls: { name: string; options: any }[] = [];
  readonly signCalls: { name: string; version?: string; algorithm: string }[] = [];
  private clock = Date.UTC(2026, 0, 1);

  async createEcKey(name: string, options: any = {}) {
    this.createCalls.push({ name, options });
    if (options.curve !== 'P-256') throw notSupported(`curve ${options.curve}`);
    const pair = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const v: Version = {
      version: crypto.randomBytes(16).toString('hex'),
      createdOn: new Date((this.clock += 1000)),
      hsm: !!options.hsm,
      priv: pair.privateKey,
      pub: pair.publicKey,
    };
    this.keys.set(name, [...(this.keys.get(name) || []), v]);
    return this.toKey(name, v);
  }

  async getKey(name: string, options: { version?: string } = {}) {
    return this.toKey(name, this.find(name, options.version));
  }

  listPropertiesOfKeyVersions(name: string): any {
    const fake = this;
    return (async function* () {
      const versions = fake.keys.get(name);
      if (!versions) throw notFound(name);
      // Key Vault does not promise any order
      for (const v of [...versions].reverse()) yield { name, version: v.version, createdOn: v.createdOn, enabled: true };
    })();
  }

  getCryptographyClient(name: string, options: { keyVersion?: string } = {}): any {
    return {
      signData: async (algorithm: string, data: Uint8Array) => {
        this.signCalls.push({ name, version: options.keyVersion, algorithm });
        if (algorithm !== 'ES256') throw notSupported(algorithm);
        const v = this.find(name, options.keyVersion);
        const result = crypto.sign('sha256', Buffer.from(data), { key: v.priv, dsaEncoding: 'ieee-p1363' } as any);
        return { result: new Uint8Array(result), algorithm, keyID: `${name}/${v.version}` };
      },
    };
  }

  // Replaces a key's public half with an Ed25519-style OKP key, to test type checks.
  corruptToOkp(name: string) {
    const v = this.find(name);
    const pair = crypto.generateKeyPairSync('ed25519');
    v.pub = pair.publicKey;
  }

  private find(name: string, version?: string): Version {
    const versions = this.keys.get(name);
    if (!versions) throw notFound(name);
    const v = version ? versions.find((x) => x.version === version) : versions[versions.length - 1];
    if (!v) throw notFound(`${name}/${version}`);
    return v;
  }

  private toKey(name: string, v: Version) {
    const jwk: any = v.pub.export({ format: 'jwk' });
    return {
      name,
      id: `https://fake.vault.azure.net/keys/${name}/${v.version}`,
      keyType: v.hsm ? 'EC-HSM' : 'EC',
      key: {
        kty: jwk.kty === 'EC' ? (v.hsm ? 'EC-HSM' : 'EC') : jwk.kty,
        crv: jwk.crv,
        x: jwk.x ? new Uint8Array(Buffer.from(jwk.x, 'base64url')) : undefined,
        y: jwk.y ? new Uint8Array(Buffer.from(jwk.y, 'base64url')) : undefined,
      },
      properties: { name, version: v.version, createdOn: v.createdOn, enabled: true },
    };
  }
}

function notFound(what: string) {
  return Object.assign(new Error(`A key with (name/id) ${what} was not found in this key vault.`), { statusCode: 404, code: 'KeyNotFound' });
}

function notSupported(what: string) {
  return Object.assign(new Error(`${what} is not supported`), { statusCode: 400, code: 'BadParameter' });
}
