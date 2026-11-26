import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { assertCapabilities, assertDefaultKeyType, azureKeyVaultSettings, createKeyProvider, requiredAlgorithms } from './key-provider.factory';
import { InMemoryKeyProvider } from './testing/in-memory-key-provider';

const inMemoryPath = require.resolve('./testing/in-memory-key-provider');

function writeModule(source: string): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'rc-provider-'));
  const file = path.join(dir, 'provider.js');
  fs.writeFileSync(file, source);
  return file;
}

describe('key provider factory', () => {
  it('defaults to vault-transit', async () => {
    const p = await createKeyProvider({ VAULT_BASE_URL: 'http://vault:8200/v1', VAULT_TOKEN: 't' } as any);
    expect(p.name).toBe('vault-transit');
  });
  it('rejects unknown providers and missing config', async () => {
    await expect(createKeyProvider({ KEY_PROVIDER: 'nope' } as any)).rejects.toThrow("Unknown KEY_PROVIDER 'nope'");
    await expect(createKeyProvider({ KEY_PROVIDER: 'vault-transit' } as any)).rejects.toThrow('VAULT_BASE_URL is required');
  });
  it('parses REQUIRED_KEY_ALGORITHMS', () => {
    expect(requiredAlgorithms({} as any)).toEqual(['Ed25519', 'P-256']);
    expect(requiredAlgorithms({ REQUIRED_KEY_ALGORITHMS: 'P-256' } as any)).toEqual(['P-256']);
    expect(() => requiredAlgorithms({ REQUIRED_KEY_ALGORITHMS: 'RSA' } as any)).toThrow('Unknown algorithm');
  });
  it('fails startup when the provider lacks a required algorithm', async () => {
    await expect(assertCapabilities(new InMemoryKeyProvider(['P-256']), ['Ed25519', 'P-256']))
      .rejects.toThrow("KEY_PROVIDER 'in-memory' does not support: Ed25519");
  });

  describe('custom provider', () => {
    it('loads createProvider(env) from KEY_PROVIDER_MODULE and passes env through', async () => {
      const file = writeModule(`
        const { InMemoryKeyProvider } = require(${JSON.stringify(inMemoryPath)});
        exports.createProvider = async (env) => {
          const p = new InMemoryKeyProvider(['P-256']);
          p.seenSetting = env.MY_SETTING;
          return p;
        };`);
      const p: any = await createKeyProvider({ KEY_PROVIDER: 'custom', KEY_PROVIDER_MODULE: file, MY_SETTING: 'x' } as any);
      expect(p.name).toBe('in-memory');
      expect(p.seenSetting).toBe('x');
    });
    it('requires an absolute KEY_PROVIDER_MODULE path', async () => {
      await expect(createKeyProvider({ KEY_PROVIDER: 'custom' } as any)).rejects.toThrow('KEY_PROVIDER_MODULE is required');
      await expect(createKeyProvider({ KEY_PROVIDER: 'custom', KEY_PROVIDER_MODULE: 'aws-kms.js' } as any))
        .rejects.toThrow('KEY_PROVIDER_MODULE must be an absolute file path');
    });
    it('fails clearly when the module cannot be loaded or has no createProvider', async () => {
      await expect(createKeyProvider({ KEY_PROVIDER: 'custom', KEY_PROVIDER_MODULE: '/nonexistent/provider.js' } as any))
        .rejects.toThrow("Cannot load KEY_PROVIDER_MODULE '/nonexistent/provider.js'");
      const file = writeModule('exports.other = 1;');
      await expect(createKeyProvider({ KEY_PROVIDER: 'custom', KEY_PROVIDER_MODULE: file } as any))
        .rejects.toThrow('must export createProvider(env)');
    });
    it('rejects a provider missing KeyProvider methods', async () => {
      const file = writeModule(`exports.createProvider = async () => ({ name: 'half', sign: async () => new Uint8Array() });`);
      await expect(createKeyProvider({ KEY_PROVIDER: 'custom', KEY_PROVIDER_MODULE: file } as any))
        .rejects.toThrow("Custom key provider 'half' is missing: capabilities, createKey, getPublicKey");
    });
  });

  describe('default key type (SIGNING_ALGORITHM)', () => {
    const p256Only = new InMemoryKeyProvider(['P-256']);
    it('accepts a default the provider can create', async () => {
      await expect(assertDefaultKeyType(new InMemoryKeyProvider(), {} as any)).resolves.toBeUndefined();
      await expect(assertDefaultKeyType(p256Only, { SIGNING_ALGORITHM: 'JsonWebSignature2020' } as any)).resolves.toBeUndefined();
    });
    it('fails startup when the provider cannot create the default key type', async () => {
      await expect(assertDefaultKeyType(p256Only, {} as any))
        .rejects.toThrow("Default key type 'Ed25519VerificationKey2020' (Ed25519, from SIGNING_ALGORITHM='') is not supported by KEY_PROVIDER 'in-memory'. Set SIGNING_ALGORITHM=JsonWebSignature2020");
      await expect(assertDefaultKeyType(p256Only, { SIGNING_ALGORITHM: 'Ed25519Signature2018' } as any))
        .rejects.toThrow("Default key type 'Ed25519VerificationKey2018'");
    });
    it('fails startup when the default is RSA', async () => {
      await expect(assertDefaultKeyType(new InMemoryKeyProvider(), { SIGNING_ALGORITHM: 'RsaSignature2018' } as any))
        .rejects.toThrow("SIGNING_ALGORITHM 'RsaSignature2018' gives default key type 'RsaVerificationKey2018', which cannot be created");
    });
  });

  describe('azure-keyvault settings', () => {
    const base = { KEY_PROVIDER: 'azure-keyvault', AZURE_KEYVAULT_URL: 'https://rc-keys.vault.azure.net/' };
    const secret = { ...base, AZURE_AUTH_METHOD: 'client-secret', AZURE_TENANT_ID: 't', AZURE_CLIENT_ID: 'c', AZURE_CLIENT_SECRET: 's' };

    it('builds the provider with client-secret or managed-identity login', async () => {
      expect((await createKeyProvider(secret as any)).name).toBe('azure-keyvault');
      expect((await createKeyProvider({ ...base, AZURE_AUTH_METHOD: 'managed-identity' } as any)).name).toBe('azure-keyvault');
    });
    it('uses HSM keys by default and software keys when asked', () => {
      expect(azureKeyVaultSettings(secret as any)).toMatchObject({ vaultUrl: 'https://rc-keys.vault.azure.net/', hsm: true, authMethod: 'client-secret' });
      expect(azureKeyVaultSettings({ ...secret, AZURE_KEY_PROTECTION: 'software' } as any).hsm).toBe(false);
    });
    it('rejects missing or invalid settings', () => {
      expect(() => azureKeyVaultSettings({ ...secret, AZURE_KEYVAULT_URL: '' } as any)).toThrow('AZURE_KEYVAULT_URL is required');
      expect(() => azureKeyVaultSettings({ ...secret, AZURE_KEYVAULT_URL: 'http://rc-keys.vault.azure.net' } as any))
        .toThrow('AZURE_KEYVAULT_URL must be an https URL');
      expect(() => azureKeyVaultSettings({ ...secret, AZURE_KEY_PROTECTION: 'hardware' } as any))
        .toThrow("AZURE_KEY_PROTECTION must be 'hsm' or 'software'");
      expect(() => azureKeyVaultSettings(base as any))
        .toThrow("AZURE_AUTH_METHOD must be 'client-secret' or 'managed-identity'");
      expect(() => azureKeyVaultSettings({ ...secret, AZURE_CLIENT_SECRET: '' } as any)).toThrow('AZURE_CLIENT_SECRET is required');
    });
    it('rejects software keys on Managed HSM', () => {
      expect(() => azureKeyVaultSettings({ ...secret, AZURE_KEYVAULT_URL: 'https://rc.managedhsm.azure.net', AZURE_KEY_PROTECTION: 'software' } as any))
        .toThrow('Managed HSM only holds HSM keys');
    });
  });
});
