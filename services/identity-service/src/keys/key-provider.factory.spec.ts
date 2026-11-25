import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { assertCapabilities, createKeyProvider, requiredAlgorithms } from './key-provider.factory';
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
});
