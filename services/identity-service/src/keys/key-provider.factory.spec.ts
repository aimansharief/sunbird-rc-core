import { assertCapabilities, createKeyProvider, requiredAlgorithms } from './key-provider.factory';
import { InMemoryKeyProvider } from './testing/in-memory-key-provider';

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
});
