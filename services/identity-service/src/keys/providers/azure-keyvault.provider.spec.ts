import * as crypto from 'crypto';
import { describeKeyProviderContract, verifyWithJwk } from '../testing/key-provider.contract';
import { FakeAzureKeyClient } from '../testing/fake-azure-key-client';
import { createKeyProvider } from '../key-provider.factory';
import { AzureKeyVaultProvider } from './azure-keyvault.provider';

const ref = () => `rc-test-${crypto.randomBytes(8).toString('hex')}`;

describeKeyProviderContract('azure-keyvault (mocked SDK)', async () =>
  new AzureKeyVaultProvider({ client: new FakeAzureKeyClient() as any, hsm: true }));

// Real Azure (phase 3b): runs only with AZURE_LIVE_TESTS=true and the AZURE_* settings of the target vault.
// Test keys are deleted afterwards (soft delete keeps them recoverable for the vault's retention period).
const live = process.env.AZURE_LIVE_TESTS === 'true';
describeKeyProviderContract(
  'azure-keyvault (live)',
  async () => (live ? createKeyProvider({ ...process.env, KEY_PROVIDER: 'azure-keyvault' }) : null),
  {
    cleanup: async (refs) => {
      const { KeyClient } = await import('@azure/keyvault-keys');
      const { DefaultAzureCredential } = await import('@azure/identity');
      const client = new KeyClient(process.env.AZURE_KEYVAULT_URL!, new DefaultAzureCredential());
      await Promise.all(refs.map((r) => client.beginDeleteKey(r).catch(() => undefined)));
    },
  },
);

describe('AzureKeyVaultProvider', () => {
  let client: FakeAzureKeyClient;
  let provider: AzureKeyVaultProvider;

  beforeEach(() => {
    client = new FakeAzureKeyClient();
    provider = new AzureKeyVaultProvider({ client: client as any, hsm: true });
  });

  it('advertises P-256 only', async () => {
    expect(provider.name).toBe('azure-keyvault');
    expect(await provider.capabilities()).toEqual(['P-256']);
  });

  it('creates an HSM or software P-256 signing key as configured', async () => {
    await provider.createKey('rc-a-1', 'P-256');
    const software = new AzureKeyVaultProvider({ client: client as any, hsm: false });
    await software.createKey('rc-a-2', 'P-256');
    expect(client.createCalls).toEqual([
      { name: 'rc-a-1', options: { curve: 'P-256', hsm: true, keyOps: ['sign', 'verify'] } },
      { name: 'rc-a-2', options: { curve: 'P-256', hsm: false, keyOps: ['sign', 'verify'] } },
    ]);
  });

  it('rejects Ed25519 without calling Key Vault', async () => {
    await expect(provider.createKey(ref(), 'Ed25519')).rejects.toThrow('azure-keyvault does not support Ed25519');
    await expect(provider.sign(ref(), 'Ed25519', Buffer.from('x'))).rejects.toThrow('azure-keyvault does not support Ed25519');
    expect(client.createCalls).toHaveLength(0);
  });

  it('refuses to create a key whose name already exists (Key Vault would add a version)', async () => {
    const name = ref();
    await provider.createKey(name, 'P-256');
    await expect(provider.createKey(name, 'P-256')).rejects.toThrow(`Key '${name}' already exists in Azure Key Vault`);
    expect(client.keys.get(name)).toHaveLength(1);
  });

  it('signs ES256 with the first key version, even after a version is added outside identity-service', async () => {
    const name = ref();
    const jwk = await provider.createKey(name, 'P-256');
    await client.createEcKey(name, { curve: 'P-256', hsm: true }); // rotated in the Azure portal
    const fresh = new AzureKeyVaultProvider({ client: client as any, hsm: true }); // no cached version

    expect(await fresh.getPublicKey(name, 'P-256')).toEqual(jwk);
    const data = Buffer.from('payload');
    const sig = await fresh.sign(name, 'P-256', data);
    expect(verifyWithJwk('P-256', jwk, data, sig)).toBe(true);
    const first = client.keys.get(name)![0].version;
    expect(client.signCalls).toEqual([{ name, version: first, algorithm: 'ES256' }]);
  });

  it('returns a public JWK without private or Azure-specific fields', async () => {
    const jwk: any = await provider.createKey(ref(), 'P-256');
    expect(Object.keys(jwk).sort()).toEqual(['crv', 'kty', 'x', 'y']);
    expect(jwk.kty).toBe('EC');
  });

  it('rejects a key that is not P-256', async () => {
    const name = ref();
    await provider.createKey(name, 'P-256');
    client.corruptToOkp(name);
    const fresh = new AzureKeyVaultProvider({ client: client as any, hsm: true });
    await expect(fresh.getPublicKey(name, 'P-256')).rejects.toThrow(`Azure key '${name}' is not a P-256 EC key`);
  });

  it('fails on an unknown key', async () => {
    await expect(provider.sign('rc-missing', 'P-256', Buffer.from('x'))).rejects.toThrow('was not found');
  });
});
