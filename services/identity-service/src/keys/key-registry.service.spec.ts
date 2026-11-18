import { KeyRegistryService } from './key-registry.service';
import { createPrismaServiceOrMock } from '../utils/test-infra.util';

describe('KeyRegistryService', () => {
  let registry: KeyRegistryService;
  const did = `did:test:${Date.now()}`;

  beforeAll(async () => {
    registry = new KeyRegistryService(await createPrismaServiceOrMock());
  });

  it('builds provider-safe key refs scoped by authority', () => {
    expect(KeyRegistryService.buildKeyRef('Ministry of Education!')).toMatch(/^rc-ministry-of-education-[0-9a-f]{32}$/);
    expect(KeyRegistryService.buildKeyRef()).toMatch(/^rc-default-[0-9a-f]{32}$/);
  });

  it('registers keys and returns the newest ACTIVE key per algorithm', async () => {
    await registry.register({ id: `${did}#key-0`, did, provider: 'in-memory', keyRef: 'a', algorithm: 'Ed25519' });
    await registry.register({ id: `${did}#key-1`, did, provider: 'in-memory', keyRef: 'b', algorithm: 'Ed25519' });
    await registry.setStatus(`${did}#key-0`, 'RETIRED');
    expect((await registry.findActive(did, 'Ed25519'))?.id).toBe(`${did}#key-1`);
    expect(await registry.findActive(did, 'P-256')).toBeNull();
    expect((await registry.listByDid(did)).map((k) => k.id)).toEqual([`${did}#key-0`, `${did}#key-1`]);
  });

  it('removes keys', async () => {
    await registry.remove(`${did}#key-1`);
    expect(await registry.findById(`${did}#key-1`)).toBeNull();
  });
});
