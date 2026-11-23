import { ForbiddenException, InternalServerErrorException, NotFoundException } from '@nestjs/common';
import { KeyAlreadyRegisteredError } from './signing.service';
import { createPrismaServiceOrMock } from '../utils/test-infra.util';
import { createTestSigning, settle } from './testing/test-signing.util';
import { verifyWithJwk } from './testing/key-provider.contract';
import { signContextFrom } from './sign-context';

describe('SigningService', () => {
  let prisma: any;
  let t: ReturnType<typeof createTestSigning>;
  const did = `did:test:signing-${Date.now()}`;
  const data = Buffer.from('hello');

  beforeAll(async () => {
    prisma = await createPrismaServiceOrMock();
    t = createTestSigning(prisma);
  });
  afterEach(() => { delete process.env.ENFORCE_KEY_AUTHORITY; });

  it('creates a key, signs with it and writes a SIGNED audit row', async () => {
    const jwk = await t.signing.createKey({ keyId: `${did}#key-0`, did, algorithm: 'Ed25519' });
    const sig = await t.signing.sign(`${did}#key-0`, data, 'ldp_vc', { actor: 'alice' });
    expect(verifyWithJwk('Ed25519', jwk, data, sig)).toBe(true);
    const rows = await prisma.signingAuditLog.findMany({ where: { keyId: `${did}#key-0` } });
    expect(rows[rows.length - 1]).toMatchObject({
      outcome: 'SIGNED', purpose: 'ldp_vc', actor: 'alice', provider: 'in-memory',
      payloadSha256: '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824',
    });
  });

  it('refuses unknown keys', async () => {
    await expect(t.signing.sign(`${did}#nope`, data, 'jwt')).rejects.toBeInstanceOf(NotFoundException);
  });

  it('refuses RETIRED keys and audits the denial', async () => {
    await t.signing.createKey({ keyId: `${did}#key-9`, did, algorithm: 'P-256' });
    await t.registry.setStatus(`${did}#key-9`, 'RETIRED');
    await expect(t.signing.sign(`${did}#key-9`, data, 'jwt')).rejects.toBeInstanceOf(ForbiddenException);
    const rows = await prisma.signingAuditLog.findMany({ where: { keyId: `${did}#key-9` } });
    expect(rows[rows.length - 1].outcome).toBe('DENIED');
  });

  it('enforces authority scoping unless ENFORCE_KEY_AUTHORITY=false', async () => {
    await t.signing.createKey({ keyId: `${did}#auth`, did, algorithm: 'Ed25519', authority: 'moe' });
    await expect(t.signing.sign(`${did}#auth`, data, 'ldp_vc', { authority: 'agri' })).rejects.toBeInstanceOf(ForbiddenException);
    await expect(t.signing.sign(`${did}#auth`, data, 'ldp_vc', {})).rejects.toBeInstanceOf(ForbiddenException);
    await expect(t.signing.sign(`${did}#auth`, data, 'ldp_vc', { authority: 'moe' })).resolves.toHaveLength(64);
    process.env.ENFORCE_KEY_AUTHORITY = 'false';
    await expect(t.signing.sign(`${did}#auth`, data, 'ldp_vc', {})).resolves.toHaveLength(64);
  });

  it('fails closed when the audit row cannot be written', async () => {
    await t.signing.createKey({ keyId: `${did}#audit`, did, algorithm: 'Ed25519' });
    const spy = jest.spyOn(prisma.signingAuditLog, 'create').mockRejectedValueOnce(new Error('db down'));
    await expect(t.signing.sign(`${did}#audit`, data, 'ldp_vc')).rejects.toThrow();
    spy.mockRestore();
  });

  it('audits FAILED and returns 500 when the key provider fails (e.g. Vault sealed or unreachable)', async () => {
    await t.signing.createKey({ keyId: `${did}#down`, did, algorithm: 'Ed25519' });
    jest.spyOn(t.provider, 'sign').mockRejectedValueOnce(new Error('Vault is sealed'));
    await expect(t.signing.sign(`${did}#down`, data, 'ldp_vc')).rejects.toBeInstanceOf(InternalServerErrorException);
    const rows = await prisma.signingAuditLog.findMany({ where: { keyId: `${did}#down` } });
    expect(rows[rows.length - 1]).toMatchObject({ outcome: 'FAILED' });
    expect(rows[rows.length - 1].error).toContain('Vault is sealed');
  });

  it('refuses REVOKED keys', async () => {
    await t.signing.createKey({ keyId: `${did}#revoked`, did, algorithm: 'Ed25519' });
    await t.registry.setStatus(`${did}#revoked`, 'REVOKED');
    await expect(t.signing.sign(`${did}#revoked`, data, 'ldp_vc')).rejects.toThrow('REVOKED');
  });

  it('refuses a key recorded for a different provider than the one configured', async () => {
    await t.registry.register({ id: `${did}#elsewhere`, did, provider: 'azure-keyvault', keyRef: 'x', algorithm: 'P-256' });
    await expect(t.signing.sign(`${did}#elsewhere`, data, 'jwt'))
      .rejects.toThrow("held by provider 'azure-keyvault' but this service is configured with 'in-memory'");
  });

  it('reports a clear conflict when the same key id is registered twice concurrently', async () => {
    const keyId = `${did}#race`;
    const results = await settle([
      t.signing.createKey({ keyId, did, algorithm: 'P-256' }),
      t.signing.createKey({ keyId, did, algorithm: 'P-256' }),
    ]);
    expect(results.filter((r) => r.ok)).toHaveLength(1);
    const rejected = results.find((r) => !r.ok) as { ok: false; reason: any };
    expect(rejected.reason).toBeInstanceOf(KeyAlreadyRegisteredError);
    expect((await t.registry.listByDid(did)).filter((k) => k.id === keyId)).toHaveLength(1);
  });

  it('derives the sign context from request.user', () => {
    process.env.AUTHORITY_CLAIM = 'org';
    expect(signContextFrom({ user: { sub: 'u1', org: 'moe' } })).toEqual({ actor: 'u1', authority: 'moe' });
    expect(signContextFrom({})).toEqual({ actor: undefined, authority: undefined });
    delete process.env.AUTHORITY_CLAIM;
  });
});
