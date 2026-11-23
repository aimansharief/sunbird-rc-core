import { NotFoundException, InternalServerErrorException, Logger } from '@nestjs/common';
import * as jose from 'jose';
import { JwtSignerService } from './jwt.service';
import { PrismaService } from '../utils/prisma.service';
import { createInMemoryPrismaMock } from '../utils/test-infra.util';
import { createTestSigning } from '../keys/testing/test-signing.util';
import { DidService } from '../did/did.service';

describe('JwtSignerService', () => {
  const signerDID = 'did:rcw:signer-1';

  let prisma: { identity: { findUnique: jest.Mock; update: jest.Mock; findMany: jest.Mock } };
  let t: ReturnType<typeof createTestSigning>;
  let didService: { resolveDID: jest.Mock };
  let service: JwtSignerService;

  function baseDidDoc(verificationMethod: any[] = []) {
    return { id: signerDID, verificationMethod, assertionMethod: [], authentication: [] };
  }

  beforeEach(() => {
    prisma = { identity: { findUnique: jest.fn(), update: jest.fn(), findMany: jest.fn() } };
    t = createTestSigning(createInMemoryPrismaMock());
    didService = { resolveDID: jest.fn() };
    service = new JwtSignerService(
      prisma as unknown as PrismaService,
      didService as unknown as DidService,
      t.signing,
      t.registry,
    );
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  async function issueJwt(payload: Record<string, any> = { hello: 'world' }) {
    prisma.identity.findUnique.mockResolvedValue({ id: signerDID, didDoc: JSON.stringify(baseDidDoc()) });
    let issuerDoc: any;
    prisma.identity.update.mockImplementation(async ({ data }: any) => {
      issuerDoc = JSON.parse(data.didDoc);
      return {};
    });
    const jwt = await service.signJwt(signerDID, payload);
    didService.resolveDID.mockResolvedValue(issuerDoc);
    return { jwt, issuerDoc, kid: `${signerDID}#jwt-key-1` };
  }

  async function issueSdJwt(payload: Record<string, any>, disclosable: string[] = []) {
    prisma.identity.findUnique.mockResolvedValue({ id: signerDID, didDoc: JSON.stringify(baseDidDoc()) });
    let issuerDoc: any;
    prisma.identity.update.mockImplementation(async ({ data }: any) => {
      issuerDoc = JSON.parse(data.didDoc);
      return {};
    });
    const sdJwt = await service.signSdJwt(signerDID, payload, disclosable);
    didService.resolveDID.mockResolvedValue(issuerDoc);
    return { sdJwt, issuerDoc };
  }

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('ensureES256Key', () => {
    it('returns the active P-256 key without creating a new one', async () => {
      const existingVmId = `${signerDID}#jwt-key-1`;
      await t.signing.createKey({ keyId: existingVmId, did: signerDID, algorithm: 'P-256' });
      prisma.identity.findUnique.mockResolvedValue({
        id: signerDID,
        didDoc: JSON.stringify(baseDidDoc([{ id: existingVmId, type: 'JsonWebKey2020', publicKeyJwk: { kty: 'EC', crv: 'P-256' } }])),
      });
      const createSpy = jest.spyOn(t.provider, 'createKey');

      expect(await service.ensureES256Key(signerDID)).toEqual({ kid: existingVmId });
      expect(createSpy).not.toHaveBeenCalled();
      expect(prisma.identity.update).not.toHaveBeenCalled();
    });

    it('throws NotFoundException when the DID does not exist', async () => {
      prisma.identity.findUnique.mockResolvedValue(null);
      await expect(service.ensureES256Key(signerDID)).rejects.toThrow(NotFoundException);
    });

    it('throws InternalServerErrorException when the Prisma read fails', async () => {
      prisma.identity.findUnique.mockRejectedValue(new Error('db down'));
      await expect(service.ensureES256Key(signerDID)).rejects.toThrow(InternalServerErrorException);
    });

    it('refuses to silently replace an unmigrated legacy P-256 key', async () => {
      prisma.identity.findUnique.mockResolvedValue({
        id: signerDID,
        didDoc: JSON.stringify(baseDidDoc([{ id: `${signerDID}#jwt-key-1`, publicKeyJwk: { crv: 'P-256' } }])),
      });
      await expect(service.ensureES256Key(signerDID)).rejects.toThrow('not in the key registry');
      expect(prisma.identity.update).not.toHaveBeenCalled();
    });

    it('creates the key in the provider and publishes only its public half', async () => {
      prisma.identity.findUnique.mockResolvedValue({ id: signerDID, didDoc: JSON.stringify(baseDidDoc()) });
      prisma.identity.update.mockResolvedValue({});

      const result = await service.ensureES256Key(signerDID);

      expect(result).toEqual({ kid: `${signerDID}#jwt-key-1` });
      const updatedDoc = JSON.parse(prisma.identity.update.mock.calls[0][0].data.didDoc);
      expect(updatedDoc.verificationMethod).toHaveLength(1);
      expect(updatedDoc.verificationMethod[0]).toMatchObject({ id: result.kid, type: 'JsonWebKey2020', controller: signerDID });
      expect(updatedDoc.verificationMethod[0].publicKeyJwk).toMatchObject({ kty: 'EC', crv: 'P-256', alg: 'ES256', kid: result.kid });
      expect(updatedDoc.verificationMethod[0].publicKeyJwk.d).toBeUndefined();
      expect(updatedDoc.assertionMethod).toContain(result.kid);
      expect(updatedDoc.authentication).toContain(result.kid);
      expect(await t.registry.findById(result.kid)).toMatchObject({ algorithm: 'P-256', status: 'ACTIVE' });
    });

    it('drops the key record when the DID document cannot be updated', async () => {
      prisma.identity.findUnique.mockResolvedValue({ id: signerDID, didDoc: JSON.stringify(baseDidDoc()) });
      prisma.identity.update.mockRejectedValue(new Error('write failed'));
      await expect(service.ensureES256Key(signerDID)).rejects.toThrow(InternalServerErrorException);
      expect(await t.registry.findById(`${signerDID}#jwt-key-1`)).toBeNull();
    });

    it('two concurrent first-time requests get the same key and the DID document is updated once', async () => {
      prisma.identity.findUnique.mockResolvedValue({ id: signerDID, didDoc: JSON.stringify(baseDidDoc()) });
      prisma.identity.update.mockResolvedValue({});
      const [a, b] = await Promise.all([service.ensureES256Key(signerDID), service.ensureES256Key(signerDID)]);
      expect(a).toEqual({ kid: `${signerDID}#jwt-key-1` });
      expect(b).toEqual(a);
      expect(prisma.identity.update).toHaveBeenCalledTimes(1);
      expect((await t.registry.listByDid(signerDID)).filter((k) => k.algorithm === 'P-256')).toHaveLength(1);
    });

    it('uses the DID\'s own P-256 #key-0 (JsonWebKey2020 DID) instead of creating #jwt-key-1', async () => {
      await t.signing.createKey({ keyId: `${signerDID}#key-0`, did: signerDID, algorithm: 'P-256' });
      prisma.identity.findUnique.mockResolvedValue({ id: signerDID, didDoc: JSON.stringify(baseDidDoc()) });
      const createSpy = jest.spyOn(t.provider, 'createKey');
      expect(await service.ensureES256Key(signerDID)).toEqual({ kid: `${signerDID}#key-0` });
      expect(createSpy).not.toHaveBeenCalled();
    });

    it('gives the new key the authority of the DID\'s existing keys', async () => {
      await t.signing.createKey({ keyId: `${signerDID}#key-0`, did: signerDID, algorithm: 'Ed25519', authority: 'moe' });
      prisma.identity.findUnique.mockResolvedValue({ id: signerDID, didDoc: JSON.stringify(baseDidDoc()) });
      prisma.identity.update.mockResolvedValue({});
      const { kid } = await service.ensureES256Key(signerDID, { authority: 'agri' });
      expect((await t.registry.findById(kid)).authority).toBe('moe');
    });
  });

  describe('signJwt', () => {
    it('signs a payload into a JWT that verifies against the persisted DID document', async () => {
      const { jwt, issuerDoc } = await issueJwt({ sub: 'holder-1', claim: 'value' });

      const header = jose.decodeProtectedHeader(jwt);
      expect(header.alg).toBe('ES256');
      expect(header.kid).toBe(`${signerDID}#jwt-key-1`);

      didService.resolveDID.mockResolvedValue(issuerDoc);
      const result = await service.verifyJwt(jwt);
      expect(result).toEqual({ verified: true, payload: { sub: 'holder-1', claim: 'value' } });
    });

    it('signs through the key provider and refuses callers from another authority', async () => {
      await t.signing.createKey({ keyId: `${signerDID}#jwt-key-1`, did: signerDID, algorithm: 'P-256', authority: 'moe' });
      prisma.identity.findUnique.mockResolvedValue({ id: signerDID, didDoc: JSON.stringify(baseDidDoc()) });
      const signSpy = jest.spyOn(t.provider, 'sign');
      await expect(service.signJwt(signerDID, { a: 1 }, {}, { authority: 'agri' })).rejects.toThrow('not authorised');
      expect(signSpy).not.toHaveBeenCalled();
      await expect(service.signJwt(signerDID, { a: 1 }, {}, { authority: 'moe' })).resolves.toMatch(/^ey/);
      expect(signSpy).toHaveBeenCalledTimes(1);
    });

    it('propagates ensureES256Key errors', async () => {
      prisma.identity.findUnique.mockResolvedValue(null);
      await expect(service.signJwt(signerDID, {})).rejects.toThrow(NotFoundException);
    });
  });

  describe('verifyJwt', () => {
    it('returns verified:false when neither a kid header nor a DID is given', async () => {
      const key = await jose.generateKeyPair('ES256');
      const noKidJwt = await new jose.CompactSign(new TextEncoder().encode(JSON.stringify({ a: 1 })))
        .setProtectedHeader({ alg: 'ES256' })
        .sign(key.privateKey);

      const result = await service.verifyJwt(noKidJwt);
      expect(result).toEqual({ verified: false, error: 'No kid header or DID given' });
    });

    it('returns "no JWK verification method" when kid is absent and the DID has no JWK verification methods', async () => {
      const key = await jose.generateKeyPair('ES256');
      const noKidJwt = await new jose.CompactSign(new TextEncoder().encode(JSON.stringify({ a: 1 })))
        .setProtectedHeader({ alg: 'ES256' })
        .sign(key.privateKey);
      didService.resolveDID.mockResolvedValue(baseDidDoc([]));

      const result = await service.verifyJwt(noKidJwt, signerDID);
      expect(result).toEqual({ verified: false, error: 'No JWK verification method on DID' });
    });

    it('fails closed when the kid does not match any verification method on the resolved DID', async () => {
      const { jwt, kid } = await issueJwt();
      didService.resolveDID.mockResolvedValue(
        baseDidDoc([{ id: `${signerDID}#unrelated`, publicKeyJwk: { kty: 'EC' } }]),
      );

      const result = await service.verifyJwt(jwt);
      expect(result.verified).toBe(false);
      expect(result.error).toContain(`No verification method matching kid '${kid}'`);
    });

    it('rejects a tampered signature', async () => {
      const { jwt, issuerDoc } = await issueJwt();
      didService.resolveDID.mockResolvedValue(issuerDoc);
      const [header, payload, signature] = jwt.split('.');
      const sigBytes = Buffer.from(signature, 'base64url');
      sigBytes[Math.floor(sigBytes.length / 2)] ^= 0xff;
      const tampered = `${header}.${payload}.${sigBytes.toString('base64url')}`;

      const result = await service.verifyJwt(tampered);
      expect(result.verified).toBe(false);
    });

    it('returns verified:false when resolving the DID throws', async () => {
      const { jwt } = await issueJwt();
      didService.resolveDID.mockRejectedValue(new NotFoundException('nope'));

      const result = await service.verifyJwt(jwt);
      expect(result.verified).toBe(false);
    });
  });

  describe('signSdJwt', () => {
    it('replaces disclosable claims with sorted _sd digests and separate disclosures', async () => {
      const { sdJwt } = await issueSdJwt({ name: 'Alice', age: 30, country: 'IN' }, ['age', 'country']);

      expect(sdJwt.endsWith('~')).toBe(true);
      const parts = sdJwt.split('~');
      const disclosures = parts.slice(1).filter(Boolean);
      expect(disclosures).toHaveLength(2);

      const header = jose.decodeProtectedHeader(parts[0]);
      expect(header.typ).toBe('vc+sd-jwt');

      const decodedPayload = JSON.parse(Buffer.from(parts[0].split('.')[1], 'base64url').toString());
      expect(decodedPayload.name).toBe('Alice');
      expect(decodedPayload.age).toBeUndefined();
      expect(decodedPayload.country).toBeUndefined();
      expect(decodedPayload._sd).toHaveLength(2);
      expect(decodedPayload._sd).toEqual([...decodedPayload._sd].sort());
      expect(decodedPayload._sd_alg).toBe('sha-256');
    });

    it('skips a disclosable key that is absent from the payload', async () => {
      const { sdJwt } = await issueSdJwt({ name: 'Alice' }, ['missingClaim']);
      const parts = sdJwt.split('~');
      expect(parts.slice(1).filter(Boolean)).toHaveLength(0);
      const decodedPayload = JSON.parse(Buffer.from(parts[0].split('.')[1], 'base64url').toString());
      expect(decodedPayload._sd).toBeUndefined();
    });

    it('produces a plain JWT with a trailing ~ and no _sd when disclosable is empty', async () => {
      const { sdJwt } = await issueSdJwt({ name: 'Alice' }, []);
      expect(sdJwt.endsWith('~')).toBe(true);
      expect(sdJwt.split('~')).toHaveLength(2);
      expect(sdJwt.split('~')[1]).toBe('');
      const decodedPayload = JSON.parse(Buffer.from(sdJwt.split('~')[0].split('.')[1], 'base64url').toString());
      expect(decodedPayload._sd).toBeUndefined();
      expect(decodedPayload._sd_alg).toBeUndefined();
    });
  });

  describe('verifySdJwt', () => {
    it('round-trips: reconstructs all disclosed claims, verified:true', async () => {
      const { sdJwt } = await issueSdJwt({ name: 'Alice', age: 30 }, ['age']);
      const result = await service.verifySdJwt(sdJwt);
      expect(result).toEqual({ verified: true, claims: { name: 'Alice', age: 30 } });
    });

    it('rejects an invalid issuer signature', async () => {
      const { sdJwt } = await issueSdJwt({ name: 'Alice' });
      const signatureSegment = sdJwt.split('.')[2].split('~')[0];
      const tampered = sdJwt.replace(signatureSegment, 'invalidsignaturevalue');

      const result = await service.verifySdJwt(tampered);
      expect(result.verified).toBe(false);
      expect(result.error).toContain('Issuer signature invalid');
    });

    it('rejects when a disclosure digest is not present in _sd', async () => {
      const { sdJwt } = await issueSdJwt({ name: 'Alice', age: 30 }, ['age']);
      const [jws] = sdJwt.split('~');
      const forgedDisclosure = Buffer.from(JSON.stringify(['forged-salt', 'age', 99])).toString('base64url');
      const forged = [jws, forgedDisclosure, ''].join('~');

      const result = await service.verifySdJwt(forged);
      expect(result).toEqual({ verified: false, error: 'Disclosure digest not found in _sd' });
    });

    it('fails closed when a Key Binding JWT is required but absent', async () => {
      const { sdJwt } = await issueSdJwt({ name: 'Alice' });
      const result = await service.verifySdJwt(sdJwt, undefined, { nonce: 'abc' });
      expect(result).toEqual({
        verified: false,
        error: 'Key Binding JWT required (nonce/audience expected) but not present in SD-JWT',
      });
    });

    it('verifies a KB-JWT bound by an inline cnf.jwk, checking nonce and audience', async () => {
      const holderKey = await jose.generateKeyPair('ES256', { extractable: true });
      const holderPublicJwk = await jose.exportJWK(holderKey.publicKey);
      const { sdJwt } = await issueSdJwt({ name: 'Alice', cnf: { jwk: holderPublicJwk } });
      const kbJwt = await new jose.CompactSign(
        new TextEncoder().encode(JSON.stringify({ nonce: 'n-1', aud: 'verifier-1' })),
      )
        .setProtectedHeader({ alg: 'ES256' })
        .sign(holderKey.privateKey);

      const result = await service.verifySdJwt(`${sdJwt}${kbJwt}`, undefined, {
        nonce: 'n-1',
        audience: 'verifier-1',
      });
      expect(result.verified).toBe(true);
      expect(result.claims?.name).toBe('Alice');
    });

    it('rejects a KB-JWT nonce mismatch', async () => {
      const holderKey = await jose.generateKeyPair('ES256', { extractable: true });
      const holderPublicJwk = await jose.exportJWK(holderKey.publicKey);
      const { sdJwt } = await issueSdJwt({ name: 'Alice', cnf: { jwk: holderPublicJwk } });
      const kbJwt = await new jose.CompactSign(new TextEncoder().encode(JSON.stringify({ nonce: 'wrong' })))
        .setProtectedHeader({ alg: 'ES256' })
        .sign(holderKey.privateKey);

      const result = await service.verifySdJwt(`${sdJwt}${kbJwt}`, undefined, { nonce: 'n-1' });
      expect(result).toEqual({ verified: false, error: 'KB-JWT nonce mismatch' });
    });

    it('resolves cnf.kid via a self-contained did:jwk without touching the DID registry', async () => {
      const holderKey = await jose.generateKeyPair('ES256', { extractable: true });
      const holderPublicJwk = await jose.exportJWK(holderKey.publicKey);
      const kid = `did:jwk:${Buffer.from(JSON.stringify(holderPublicJwk)).toString('base64url')}`;
      const { sdJwt } = await issueSdJwt({ name: 'Alice', cnf: { kid } });
      const kbJwt = await new jose.CompactSign(new TextEncoder().encode(JSON.stringify({ nonce: 'n-1' })))
        .setProtectedHeader({ alg: 'ES256' })
        .sign(holderKey.privateKey);

      const result = await service.verifySdJwt(`${sdJwt}${kbJwt}`, undefined, { nonce: 'n-1' });
      expect(result.verified).toBe(true);
      expect(didService.resolveDID).toHaveBeenCalledTimes(1);
      expect(didService.resolveDID).toHaveBeenCalledWith(signerDID);
    });

    it('falls back to the DID registry for a non-self-contained cnf.kid', async () => {
      const holderKey = await jose.generateKeyPair('ES256', { extractable: true });
      const holderPublicJwk = await jose.exportJWK(holderKey.publicKey);
      const holderDID = 'did:rcw:holder-1';
      const kid = `${holderDID}#key-1`;
      const { sdJwt, issuerDoc } = await issueSdJwt({ name: 'Alice', cnf: { kid } });
      didService.resolveDID.mockImplementation(async (did: string) =>
        did === holderDID ? baseDidDoc([{ id: kid, publicKeyJwk: holderPublicJwk }]) : issuerDoc,
      );
      const kbJwt = await new jose.CompactSign(new TextEncoder().encode(JSON.stringify({ nonce: 'n-1' })))
        .setProtectedHeader({ alg: 'ES256' })
        .sign(holderKey.privateKey);

      const result = await service.verifySdJwt(`${sdJwt}${kbJwt}`, undefined, { nonce: 'n-1' });
      expect(result.verified).toBe(true);
    });

    it('rejects when cnf.kid is unresolvable by either path', async () => {
      const { sdJwt, issuerDoc } = await issueSdJwt({ name: 'Alice', cnf: { kid: 'did:example:unknown#key-1' } });
      didService.resolveDID.mockImplementation(async (did: string) => {
        if (did === signerDID) return issuerDoc;
        throw new NotFoundException('not found');
      });
      const kbJwt = await new jose.CompactSign(new TextEncoder().encode(JSON.stringify({ nonce: 'n-1' })))
        .setProtectedHeader({ alg: 'ES256' })
        .sign((await jose.generateKeyPair('ES256')).privateKey);

      const result = await service.verifySdJwt(`${sdJwt}${kbJwt}`, undefined, { nonce: 'n-1' });
      expect(result.verified).toBe(false);
      expect(result.error).toContain('cnf.kid');
    });

    it('rejects a malformed KB-JWT', async () => {
      const holderKey = await jose.generateKeyPair('ES256', { extractable: true });
      const holderPublicJwk = await jose.exportJWK(holderKey.publicKey);
      const { sdJwt } = await issueSdJwt({ name: 'Alice', cnf: { jwk: holderPublicJwk } });

      const result = await service.verifySdJwt(`${sdJwt}not-a-valid-kb-jwt`, undefined, { nonce: 'n-1' });
      expect(result.verified).toBe(false);
      expect(result.error).toContain('KB-JWT invalid');
    });
  });

  describe('getJwks', () => {
    it('returns only JWT-signing keys (#jwt-key-1) with a publicKeyJwk, excluding mdoc/LD keys', async () => {
      const jwtVm = { id: `${signerDID}#jwt-key-1`, publicKeyJwk: { kty: 'EC', crv: 'P-256', x: 'x1', y: 'y1' } };
      const mdocVm = {
        id: `${signerDID}#key-0`,
        type: 'JsonWebKey2020',
        publicKeyJwk: { kty: 'EC', crv: 'P-256', x: 'x2', y: 'y2' },
      };
      const ldVm = { id: `${signerDID}#key-0-ld`, type: 'Ed25519VerificationKey2020', publicKeyMultibase: 'z6M...' };
      prisma.identity.findMany.mockResolvedValue([
        { id: signerDID, didDoc: JSON.stringify(baseDidDoc([jwtVm, mdocVm, ldVm])) },
      ]);

      const result = await service.getJwks();
      expect(result.keys).toEqual([{ ...jwtVm.publicKeyJwk, kid: jwtVm.id }]);
    });

    it('falls back to an unfiltered scan when the string_contains filter is unsupported', async () => {
      prisma.identity.findMany.mockRejectedValueOnce(new Error('string_contains unsupported'));
      prisma.identity.findMany.mockResolvedValueOnce([]);
      const warnSpy = jest.spyOn(Logger, 'warn').mockImplementation(() => undefined);

      const result = await service.getJwks();

      expect(result.keys).toEqual([]);
      expect(prisma.identity.findMany).toHaveBeenCalledTimes(2);
      expect(prisma.identity.findMany.mock.calls[1]).toEqual([]);
      expect(warnSpy).toHaveBeenCalled();
    });

    it('skips an identity with a malformed didDoc without failing the others', async () => {
      const goodVm = { id: `${signerDID}#jwt-key-1`, publicKeyJwk: { kty: 'EC' } };
      prisma.identity.findMany.mockResolvedValue([
        { id: 'did:rcw:broken', didDoc: 'not-json' },
        { id: signerDID, didDoc: JSON.stringify(baseDidDoc([goodVm])) },
      ]);

      const result = await service.getJwks();
      expect(result.keys).toEqual([{ ...goodVm.publicKeyJwk, kid: goodVm.id }]);
    });

    it('keeps rotated JWT keys (#jwt-key-N) in the JWKS', async () => {
      const rotated = { id: `${signerDID}#jwt-key-2`, publicKeyJwk: { kty: 'EC', crv: 'P-256', x: 'x3', y: 'y3' } };
      prisma.identity.findMany.mockResolvedValue([{ id: signerDID, didDoc: JSON.stringify(baseDidDoc([rotated])) }]);
      expect((await service.getJwks()).keys).toEqual([{ ...rotated.publicKeyJwk, kid: rotated.id }]);
    });

    it('defaults kid to the verification method id when publicKeyJwk.kid is absent', async () => {
      const vm = { id: `${signerDID}#jwt-key-1`, publicKeyJwk: { kty: 'EC' } };
      prisma.identity.findMany.mockResolvedValue([{ id: signerDID, didDoc: JSON.stringify(baseDidDoc([vm])) }]);

      const result = await service.getJwks();
      expect(result.keys[0].kid).toBe(vm.id);
    });
  });
});