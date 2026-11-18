import { DidService } from './did.service';
import { PrismaService } from '../utils/prisma.service';
import { createPrismaServiceOrMock } from '../utils/test-infra.util';
import { createTestSigning } from '../keys/testing/test-signing.util';
import { GenerateDidDTO, VerificationKeyType } from './dtos/GenerateDidRequest.dto';

describe('DidService', () => {
  let service: DidService;
  let doc: GenerateDidDTO;
  let prisma: PrismaService;
  let t: ReturnType<typeof createTestSigning>;

  const defaultDoc: GenerateDidDTO = {
    alsoKnownAs: ['C4GT', 'https://www.codeforgovtech.in/'],
    services: [
      {
        id: 'C4GT',
        type: 'IdentityHub',
        serviceEndpoint: {
          '@context': 'schema.c4gt.acknowledgment',
          '@type': 'UserServiceEndpoint',
          instance: ['https://www.codeforgovtech.in'],
        },
      },
    ],
    method: 'C4GT',
  };

  beforeEach(async () => {
    doc = JSON.parse(JSON.stringify(defaultDoc));
    prisma = await createPrismaServiceOrMock();
    t = createTestSigning(prisma);
    service = new DidService(prisma, t.signing, t.registry);
    service.signingAlgorithm = 'Ed25519Signature2020';
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  it('should generate a DID with a custom method', async () => {
    const result = await service.generateDID(doc);
    expect(result).toBeDefined();
    expect(result.verificationMethod).toBeDefined();
    expect(result.verificationMethod[0].publicKeyMultibase).toBeDefined();
    expect(result.id.split(':')[1]).toEqual('C4GT');

    const stored = await prisma.identity.findUnique({ where: { id: result.id } });
    expect(stored).toBeDefined();
    expect(JSON.parse(stored.didDoc as string).id).toEqual(result.id);
  });

  it('should generate a DID with a default method', async () => {
    delete doc.method;
    const result = await service.generateDID(doc);
    expect(result).toBeDefined();
    expect(result.verificationMethod).toBeDefined();
    expect(result.verificationMethod[0].publicKeyMultibase).toBeDefined();
    expect(result.id.split(':')[1]).toEqual('rcw');
  });

  it('should generate a web DID with a given base url and verification key', async () => {
    doc.method = 'web';
    doc.webDidBaseUrl = 'https://registry.dev.example.com/identity';
    doc.keyPairType = VerificationKeyType.Ed25519VerificationKey2018;
    const result = await service.generateDID(doc);
    expect(result).toBeDefined();
    expect(result.id).toMatch(/did:web:registry.dev.example.com:*/i);
    expect(result.verificationMethod).toBeDefined();
    expect(result.verificationMethod[0].type).toStrictEqual(VerificationKeyType.Ed25519VerificationKey2018.toString());
  });

  it('rejects new RsaVerificationKey2018 keys (not supported by key providers)', async () => {
    doc.method = 'abc';
    doc.keyPairType = VerificationKeyType.RsaVerificationKey2018;
    await expect(service.generateDID(doc)).rejects.toThrow('RsaVerificationKey2018');
  });

  it('should generate a DID with a given ID', async () => {
    doc.method = 'web';
    doc.id = `did:web:abc.com:given:${Date.now()}`;
    const result = await service.generateDID(doc);
    expect(result).toBeDefined();
    expect(result.id).toMatch(doc.id);
  });

  it('should generate a DID with an EC/JsonWebKey2020 verification key (mdoc)', async () => {
    doc.method = 'abc';
    doc.keyPairType = VerificationKeyType.JsonWebKey2020;
    const result = await service.generateDID(doc);
    expect(result).toBeDefined();
    expect(result.verificationMethod).toBeDefined();
    expect(result.verificationMethod[0].type).toStrictEqual('JsonWebKey2020');
    expect(result.verificationMethod[0].publicKeyJwk).toBeDefined();
  });

  it('throws InternalServerErrorException when persisting the DID to the database fails', async () => {
    jest.spyOn(prisma.identity, 'create').mockRejectedValueOnce(new Error('db down'));
    await expect(service.generateDID(doc)).rejects.toThrow('Error writing DID to database');
  });

  it('fails without storing a DID when the key provider cannot create the key', async () => {
    jest.spyOn(t.provider, 'createKey').mockRejectedValueOnce(new Error('key provider down'));
    doc.id = `did:c4gt:provider-down-${Date.now()}`;
    await expect(service.generateDID(doc)).rejects.toThrow('key provider down');
    expect(await prisma.identity.findUnique({ where: { id: doc.id } })).toBeNull();
  });

  it('removes the key record when the DID cannot be stored', async () => {
    jest.spyOn(prisma.identity, 'create').mockRejectedValueOnce(new Error('db down'));
    doc.id = `did:c4gt:db-down-${Date.now()}`;
    await expect(service.generateDID(doc)).rejects.toThrow('Error writing DID to database');
    expect(await t.registry.findById(`${doc.id}#key-0`)).toBeNull();
  });

  it('creates the key in the provider, registers it and publishes only the public key', async () => {
    const result = await service.generateDID(doc);
    const keyId = `${result.id}#key-0`;
    expect(result.verificationMethod[0].id).toBe(keyId);
    expect(JSON.stringify(result)).not.toMatch(/privateKey/);
    expect(await t.registry.findById(keyId)).toMatchObject({ did: result.id, algorithm: 'Ed25519', status: 'ACTIVE' });
  });

  it('registers P-256 keys for JsonWebKey2020', async () => {
    doc.keyPairType = VerificationKeyType.JsonWebKey2020;
    const result = await service.generateDID(doc);
    expect(result.verificationMethod[0].publicKeyJwk.crv).toBe('P-256');
    expect((await t.registry.findById(`${result.id}#key-0`)).algorithm).toBe('P-256');
  });

  it('creates keyless DIDs when withKey is false', async () => {
    const result = await service.generateDID({ ...doc, withKey: false });
    expect(result.verificationMethod).toBeUndefined();
    expect(await t.registry.listByDid(result.id)).toEqual([]);
  });

  it('records the caller authority on the key (token claim wins over the request body)', async () => {
    const fromToken = await service.generateDID({ ...doc, authority: 'agri' }, { authority: 'moe' });
    expect((await t.registry.findById(`${fromToken.id}#key-0`)).authority).toBe('moe');
    const fromBody = await service.generateDID({ ...doc, authority: 'agri' });
    expect((await t.registry.findById(`${fromBody.id}#key-0`)).authority).toBe('agri');
  });

  it('resolve a DID', async () => {
    const generated = await service.generateDID(doc);

    const resolvedDid = await service.resolveDID(generated.id);
    expect(resolvedDid).toBeDefined();
    expect(resolvedDid.id).toEqual(generated.id);
    expect(resolvedDid).toEqual(generated);

    await expect(service.resolveDID('did:abc:efg:hij')).rejects.toThrow('DID: did:abc:efg:hij not found');
  });

  it('throws InternalServerErrorException when the Prisma read fails during resolve', async () => {
    jest.spyOn(prisma.identity, 'findUnique').mockRejectedValueOnce(new Error('db down'));
    await expect(service.resolveDID('did:x')).rejects.toThrow('Error fetching DID: did:x from db');
  });

  it('resolve a web DID for given id', async () => {
    service.webDidPrefix = 'did:web:abc.com:resolveweb:';
    doc.method = 'web';
    const generated = await service.generateDID(doc);

    const resolvedDid = await service.resolveWebDID(generated.id.split(service.webDidPrefix)[1]);
    expect(resolvedDid).toBeDefined();
    expect(resolvedDid.id).toEqual(generated.id);
    expect(resolvedDid).toEqual(generated);
  });

  it('generate web did id test', () => {
    service.webDidPrefix = 'did:web:example.com:identity:';
    const didId = service.generateDidUri('web');
    expect(didId).toBeDefined();
    expect(didId).toContain('did:web:example.com:identity');
  });

  it('get web did id for id test', () => {
    service.webDidPrefix = 'did:web:example.com:identity:';
    const didId = service.getWebDidIdForId('abc');
    expect(didId).toBeDefined();
    expect(didId).toEqual('did:web:example.com:identity:abc');
  });

  it('should generate a DID with a web method', async () => {
    service.webDidPrefix = 'did:web:example.com:identity:';
    const result = await service.generateDID({
      alsoKnownAs: [],
      services: [],
      method: 'web',
    });
    expect(result).toBeDefined();
    expect(result.verificationMethod).toBeDefined();
    expect(result.id.split(':')[1]).toEqual('web');
    expect(result.id).toContain('did:web:example.com:identity');
  });

  describe('rotateKey', () => {
    it('retires the old key, adds a new one, and signing moves to the new key', async () => {
      const created = await service.generateDID(doc);
      const rotated = await service.rotateKey(created.id, 'Ed25519', false, {});
      expect(rotated.verificationMethod.map((v) => v.id)).toEqual([`${created.id}#key-0`, `${created.id}#key-1`]);
      expect(rotated.assertionMethod).toEqual([`${created.id}#key-0`, `${created.id}#key-1`]);
      expect((await t.registry.findById(`${created.id}#key-0`)).status).toBe('RETIRED');
      expect((await t.registry.findActive(created.id, 'Ed25519')).id).toBe(`${created.id}#key-1`);
      await expect(t.signing.sign(`${created.id}#key-0`, Buffer.from('x'), 'ldp_vc')).rejects.toThrow('RETIRED');
      expect(await service.resolveDID(created.id)).toEqual(rotated);
    });

    it('revokes: removes the old key from the DID document', async () => {
      const created = await service.generateDID(doc);
      const rotated = await service.rotateKey(created.id, 'Ed25519', true, {});
      expect(rotated.verificationMethod.map((v) => v.id)).toEqual([`${created.id}#key-1`]);
      expect(rotated.authentication).toEqual([`${created.id}#key-1`]);
      expect((await t.registry.findById(`${created.id}#key-0`)).status).toBe('REVOKED');
    });

    it('continues the #jwt-key-N series and keeps the JWK metadata', async () => {
      const created = await service.generateDID({ ...doc, keyPairType: VerificationKeyType.JsonWebKey2020 });
      const stored = await service.resolveDID(created.id);
      stored.verificationMethod[0].id = `${created.id}#jwt-key-1`;
      stored.verificationMethod[0].publicKeyJwk.alg = 'ES256';
      stored.assertionMethod = [`${created.id}#jwt-key-1`];
      jest.spyOn(prisma.identity, 'findUnique').mockResolvedValueOnce({ id: created.id, didDoc: JSON.stringify(stored) } as any);
      jest.spyOn(t.registry, 'findActive').mockResolvedValueOnce({
        ...(await t.registry.findById(`${created.id}#key-0`)), id: `${created.id}#jwt-key-1`,
      } as any);
      jest.spyOn(t.signing, 'assertCanSign').mockResolvedValueOnce(undefined as any);
      jest.spyOn(t.registry, 'setStatus').mockResolvedValueOnce(undefined as any);
      const rotated = await service.rotateKey(created.id, 'P-256', false, {});
      const added = rotated.verificationMethod[rotated.verificationMethod.length - 1];
      expect(added.id).toBe(`${created.id}#jwt-key-2`);
      expect(added.publicKeyJwk).toMatchObject({ alg: 'ES256', use: 'sig', kid: `${created.id}#jwt-key-2` });
    });

    it('refuses rotation by another authority', async () => {
      const created = await service.generateDID(doc, { authority: 'moe' });
      await expect(service.rotateKey(created.id, 'Ed25519', false, { authority: 'agri' })).rejects.toThrow('not authorised');
      expect((await t.registry.findById(`${created.id}#key-0`)).status).toBe('ACTIVE');
    });

    it('404s when there is no active key of that algorithm', async () => {
      const created = await service.generateDID(doc);
      await expect(service.rotateKey(created.id, 'P-256', false, {})).rejects.toThrow('no active P-256 key');
    });
  });

  it('throw exception when web did base url is not set', () => {
    service.webDidPrefix = undefined;
    expect(() => service.getWebDidIdForId('abc'))
      .toThrow('Web did base url not found');
  });
});
