import { BadRequestException, NotFoundException, InternalServerErrorException } from '@nestjs/common';
import VcService from './vc.service';
import { PrismaService } from '../utils/prisma.service';
import { DidService } from '../did/did.service';
import { VerificationKeyType } from '../did/dtos/GenerateDidRequest.dto';
import { createPrismaServiceOrMock } from '../utils/test-infra.util';
import { createTestSigning } from '../keys/testing/test-signing.util';

describe('VcService', () => {
  let service: VcService;
  let prisma: PrismaService;
  let t: ReturnType<typeof createTestSigning>;
  let didService: DidService;
  let didDoc: any;
  let ed2018Doc: any;
  let p256Doc: any;

  const signPayload = {
    '@context': {
      name: 'http://schema.org/name',
    },
    name: 'Hello!',
  };

  beforeAll(async () => {
    prisma = await createPrismaServiceOrMock();
    t = createTestSigning(prisma);
    didService = new DidService(prisma, t.signing, t.registry);
    didService.signingAlgorithm = 'Ed25519Signature2020';

    didDoc = await didService.generateDID({ alsoKnownAs: [], services: [], method: 'test' });
    ed2018Doc = await didService.generateDID({
      alsoKnownAs: [],
      services: [],
      method: 'test',
      keyPairType: VerificationKeyType.Ed25519VerificationKey2018,
    });
    p256Doc = await didService.generateDID({
      alsoKnownAs: [],
      services: [],
      method: 'test',
      keyPairType: VerificationKeyType.JsonWebKey2020,
    });
  });

  beforeEach(async () => {
    service = new VcService(prisma, didService, t.signing, t.registry);
    await service.init();
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  it('should sign a payload', async () => {
    const signedPayload = await service.sign(didDoc.id, signPayload);
    expect(signedPayload).toBeDefined();
    expect(signedPayload.proof).toBeDefined();
  });

  it('should verify a signed payload successfully', async () => {
    const signedPayload = await service.sign(didDoc.id, signPayload);
    const verified = await service.verify(didDoc.id, signedPayload);
    expect(verified).toBeDefined();
    expect(verified).toBeTruthy();
    expect(verified).toEqual(true);
  });

  it('signs through the KeyProvider and the proof names the signing key', async () => {
    const signSpy = jest.spyOn(t.provider, 'sign');
    const signed: any = await service.sign(didDoc.id, signPayload);
    expect(signSpy).toHaveBeenCalledTimes(1);
    expect(signed.proof.verificationMethod).toBe(`${didDoc.id}#key-0`);
    expect(await service.verify(didDoc.id, signed)).toBe(true);
  });

  it('denies callers from another authority', async () => {
    const owned = await didService.generateDID({ alsoKnownAs: [], services: [], method: 'test' }, { authority: 'moe' });
    await expect(service.sign(owned.id, signPayload, { authority: 'agri' })).rejects.toThrow('not authorised');
  });

  it('verifies with the key named in proof.verificationMethod, not just the first key', async () => {
    const signed: any = await service.sign(didDoc.id, signPayload);
    const doc = await didService.resolveDID(didDoc.id);
    doc.verificationMethod.unshift({ ...doc.verificationMethod[0], id: `${didDoc.id}#decoy`, publicKeyMultibase: 'z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK' });
    jest.spyOn(didService, 'resolveDID').mockResolvedValueOnce(doc);
    expect(await service.verify(didDoc.id, signed)).toBe(true);
  });

  it('should fail to verify a tampered payload', async () => {
    const signedPayload = await service.sign(didDoc.id, signPayload);
    signedPayload.name = 'Hello changed';
    const verified = await service.verify(didDoc.id, signedPayload);
    expect(verified).toBeDefined();
    expect(verified).toBeFalsy();
    expect(verified).toEqual(false);
  });

  describe('additional signature suites', () => {
    it('refuses JSON-LD signing for a DID without an Ed25519 key', async () => {
      await expect(service.sign(p256Doc.id, signPayload)).rejects.toThrow(BadRequestException);
    });

    it('signs and verifies with Ed25519Signature2018 (Ed25519VerificationKey2018)', async () => {
      const signed = await service.sign(ed2018Doc.id, signPayload);
      expect(signed.proof).toBeDefined();
      const verified = await service.verify(ed2018Doc.id, signed);
      expect(verified).toEqual(true);
    });
  });

  describe('getSuite', () => {
    it('throws NotFoundException for an unsupported signature type', async () => {
      await expect(
        service.getSuite({ type: 'Ed25519VerificationKey2020' }, 'NoSuchSignature2099'),
      ).rejects.toThrow(NotFoundException);
    });

    it('throws NotFoundException when the verification method type is not supported by the signature type', async () => {
      await expect(
        service.getSuite({ type: 'RsaVerificationKey2018' }, 'Ed25519Signature2020'),
      ).rejects.toThrow(NotFoundException);
    });
  });

  describe('error paths', () => {
    it('throws InternalServerErrorException when the Prisma read fails during sign', async () => {
      jest.spyOn(prisma.identity, 'findUnique').mockRejectedValueOnce(new Error('db down'));
      await expect(service.sign(didDoc.id, signPayload)).rejects.toThrow(InternalServerErrorException);
    });

    it('throws NotFoundException when the signer DID does not exist', async () => {
      await expect(service.sign('did:does-not-exist', signPayload)).rejects.toThrow(NotFoundException);
    });

    it('throws InternalServerErrorException when resolving the signer DID fails during verify', async () => {
      jest.spyOn(didService, 'resolveDID').mockRejectedValueOnce(new Error('resolve failed'));
      await expect(service.verify(didDoc.id, {})).rejects.toThrow(InternalServerErrorException);
    });
  });
});