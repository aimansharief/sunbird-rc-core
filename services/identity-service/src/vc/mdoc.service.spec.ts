import * as crypto from 'crypto';
import { NotFoundException, InternalServerErrorException } from '@nestjs/common';
import { MdocService } from './mdoc.service';
import { PrismaService } from '../utils/prisma.service';
import { createInMemoryPrismaMock } from '../utils/test-infra.util';
import { createTestSigning } from '../keys/testing/test-signing.util';

describe('MdocService', () => {
  const signerDID = 'did:rcw:signer-1';
  const vmId = `${signerDID}#key-0`;
  const docType = 'org.iso.18013.5.1.mDL';

  let prisma: { identity: { findUnique: jest.Mock } };
  let t: ReturnType<typeof createTestSigning>;
  let service: MdocService;

  beforeEach(() => {
    prisma = { identity: { findUnique: jest.fn() } };
    t = createTestSigning(createInMemoryPrismaMock());
    service = new MdocService(prisma as unknown as PrismaService, t.signing, t.registry);
  });

  // The issuer's P-256 key lives in the (test) key provider; the DID document carries only its public half.
  async function primeSigner() {
    const publicKeyJwk = await t.signing.createKey({ keyId: vmId, did: signerDID, algorithm: 'P-256' });
    prisma.identity.findUnique.mockResolvedValue({
      id: signerDID,
      didDoc: JSON.stringify({
        id: signerDID,
        verificationMethod: [{ id: vmId, type: 'JsonWebKey2020', controller: signerDID, publicKeyJwk }],
      }),
    });
  }

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('signMdoc', () => {
    it('signs an mdoc for a DID with a JsonWebKey2020 verification method', async () => {
      await primeSigner();
      const mdoc = await service.signMdoc(signerDID, docType, {
        'org.iso.18013.5.1': { given_name: 'Alice', family_name: 'Doe' },
      });
      expect(typeof mdoc).toBe('string');
      expect(mdoc.length).toBeGreaterThan(0);
    });

    it('accepts an optional deviceKeyJwk', async () => {
      await primeSigner();
      const { publicKey: deviceKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
      const deviceKeyJwk = deviceKey.export({ format: 'jwk' });
      const mdoc = await service.signMdoc(
        signerDID,
        docType,
        { 'org.iso.18013.5.1': { given_name: 'Alice' } },
        deviceKeyJwk as any,
      );
      expect(typeof mdoc).toBe('string');
      expect(mdoc.length).toBeGreaterThan(0);
    });

    it('throws NotFoundException when the signer DID does not exist', async () => {
      prisma.identity.findUnique.mockResolvedValue(null);
      await expect(service.signMdoc(signerDID, docType, {})).rejects.toThrow(NotFoundException);
    });

    it('throws InternalServerErrorException when the Prisma read fails', async () => {
      prisma.identity.findUnique.mockRejectedValue(new Error('db down'));
      await expect(service.signMdoc(signerDID, docType, {})).rejects.toThrow(InternalServerErrorException);
    });

    it('throws NotFoundException when the DID has no JsonWebKey2020 verification method', async () => {
      prisma.identity.findUnique.mockResolvedValue({
        id: signerDID,
        didDoc: JSON.stringify({
          id: signerDID,
          verificationMethod: [{ id: `${signerDID}#key-0`, type: 'Ed25519VerificationKey2020' }],
        }),
      });
      await expect(service.signMdoc(signerDID, docType, {})).rejects.toThrow(/JsonWebKey2020/);
    });

    it('throws NotFoundException when the P-256 key is not in the key registry (unmigrated DID)', async () => {
      prisma.identity.findUnique.mockResolvedValue({
        id: signerDID,
        didDoc: JSON.stringify({
          id: signerDID,
          verificationMethod: [{ id: vmId, type: 'JsonWebKey2020', publicKeyJwk: { kty: 'EC', crv: 'P-256' } }],
        }),
      });
      await expect(service.signMdoc(signerDID, docType, {})).rejects.toThrow(/JsonWebKey2020/);
    });

    it('signs the certificate and the COSE issuer signature with the provider-held key', async () => {
      await primeSigner();
      const purposes: string[] = [];
      const original = t.signing.sign.bind(t.signing);
      jest.spyOn(t.signing, 'sign').mockImplementation(async (keyId, data, purpose, ctx) => {
        purposes.push(purpose);
        return original(keyId, data, purpose, ctx);
      });
      const mdoc = await service.signMdoc(signerDID, docType, { 'org.iso.18013.5.1': { family_name: 'Doe' } });
      expect(purposes).toEqual(['x509', 'mdoc']);
      expect((await service.verifyMdoc(mdoc)).verified).toBe(true);
    });

    it('refuses callers from another authority', async () => {
      const publicKeyJwk = await t.signing.createKey({ keyId: vmId, did: signerDID, algorithm: 'P-256', authority: 'moe' });
      prisma.identity.findUnique.mockResolvedValue({
        id: signerDID,
        didDoc: JSON.stringify({ id: signerDID, verificationMethod: [{ id: vmId, type: 'JsonWebKey2020', publicKeyJwk }] }),
      });
      await expect(service.signMdoc(signerDID, docType, { ns: { a: 1 } }, undefined, { authority: 'agri' }))
        .rejects.toThrow('not authorised');
    });
  });

  describe('verifyMdoc', () => {
    it('verifies a genuine signed mdoc round-trip', async () => {
      await primeSigner();
      const namespaces = { 'org.iso.18013.5.1': { given_name: 'Alice', family_name: 'Doe' } };
      const mdoc = await service.signMdoc(signerDID, docType, namespaces);

      const result = await service.verifyMdoc(mdoc);
      expect(result.verified).toBe(true);
      expect(result.docType).toBe(docType);
      expect(result.claims?.['org.iso.18013.5.1']).toMatchObject({ given_name: 'Alice', family_name: 'Doe' });
    });

    it('returns verified:false for garbage input', async () => {
      const result = await service.verifyMdoc('not-a-valid-mdoc');
      expect(result.verified).toBe(false);
      expect(result.error).toBeDefined();
    });

    it('detects a tampered signature', async () => {
      await primeSigner();
      const mdoc = await service.signMdoc(signerDID, docType, {
        'org.iso.18013.5.1': { given_name: 'Alice' },
      });
      const bytes = Buffer.from(mdoc, 'base64url');
      const flipIndex = Math.floor(bytes.length / 2);
      bytes[flipIndex] = bytes[flipIndex] ^ 0xff;
      const tampered = bytes.toString('base64url');

      const result = await service.verifyMdoc(tampered);
      expect(result.verified).toBe(false);
    });
  });
});