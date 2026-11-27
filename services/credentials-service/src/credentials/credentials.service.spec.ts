import { Test, TestingModule } from '@nestjs/testing';
import { CredentialsService } from './credentials.service';
import Ajv2019 from 'ajv/dist/2019';
import { UnsignedVCValidator, VCValidator } from './types/validators';
import { SchemaUtilsSerivce } from './utils/schema.utils.service';
import { IdentityUtilsService } from './utils/identity.utils.service';
import { RenderingUtilsService } from './utils/rendering.utils.service';
import { CredentialFormatService } from './utils/credential-format.service';
import { StatusListService } from './utils/status-list.service';
import { RevocationListImpl } from '../revocation-list/revocation-list.impl';
import { PrismaClient } from '@prisma/client';
import {
  generateCredentialRequestPayload,
  generateV2CredentialRequestPayload,
  generateCredentialSchemaTestBody,
  getCredentialByIdSchema,
  issueCredentialReturnTypeSchema,
  generateRenderingTemplatePayload,
} from './credentials.fixtures';
import { RENDER_OUTPUT } from './enums/renderOutput.enum';
import { TerminusModule } from '@nestjs/terminus';
import { HttpModule, HttpService } from '@nestjs/axios';
import { execSync } from 'child_process';
import { NotFoundException } from '@nestjs/common';
import { DOCUMENTS } from './documents';
import * as crypto from 'crypto';

const hasWkhtmltopdf = (() => {
  try {
    execSync('which wkhtmltopdf', { stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
})();

// setup ajv
const ajv = new Ajv2019({ strictTuples: false });
ajv.addFormat('date-time', function isValidDateTime(dateTimeString) {
    // Regular expression for ISO 8601 date-time format
    const iso8601Regex = /^(\d{4}-[01]\d-[0-3]\d[T\s](?:[0-2]\d:[0-5]\d:[0-5]\d(?:\.\d+)?|23:59:60)(?:Z|[+-][0-2]\d:[0-5]\d)?)$/;

    // Check if the string matches the ISO 8601 format
    if (!iso8601Regex.test(dateTimeString)) {
      return false;
    }

    // Check if the string can be parsed into a valid date
    const date = new Date(dateTimeString);
    return !isNaN(date.getTime());
  }
);

describe('CredentialsService', () => {
  let service: CredentialsService;
  let httpSerivce: HttpService;
  let identityUtilsService: IdentityUtilsService;

  const validate = ajv.compile(issueCredentialReturnTypeSchema);
  const getCredReqValidate = ajv.compile(getCredentialByIdSchema);

  let issuerDID;
  let subjectDID;
  let credentialSchemaID;
  let sampleCredReqPayload;

  beforeAll(async () => {
    const module: TestingModule = await Test.createTestingModule({
      imports: [TerminusModule, HttpModule],
      providers: [
        CredentialsService,
        PrismaClient,
        RenderingUtilsService,
        SchemaUtilsSerivce,
        IdentityUtilsService,
        CredentialFormatService,
        StatusListService,
        RevocationListImpl,
      ],
    }).compile();

    service = module.get<CredentialsService>(CredentialsService);
    httpSerivce = module.get<HttpService>(HttpService);
    identityUtilsService =
      module.get<IdentityUtilsService>(IdentityUtilsService);

    issuerDID = await identityUtilsService.generateDID([
      'VerifiableCredentialTESTINGIssuer',
    ]);
    issuerDID = issuerDID[0].id;

    subjectDID = await identityUtilsService.generateDID([
      'VerifiableCredentialTESTINGIssuer',
    ]);
    subjectDID = subjectDID[0].id;

    const schemaPayload = generateCredentialSchemaTestBody();
    schemaPayload.schema.author = issuerDID;
    const schema = await httpSerivce.axiosRef.post(
      `${process.env.SCHEMA_BASE_URL}/credential-schema`,
      schemaPayload
    );
    credentialSchemaID = schema.data.schema.id;
    sampleCredReqPayload = generateCredentialRequestPayload(
      issuerDID,
      subjectDID,
      credentialSchemaID,
      schema.data.schema.version
    );
  });

  beforeEach(async () => {
    jest.restoreAllMocks();
  })

  it('service should be defined', () => {
    expect(service).toBeDefined();
  });

  it('should issue a credential', async () => {
    const newCred = await service.issueCredential(sampleCredReqPayload);
    VCValidator.parse(newCred.credential);
    expect(validate(newCred)).toBe(true);
  });

  it('should issue a VC 2.0 credential (validFrom/validUntil, v2 context)', async () => {
    const v2Payload = generateV2CredentialRequestPayload(
      issuerDID,
      subjectDID,
      credentialSchemaID,
      sampleCredReqPayload.credentialSchemaVersion
    );
    const newCred = await service.issueCredential(v2Payload);
    UnsignedVCValidator.parse(newCred.credential);
    expect(newCred.credential['@context']).toContain(
      'https://www.w3.org/ns/credentials/v2'
    );
    expect(newCred.credential['validFrom']).toBeDefined();
    expect(newCred.credential['issuanceDate']).toBeUndefined();
  });

  it('should verify both a 1.1 and a 2.0 credential in the same run', async () => {
    const v1Cred = await service.issueCredential(sampleCredReqPayload);
    const v2Payload = generateV2CredentialRequestPayload(
      issuerDID,
      subjectDID,
      credentialSchemaID,
      sampleCredReqPayload.credentialSchemaVersion
    );
    const v2Cred = await service.issueCredential(v2Payload);

    const v1Result: any = await service.verifyCredential(v1Cred.credential as any);
    const v2Result: any = await service.verifyCredential(v2Cred.credential as any);

    expect(v1Result.checks?.[0]?.proof).toBe('OK');
    expect(v2Result.checks?.[0]?.proof).toBe('OK');
  });

  describe("getCredentialById", () => {
    let newCred: any;
    beforeAll(async () => {
      newCred = await service.issueCredential(sampleCredReqPayload);
    })

    it('should get a credential in JSON', async () => {
      const cred = await service.getCredentialById(newCred.credential?.id);
      UnsignedVCValidator.parse(cred);
      expect(getCredReqValidate(cred)).toBe(true);
    });

    it('should get a credential in QR', async () => {
      const dataURL = await service.getCredentialById(newCred.credential?.id, null, null, RENDER_OUTPUT.QR);
      expect(dataURL).toBeDefined(); // Assert that the dataURL is defined
      expect(dataURL).toContain('data:image/png;base64,');
    });

    it('should get a credential in HTML', async () => {
      const templatePayload = generateRenderingTemplatePayload(newCred.credentialSchemaId, "1.0.0")
      const template = await httpSerivce.axiosRef.post(`${process.env.SCHEMA_BASE_URL}/template`, templatePayload);
      const cred = await service.getCredentialById(newCred.credential?.id, template.data.template.templateId, null, RENDER_OUTPUT.HTML);
      expect(cred).toContain('</html>')
      expect(cred).toContain('IIIT Sonepat, NIT Kurukshetra')
      expect(cred).toBeDefined()
    });

    const itPdf = hasWkhtmltopdf ? it : it.skip;
    itPdf('should get a credential in PDF', async () => {
      const templatePayload = generateRenderingTemplatePayload(newCred.credentialSchemaId, "1.0.0")
      const template = await httpSerivce.axiosRef.post(`${process.env.SCHEMA_BASE_URL}/template`, templatePayload);
      const cred = await service.getCredentialById(newCred.credential?.id, template.data.template.templateId, null, RENDER_OUTPUT.PDF);
      expect(cred).toBeDefined()
    });

    it('should get a credential in STRING', async () => {
      const cred = await service.getCredentialById(newCred.credential?.id, null, null, RENDER_OUTPUT.STRING);
      expect(cred).toBeDefined()
    });

    it('should throw because no credential is present to be searched by ID', async () => {
      await expect(service.getCredentialById('did:ulp:123')).rejects.toThrow();
    });
  })

  it('should throw because credential not present to be verified', async () => {
    await expect(service.verifyCredentialById('did:ulp:123')).rejects.toThrow();
  });

  it('should verify an issued credential (expired)', async () => {
    const expiredPayload = JSON.parse(JSON.stringify(sampleCredReqPayload));
    expiredPayload.credential.issuanceDate = '2023-02-06T11:56:27.259Z';
    expiredPayload.credential.expirationDate = '2023-02-08T11:56:27.259Z';

    const newCred = await service.issueCredential(expiredPayload);
    const verifyRes: any = await service.verifyCredentialById((newCred.credential as any)['id']);
    expect(verifyRes.status).toEqual("ISSUED");
    expect(verifyRes.checks[0].expired).toEqual("NOK");
    expect(verifyRes.checks[0].proof).toEqual("NOK");
    expect(verifyRes.checks[0].revoked).toEqual("OK");
  });

  it('should return an empty revocation list', async () => {
    const res = await service.getRevocationList('did:nonexistent:empty-test');
    expect(res).toEqual([]);
  });

  it('should say revoked', async () => {
    const newCred = await service.issueCredential(sampleCredReqPayload);
    expect(
      await service.deleteCredential((newCred.credential as any).id)
    ).toHaveProperty('status', 'REVOKED');
  });

  it('should throw while delete because credential not present', async () => {
    await expect(service.deleteCredential('did:ulp:123')).rejects.toThrow();
  });

  it('should throw', async () => {
    await expect(
      service.getCredentialsBySubjectOrIssuer({
        subject: { id: 'did:ulp:123' },
      })
    ).rejects.toThrow();
  });

  it('should return array of creds based on issuer', async () => {
      const newCred = await service.issueCredential(sampleCredReqPayload);
      expect(
        await service.getCredentialsBySubjectOrIssuer({
          issuer: {
            id: (newCred.credential as any)?.issuer,
          },
        })
      ).toBeInstanceOf(Array);
  });


  it('should return array of creds based on issuer', async () => {
    const newCred = await service.issueCredential(sampleCredReqPayload);
    expect(
      await service.getCredentials(['tag1'])
    ).toBeInstanceOf(Array);
      const res = await service.getCredentials(['tag1'], 2, 1000)
      expect(res.length).toEqual(0)
  });



  it('should give revockedList by issuerId', async () => {
    const newCred = await service.issueCredential(sampleCredReqPayload);
    expect((newCred.credential as any).id).toBeDefined();
    const revockedCred  = await service.deleteCredential((newCred.credential as any).id)
    expect(
      await service.getRevocationList(
       (revockedCred as any)?.issuer,
      )
    ).toBeInstanceOf(Array);
  });

  it('should give revockedList of all creds', async () => {
    const newCred = await service.issueCredential(sampleCredReqPayload);
    expect((newCred.credential as any).id).toBeDefined();
    const revockedCred  = await service.deleteCredential((newCred.credential as any).id)
    expect(
      await service.getRevocationList(undefined)
    ).toBeInstanceOf(Array);
  });


  it('should throw error by saying enter a valid issuer Id', async () => {
    const newCred = await service.issueCredential(sampleCredReqPayload);
    expect((newCred.credential as any).id).toBeDefined();
    const revockedCred  = await service.deleteCredential((newCred.credential as any).id)
    await expect(
      service.getRevocationList("")
    ).rejects.toThrow();
  });

});

// Mocked-unit coverage for branches the real-DB/real-HTTP suite above can't
// reliably reach (error paths, format dispatch, presentation holder-binding).
// Every dependency is mocked here — no DB, no identity-service/credential-schema HTTP.
describe('CredentialsService — mocked unit branches', () => {
  const makeService = async (overrides: any = {}) => {
    const service = new CredentialsService(
      (overrides.prisma || {}) as any,
      (overrides.identityUtilsService || {}) as any,
      (overrides.renderingUtilsService || {}) as any,
      (overrides.schemaUtilsService || {}) as any,
      (overrides.credentialFormatService || {}) as any,
      (overrides.statusListService || {}) as any,
    );
    await service.init();
    return service;
  };

  describe('getSuite', () => {
    it('throws NotFoundException for an unsupported signature type', async () => {
      const service = await makeService();
      await expect(
        service.getSuite({ type: 'Ed25519VerificationKey2020' } as any, 'NoSuchSignature2099'),
      ).rejects.toThrow(NotFoundException);
    });

    it('throws NotFoundException when the verification method type is not supported by the signature type', async () => {
      const service = await makeService();
      await expect(
        service.getSuite({ type: 'RsaVerificationKey2018' } as any, 'Ed25519Signature2020'),
      ).rejects.toThrow(NotFoundException);
    });
  });

  describe('verifyCredential — ecdsa-rdfc-2019 (P-256 DataIntegrityProof)', () => {
    const issuer = 'did:rcw:p256-issuer';
    const vmId = `${issuer}#key-0`;

    // Signs the way identity-service does for a P-256 key: ECDSA over SHA-256, 64-byte r||s.
    const signP256 = async () => {
      const { DataIntegrityProof } = await import('@digitalbazaar/data-integrity');
      const { cryptosuite } = await import('@digitalbazaar/ecdsa-rdfc-2019-cryptosuite');
      const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
      const didDoc = {
        '@context': ['https://www.w3.org/ns/did/v1'],
        id: issuer,
        verificationMethod: [{ id: vmId, type: 'JsonWebKey2020', controller: issuer, publicKeyJwk: publicKey.export({ format: 'jwk' }) }],
        assertionMethod: [vmId],
      };
      const signer = {
        id: vmId,
        algorithm: 'P-256',
        sign: async ({ data }) => new Uint8Array(crypto.sign('sha256', data, { key: privateKey, dsaEncoding: 'ieee-p1363' })),
      };
      const service = await makeService();
      const credential = await service.map.vc.issue({
        credential: {
          '@context': ['https://www.w3.org/2018/credentials/v1', { grade: 'https://schema.org/grade' }],
          type: ['VerifiableCredential'],
          issuer,
          issuanceDate: '2026-01-01T00:00:00Z',
          expirationDate: '2099-01-01T00:00:00Z',
          credentialSubject: { id: 'did:rcw:holder-1', grade: 'A' },
        },
        suite: new DataIntegrityProof({ signer, cryptosuite }),
        documentLoader: service.getDocumentLoader(didDoc as any),
      });
      return { didDoc, credential };
    };

    it('verifies a P-256 credential and rejects a tampered one', async () => {
      const { didDoc, credential } = await signP256();
      expect(credential.proof).toMatchObject({ type: 'DataIntegrityProof', cryptosuite: 'ecdsa-rdfc-2019' });
      const service = await makeService({ identityUtilsService: { resolveDID: jest.fn().mockResolvedValue(didDoc) } });

      const ok: any = await service.verifyCredential(structuredClone(credential));
      expect(ok.checks[0].proof).toBe('OK');

      const tampered = structuredClone(credential);
      tampered.credentialSubject.grade = 'B';
      const bad: any = await service.verifyCredential(tampered);
      expect(bad.checks[0].proof).toBe('NOK');
    });

    it('serves verification-method URLs from the DID document', async () => {
      const { didDoc } = await signP256();
      const service = await makeService();
      const result = await service.getDocumentLoader(didDoc as any)(vmId);
      expect(result.document).toMatchObject({ id: vmId, type: 'JsonWebKey2020' });
    });
  });

  describe('getDocumentLoader', () => {
    it('resolves the DID document itself for a self-reference URL', async () => {
      const service = await makeService();
      const didDoc = { id: 'did:rcw:issuer-1' };
      const loader = service.getDocumentLoader(didDoc as any);
      const result = await loader('did:rcw:issuer-1');
      expect(result.document).toBe(didDoc);
    });

    it('resolves a known static document from the DOCUMENTS map', async () => {
      const service = await makeService();
      const loader = service.getDocumentLoader({ id: 'did:x' } as any);
      const knownUrl = Object.keys(DOCUMENTS)[0];
      const result = await loader(knownUrl);
      expect(result.document).toBe((DOCUMENTS as any)[knownUrl]);
    });
  });

  describe('checkChallengeDomain', () => {
    it('returns checked:false, ok:true when no options are supplied', async () => {
      const service = await makeService();
      const result = (service as any).checkChallengeDomain({ challenge: 'x' }, undefined);
      expect(result).toEqual({ checked: false, ok: true });
    });

    it('passes when challenge and domain both match', async () => {
      const service = await makeService();
      const result = (service as any).checkChallengeDomain(
        { challenge: 'c1', domain: 'd1' },
        { challenge: 'c1', domain: 'd1' },
      );
      expect(result).toEqual({ checked: true, ok: true });
    });

    it('fails when the challenge mismatches', async () => {
      const service = await makeService();
      const result = (service as any).checkChallengeDomain(
        { challenge: 'wrong' },
        { challenge: 'c1' },
      );
      expect(result).toEqual({ checked: true, ok: false });
    });

    it('fails when the domain mismatches', async () => {
      const service = await makeService();
      const result = (service as any).checkChallengeDomain(
        { domain: 'wrong' },
        { domain: 'd1' },
      );
      expect(result).toEqual({ checked: true, ok: false });
    });
  });

  describe('verifyCredential — enveloped formats (verifyEnvelopedCredential)', () => {
    it('verifies a JWT-enveloped credential (two dots, no ~)', async () => {
      const verifyJwt = jest.fn().mockResolvedValue({
        verified: true,
        payload: { vc: { expirationDate: new Date(Date.now() + 100000).toISOString() } },
      });
      const service = await makeService({ identityUtilsService: { verifyJwt } });
      const result: any = await service.verifyCredential('header.payload.signature');
      expect(verifyJwt).toHaveBeenCalledWith('header.payload.signature');
      expect(result.checks[0].proof).toBe('OK');
    });

    it('verifies an SD-JWT-enveloped credential (contains ~)', async () => {
      const verifySdJwt = jest.fn().mockResolvedValue({ verified: true, claims: {} });
      const service = await makeService({ identityUtilsService: { verifySdJwt } });
      const result: any = await service.verifyCredential('sd.jwt.value~disclosure');
      expect(verifySdJwt).toHaveBeenCalled();
      expect(result.checks[0].proof).toBe('OK');
    });

    it('verifies an mdoc-enveloped credential (no dots, no ~)', async () => {
      const verifyMdoc = jest.fn().mockResolvedValue({ verified: true, claims: {}, docType: 'org.iso.18013.5.1' });
      const service = await makeService({ identityUtilsService: { verifyMdoc } });
      const result: any = await service.verifyCredential('mdoc_base64_no_separators');
      expect(verifyMdoc).toHaveBeenCalled();
      expect(result.docType).toBe('org.iso.18013.5.1');
      expect(result.checks[0].proof).toBe('OK');
    });

    it('reports proof NOK when the JWT signature does not verify', async () => {
      const verifyJwt = jest.fn().mockResolvedValue({ verified: false });
      const service = await makeService({ identityUtilsService: { verifyJwt } });
      const result: any = await service.verifyCredential('a.b.c');
      expect(result.checks[0].proof).toBe('NOK');
    });

    it('returns errors when the identity-service call rejects', async () => {
      const verifyJwt = jest.fn().mockRejectedValue(new Error('network down'));
      const service = await makeService({ identityUtilsService: { verifyJwt } });
      const result: any = await service.verifyCredential('a.b.c');
      expect(result.errors).toBeDefined();
    });
  });

  describe('verifyCredential — VerifiablePresentation (verifyPresentation)', () => {
    it('returns errors for an unsupported VP proof type', async () => {
      const service = await makeService();
      const vp = { type: ['VerifiablePresentation'], proof: { type: 'Ed25519Signature2020' } };
      const result: any = await service.verifyCredential(vp as any);
      expect(result.errors).toBeDefined();
    });

    it('returns errors when the holder public key cannot be resolved', async () => {
      const resolveDID = jest.fn().mockResolvedValue({ verificationMethod: [] });
      const service = await makeService({ identityUtilsService: { resolveDID } });
      const vp = {
        type: ['VerifiablePresentation'],
        proof: { type: 'JsonWebSignature2020', verificationMethod: 'did:web:example.com#key-1' },
      };
      const result: any = await service.verifyCredential(vp as any);
      expect(resolveDID).toHaveBeenCalledWith('did:web:example.com');
      expect(result.errors).toBeDefined();
    });
  });
});
