import { BadRequestException, Injectable, InternalServerErrorException, Logger, NotFoundException } from '@nestjs/common';
import { PrismaService } from '../utils/prisma.service';
import { v4 as uuid } from 'uuid';
import { SigningService } from '../keys/signing.service';
import { KeyRegistryService } from '../keys/key-registry.service';
import { SignContext } from '../keys/sign-context';
import { algorithmForVmType, buildVerificationMethod, isSupportedVmType } from '../keys/verification-method';
import { Identity } from '@prisma/client';
import { RSAKeyPair } from 'crypto-ld';
import { GenerateDidDTO } from './dtos/GenerateDidRequest.dto';

const { DIDDocument } = require('did-resolver');
type DIDDocument = typeof DIDDocument;
type KeysType = {
  [key: string]: {
    name: string;
    key: any;
  };
};
const DEFAULT_VM_TYPE_FOR_ALGORITHM: Record<string, string> = {
  Ed25519Signature2020: 'Ed25519VerificationKey2020',
  Ed25519Signature2018: 'Ed25519VerificationKey2018',
  JsonWebSignature2020: 'JsonWebKey2020',
  RsaSignature2018: 'RsaVerificationKey2018',
};

@Injectable()
export class DidService {
  keys: KeysType = {
  }
  webDidPrefix: string;
  signingAlgorithm: string;
  didResolver: any;
  constructor(
    private prisma: PrismaService,
    private signing: SigningService,
    private registry: KeyRegistryService,
  ) {
    let baseUrl: string = process.env.WEB_DID_BASE_URL;
    this.webDidPrefix = this.getDidPrefixForBaseUrl(baseUrl);
    this.signingAlgorithm = process.env.SIGNING_ALGORITHM;
    this.init();
  }

  async init() {
    const {Ed25519VerificationKey2020} = await import('@digitalbazaar/ed25519-verification-key-2020');
    const {Ed25519VerificationKey2018} = await import('@digitalbazaar/ed25519-verification-key-2018');
    this.keys['Ed25519Signature2020'] = {
      name: 'Ed25519VerificationKey2020',
      key: Ed25519VerificationKey2020
    };
    this.keys['Ed25519Signature2018'] = {
      name: 'Ed25519VerificationKey2018',
      key: Ed25519VerificationKey2018
    };
    this.keys['RsaSignature2018'] = {
      name: 'RsaVerificationKey2018',
      key: RSAKeyPair
    };
    // EC P-256/JsonWebKey2020 — generated directly via Node crypto in
    // generateDID() below (no digitalbazaar LD-key library covers plain
    // EC/JWK keys), so `key` is left null here as a lookup sentinel only.
    this.keys['JsonWebSignature2020'] = {
      name: 'JsonWebKey2020',
      key: null
    };
    const { Resolver } = await import('did-resolver');
    const { getResolver } = await import('web-did-resolver');
    const webResolver = getResolver();
    this.didResolver = new Resolver({
      ...webResolver
        //...you can flatten multiple resolver methods into the Resolver
    });
  }

  getDidPrefixForBaseUrl(baseUrl: string): string {
    if(!baseUrl || typeof baseUrl !== "string") return '';
    baseUrl = baseUrl.split("?")[0]
      .replace("https://", "")
      .replace(/:/g, "%3A")
      .replace(/\//g, ":");
    return `did:web:${baseUrl}:`;
  }

  generateDidUri(method: string, id?: string, webDidBaseUrl?: string): string {
    if(id) return id;
    if (method === 'web') {
      return this.getWebDidIdForId(uuid(), webDidBaseUrl);
    }
    return `did:${(method && method.trim() !== '') ? method.trim() : 'rcw'}:${uuid()}`;
  }

  getWebDidIdForId(id: string, webDidBaseUrl?: string): string {
    if(!this.webDidPrefix && !webDidBaseUrl) throw new NotFoundException("Web did base url not found");
    if(webDidBaseUrl) {
      const webDidBasePrefix = this.getDidPrefixForBaseUrl(webDidBaseUrl);
      return `${webDidBasePrefix}${id}`;
    }
    return `${this.webDidPrefix}${id}`;
  }

  async getVerificationKey(signingAlgorithm?: string): Promise<any> {
    if(!this.keys[signingAlgorithm]) {
      await this.init();
    }
    if(!this.keys[signingAlgorithm]) {
      throw new NotFoundException("Signature algorithm not found")
    }
    return this.keys[signingAlgorithm];
  }

  async getVerificationKeyByName(name?: string) {
    let verificationKey = Object.values(this.keys).find((d: {name: string, key: any}) => d.name === name);
    if(!verificationKey) {
      await this.init();
      verificationKey = Object.values(this.keys).find((d: {name: string, key: any}) => d.name === name);
    }
    if(name && !verificationKey) throw new NotFoundException("Verification Key '" + name + "' not found");
    return verificationKey;
  }

  async generateDID(doc: GenerateDidDTO, ctx: SignContext = {}): Promise<DIDDocument> {
    const didUri: string = this.generateDidUri(doc?.method, doc?.id, doc?.webDidBaseUrl);
    const withKey = doc?.withKey !== false;
    let keyId: string | undefined;
    let verificationMethod: any;

    if (withKey) {
      const vmType: string = doc?.keyPairType
        || DEFAULT_VM_TYPE_FOR_ALGORITHM[this.signingAlgorithm]
        || 'Ed25519VerificationKey2020';
      if (vmType === 'RsaVerificationKey2018') {
        throw new BadRequestException(
          'RsaVerificationKey2018 keys cannot be created: supported key types are Ed25519VerificationKey2020, Ed25519VerificationKey2018 and JsonWebKey2020',
        );
      }
      if (!isSupportedVmType(vmType)) throw new NotFoundException(`Verification Key '${vmType}' not found`);
      keyId = `${didUri}#key-0`;
      const jwk = await this.signing.createKey({
        keyId, did: didUri, algorithm: algorithmForVmType(vmType), authority: ctx.authority ?? doc?.authority,
      });
      verificationMethod = buildVerificationMethod(keyId, didUri, vmType, jwk);
    }

    const document: DIDDocument = {
      '@context': ['https://www.w3.org/ns/did/v1'],
      id: didUri,
      alsoKnownAs: doc.alsoKnownAs,
      service: doc.services,
      ...(withKey
        ? { verificationMethod: [verificationMethod], authentication: [keyId], assertionMethod: [keyId] }
        : {}),
    };

    try {
      await this.prisma.identity.create({ data: { id: didUri, didDoc: JSON.stringify(document) } });
    } catch (err) {
      Logger.error(`Error writing DID to database ${err}`);
      if (keyId) await this.signing.discardKey(keyId).catch(() => undefined);
      throw new InternalServerErrorException('Error writing DID to database');
    }
    return document;
  }

  async resolveDID(id: string): Promise<DIDDocument> {
    let artifact: Identity;
    try {
      artifact = await this.prisma.identity.findUnique({
        where: { id: id?.split("#")[0] },
      });
    } catch (err) {
      Logger.error(`Error fetching DID: ${id} from db, ${err}`);
      throw new InternalServerErrorException(`Error fetching DID: ${id} from db`);
    }

    if(!artifact && id?.startsWith("did:web") && !id?.startsWith(this.webDidPrefix)) {
      try {
        let doc = (await this.didResolver.resolve(id)).didDocument;
        if(!doc) throw new Error("DID document is null");
        return doc;
      } catch (err) {
        Logger.error(`Error fetching DID: ${id} from web, ${err}`);
        throw new InternalServerErrorException(`Error fetching DID: ${id} from web`);
      }
    }

    if (artifact) {
      return JSON.parse(artifact.didDoc as string) as DIDDocument;
    } else {
      throw new NotFoundException(`DID: ${id} not found`);
    }
  }

  async resolveWebDID(id: string): Promise<DIDDocument> {
    const webDidId = this.getWebDidIdForId(id);
    return this.resolveDID(webDidId);
  }
}
