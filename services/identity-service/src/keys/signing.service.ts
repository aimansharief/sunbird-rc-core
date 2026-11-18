import {
  ForbiddenException, Inject, Injectable, InternalServerErrorException, Logger, NotFoundException,
} from '@nestjs/common';
import type { JWK } from 'jose';
import { PrismaService } from '../utils/prisma.service';
import { sha256 } from './encoding';
import { KEY_PROVIDER, KeyAlgorithm, KeyProvider } from './key-provider';
import { KeyRegistryService, SigningKeyRecord } from './key-registry.service';
import { SignContext, SignPurpose } from './sign-context';

@Injectable()
export class SigningService {
  private readonly logger = new Logger(SigningService.name);

  constructor(
    @Inject(KEY_PROVIDER) private readonly provider: KeyProvider,
    private readonly registry: KeyRegistryService,
    private readonly prisma: PrismaService,
  ) {}

  get providerName(): string {
    return this.provider.name;
  }

  async createKey(p: { keyId: string; did: string; algorithm: KeyAlgorithm; authority?: string | null }): Promise<JWK> {
    const keyRef = KeyRegistryService.buildKeyRef(p.authority);
    const jwk = await this.provider.createKey(keyRef, p.algorithm);
    await this.registry.register({
      id: p.keyId, did: p.did, provider: this.provider.name, keyRef, algorithm: p.algorithm, authority: p.authority ?? null,
    });
    return jwk;
  }

  // Drops the registry row after a failed DID write. The provider key is left orphaned and unusable.
  async discardKey(keyId: string): Promise<void> {
    this.logger.warn(`Discarding key record ${keyId}; its provider key is now orphaned`);
    await this.registry.remove(keyId);
  }

  async assertCanSign(keyId: string, purpose: SignPurpose, ctx: SignContext = {}, digest = ''): Promise<SigningKeyRecord> {
    const key = await this.registry.findById(keyId);
    if (!key) {
      throw new NotFoundException(
        `No signing key registered for '${keyId}'. DIDs created before this release must be migrated (yarn keys:migrate).`,
      );
    }
    let reason: string | null = null;
    if (key.status !== 'ACTIVE') reason = `Signing key '${keyId}' is ${key.status}`;
    else if (this.enforceAuthority() && key.authority && key.authority !== ctx.authority) {
      reason = `Caller is not authorised to sign with keys of authority '${key.authority}'`;
    }
    if (reason) {
      await this.audit(key, purpose, ctx, digest, 'DENIED', reason);
      throw new ForbiddenException(reason);
    }
    if (key.provider !== this.provider.name) {
      throw new InternalServerErrorException(
        `Key '${keyId}' is held by provider '${key.provider}' but this service is configured with '${this.provider.name}'`,
      );
    }
    return key;
  }

  async sign(keyId: string, data: Uint8Array, purpose: SignPurpose, ctx: SignContext = {}): Promise<Uint8Array> {
    const digest = sha256(data).toString('hex');
    const key = await this.assertCanSign(keyId, purpose, ctx, digest);
    let signature: Uint8Array;
    try {
      signature = await this.provider.sign(key.keyRef, key.algorithm as KeyAlgorithm, data);
    } catch (err) {
      this.logger.error(`Signing with ${keyId} via ${this.provider.name} failed: ${err}`);
      await this.audit(key, purpose, ctx, digest, 'FAILED', `${err}`.slice(0, 500));
      throw new InternalServerErrorException('Signing failed');
    }
    await this.audit(key, purpose, ctx, digest, 'SIGNED'); // throws => signature discarded (fail closed)
    return signature;
  }

  private enforceAuthority(): boolean {
    return (process.env.ENFORCE_KEY_AUTHORITY ?? 'true').trim() !== 'false';
  }

  private async audit(
    key: SigningKeyRecord, purpose: SignPurpose, ctx: SignContext, digest: string,
    outcome: 'SIGNED' | 'DENIED' | 'FAILED', error?: string,
  ) {
    await this.prisma.signingAuditLog.create({
      data: {
        keyId: key.id, did: key.did, provider: key.provider, algorithm: key.algorithm,
        authority: key.authority, actor: ctx.actor ?? null, purpose,
        payloadSha256: digest, outcome, error: error ?? null,
      },
    });
  }
}
