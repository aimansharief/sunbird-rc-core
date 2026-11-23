import { Injectable } from '@nestjs/common';
import { SigningKey } from '@prisma/client';
import { v4 as uuid } from 'uuid';
import { PrismaService } from '../utils/prisma.service';
import { KeyAlgorithm } from './key-provider';

export type SigningKeyRecord = SigningKey;

@Injectable()
export class KeyRegistryService {
  constructor(private readonly prisma: PrismaService) {}

  static buildKeyRef(authority?: string | null): string {
    const scope = (authority || 'default')
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/^-+|-+$/g, '')
      .slice(0, 40) || 'default';
    return `rc-${scope}-${uuid().replace(/-/g, '')}`;
  }

  register(rec: { id: string; did: string; provider: string; keyRef: string; algorithm: KeyAlgorithm; authority?: string | null }) {
    return this.prisma.signingKey.create({ data: { ...rec, authority: rec.authority ?? null } });
  }

  findById(id: string) {
    return this.prisma.signingKey.findUnique({ where: { id } });
  }

  findActive(did: string, algorithm: KeyAlgorithm) {
    return this.prisma.signingKey.findFirst({
      where: { did, algorithm, status: 'ACTIVE' },
      orderBy: { createdAt: 'desc' },
    });
  }

  listByDid(did: string) {
    return this.prisma.signingKey.findMany({ where: { did }, orderBy: { createdAt: 'asc' } });
  }

  setStatus(id: string, status: 'ACTIVE' | 'RETIRED' | 'REVOKED') {
    return this.prisma.signingKey.update({ where: { id }, data: { status } });
  }

  // Atomic compare-and-set: changes the status only if it is still `from`. Returns false if another request got there first.
  async transition(id: string, from: 'ACTIVE' | 'RETIRED' | 'REVOKED', to: 'ACTIVE' | 'RETIRED' | 'REVOKED'): Promise<boolean> {
    const { count } = await this.prisma.signingKey.updateMany({ where: { id, status: from }, data: { status: to } });
    return count === 1;
  }

  async remove(id: string): Promise<void> {
    await this.prisma.signingKey.delete({ where: { id } });
  }
}
