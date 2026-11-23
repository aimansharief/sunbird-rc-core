import { KeyProvider } from '../key-provider';
import { KeyRegistryService } from '../key-registry.service';
import { SigningService } from '../signing.service';
import { InMemoryKeyProvider } from './in-memory-key-provider';

export function createTestSigning(prisma: any, provider: KeyProvider = new InMemoryKeyProvider()) {
  const registry = new KeyRegistryService(prisma);
  return { provider, registry, signing: new SigningService(provider, registry, prisma) };
}

// Promise.allSettled equivalent (the es2017 target has no typings for it).
export function settle<T>(promises: Promise<T>[]): Promise<Array<{ ok: true; value: T } | { ok: false; reason: any }>> {
  return Promise.all(promises.map((p) => p.then((value) => ({ ok: true as const, value }), (reason) => ({ ok: false as const, reason }))));
}
