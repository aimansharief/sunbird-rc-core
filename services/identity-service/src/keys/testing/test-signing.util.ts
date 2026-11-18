import { KeyProvider } from '../key-provider';
import { KeyRegistryService } from '../key-registry.service';
import { SigningService } from '../signing.service';
import { InMemoryKeyProvider } from './in-memory-key-provider';

export function createTestSigning(prisma: any, provider: KeyProvider = new InMemoryKeyProvider()) {
  const registry = new KeyRegistryService(prisma);
  return { provider, registry, signing: new SigningService(provider, registry, prisma) };
}
