import { Global, Logger, Module } from '@nestjs/common';
import { PrismaService } from '../utils/prisma.service';
import { KEY_PROVIDER } from './key-provider';
import { assertCapabilities, assertDefaultKeyType, createKeyProvider, requiredAlgorithms } from './key-provider.factory';
import { KeyRegistryService } from './key-registry.service';
import { SigningService } from './signing.service';

@Global()
@Module({
  providers: [
    PrismaService,
    KeyRegistryService,
    SigningService,
    {
      provide: KEY_PROVIDER,
      useFactory: async () => {
        const provider = await createKeyProvider();
        await assertCapabilities(provider, requiredAlgorithms());
        await assertDefaultKeyType(provider);
        Logger.log(`Signing keys held by KEY_PROVIDER '${provider.name}'`, 'KeysModule');
        return provider;
      },
    },
  ],
  exports: [SigningService, KeyRegistryService],
})
export class KeysModule {}
