import { describeKeyProviderContract } from './key-provider.contract';
import { InMemoryKeyProvider } from './in-memory-key-provider';

describeKeyProviderContract('in-memory', async () => new InMemoryKeyProvider());
describeKeyProviderContract('in-memory (P-256 only)', async () => new InMemoryKeyProvider(['P-256']));
