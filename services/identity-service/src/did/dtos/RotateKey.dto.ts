import { ApiProperty } from '@nestjs/swagger';

export class RotateKeyDTO {
  @ApiProperty({ enum: ['Ed25519', 'P-256'] })
  algorithm: 'Ed25519' | 'P-256';

  @ApiProperty({
    required: false,
    default: false,
    description: 'true = remove the old key from the DID document (credentials it signed stop verifying). Use after key compromise.',
  })
  revokePrevious?: boolean;
}
