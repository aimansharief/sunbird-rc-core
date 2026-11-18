import {
  BadRequestException,
  Body,
  Controller,
  Get,
  InternalServerErrorException,
  Logger,
  Param,
  Post,
  Req,
  UseGuards,
} from '@nestjs/common';
import {
  ApiBadRequestResponse,
  ApiBody,
  ApiNotFoundResponse,
  ApiOkResponse,
  ApiOperation,
  ApiParam,
  ApiResponse,
  ApiTags,
} from '@nestjs/swagger';
const { DIDDocument } = require('did-resolver');
type DIDDocument = typeof DIDDocument;
import { DidService } from './did.service';
import { GenerateDidRequestDTO } from './dtos/GenerateDidRequest.dto';
import { signContextFrom } from '../keys/sign-context';
import { RotateKeyDTO } from './dtos/RotateKey.dto';
const pLimit = require('p-limit');
const limit = pLimit(100);

@ApiTags('DID')
@Controller()
export class DidController {
  constructor(private readonly didService: DidService) {}

  @ApiOperation({ summary: 'Generate a new DID' })
  @ApiOkResponse({ description: 'DID Generated', isArray: true })
  @ApiBadRequestResponse({ description: 'Bad request' })
  @ApiBody({ type: GenerateDidRequestDTO, isArray: false })
  @Post('/did/generate')
  async generateDID(
    @Body() generateRequest: GenerateDidRequestDTO,
    @Req() req: any,
  ): Promise<DIDDocument[]> {
    const ctx = signContextFrom(req);
    const promises = generateRequest.content.map((generateDidDTO) => {
      return limit(() => this.didService.generateDID(generateDidDTO, ctx));
    });
    try {
      return await Promise.all(promises);
    } catch (err) {
      Logger.error(err);
      throw new InternalServerErrorException(err?.message);
    }
  }

  @ApiOperation({ summary: 'Rotate the active signing key of a DID' })
  @ApiOkResponse({ description: 'Updated DID document' })
  @Post('/did/:id/keys/rotate')
  async rotateKey(@Param('id') id: string, @Body() body: RotateKeyDTO, @Req() req: any): Promise<DIDDocument> {
    if (!['Ed25519', 'P-256'].includes(body?.algorithm)) {
      throw new BadRequestException("algorithm must be 'Ed25519' or 'P-256'");
    }
    return this.didService.rotateKey(id, body.algorithm, body.revokePrevious === true, signContextFrom(req));
  }

  @ApiOperation({ summary: 'Resolve a DID ID' })
  @ApiOkResponse({ description: 'DID resolved' })
  @ApiBadRequestResponse({ description: 'Bad Request' })
  @ApiNotFoundResponse({ description: 'DID not found' })
  @ApiParam({ name: 'id', description: 'The DID ID to resolve' })
  @Get('/did/resolve/:id')
  async resolveDID(@Param('id') id: string): Promise<DIDDocument> {
    return await this.didService.resolveDID(id);
  }

  @ApiOperation({ summary: 'Resolve a Web DID ID' })
  @ApiOkResponse({ description: 'DID resolved' })
  @ApiBadRequestResponse({ description: 'Bad Request' })
  @ApiNotFoundResponse({ description: 'DID not found' })
  @ApiParam({ name: 'id', description: 'The DID ID to resolve' })
  @Get('/:id/did.json')
  async resolveWebDID(@Param('id') id: string): Promise<DIDDocument> {
    return await this.didService.resolveWebDID(id);
  }
}
