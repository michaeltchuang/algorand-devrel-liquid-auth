import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { AppService } from '../app.service.js';
import {
  generateRegistrationOptions,
  RegistrationResponseJSON,
  verifyRegistrationResponse,
} from '@simplewebauthn/server';
import { AttestationSelectorDto } from './attestation.dto.js';
import {
  decodeAddress,
  fromBase64Url,
  toBase64URL,
} from '../encoding/index.js';
import nacl from 'tweetnacl';
import { AlgodService } from '../algod/algod.service.js';

@Injectable()
export class AttestationService {
  private readonly logger = new Logger(AttestationService.name);
  encoder: TextEncoder = new TextEncoder();
  constructor(
    private appService: AppService,
    private algodService: AlgodService,
    private configService: ConfigService,
  ) {}

  async verify(
    algod: AlgodService,
    type: string,
    challenge: string,
    signature: string,
    address: string,
  ) {
    const challengeBytes = fromBase64Url(challenge);
    const signatureBytes = fromBase64Url(signature);

    if (type === 'algorand') {
      // Ed25519 signature verification
      const publicKeyBytes = decodeAddress(address);
      const valid = nacl.sign.detached.verify(
        challengeBytes,
        signatureBytes,
        publicKeyBytes,
      );
      if (valid) return true;
      if (!valid) {
        // signature check failed, check if its rekeyed
        // if it is, verify against that public key instead
        const accountInfo = await algod
          .accountInformation(address)
          .exclude('all')
          .do();

        if (!accountInfo['auth-addr']) {
          return false;
        }

        const authPublicKey = decodeAddress(accountInfo['auth-addr']);

        // Validate Auth Address Signature
        return nacl.sign.detached.verify(
          challengeBytes,
          signatureBytes,
          authPublicKey,
        );
      }
    } else if (type === 'falcon-1024') {
      // Falcon-1024 post-quantum signature verification via Go microservice
      try {
        const publicKeyBytes = decodeAddress(address);
        
        // Call the Falcon verification Go service
        const falconServiceUrl = this.configService.get<string>('falconServiceUrl') || 'http://localhost:3002';
        
        const response = await fetch(`${falconServiceUrl}/verify`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            publicKey: Array.from(publicKeyBytes),
            signature: Array.from(signatureBytes),
            message: Array.from(challengeBytes),
          }),
        });

        if (!response.ok) {
          throw new Error(`Falcon service returned ${response.status}`);
        }

        const result = await response.json();
        
        if (result.valid) return true;
        
        // Check if the account is rekeyed to another Falcon key
        const accountInfo = await algod
          .accountInformation(address)
          .exclude('all')
          .do();

        if (!accountInfo['auth-addr']) {
          return false;
        }

        const authPublicKey = decodeAddress(accountInfo['auth-addr']);

        // Validate with rekeyed Falcon public key
        const rekeyResponse = await fetch(`${falconServiceUrl}/verify`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            publicKey: Array.from(authPublicKey),
            signature: Array.from(signatureBytes),
            message: Array.from(challengeBytes),
          }),
        });

        if (!rekeyResponse.ok) {
          return false;
        }

        const rekeyResult = await rekeyResponse.json();
        return rekeyResult.valid;
      } catch (error) {
        this.logger.error('Falcon-1024 verification error:', error);
        return false;
      }
    }
    return false;
  }
  async request(options: AttestationSelectorDto) {
    //https://www.iana.org/assignments/cose/cose.xhtml#algorithms
    // EdDSA is -8
    // const params = [-7, -35, -36, -257, -258, -259, -37, -38, -39, -8];
    const _options = await generateRegistrationOptions({
      rpName: this.configService.get('rpName'),
      rpID: this.configService.get('hostname'),
      userName: options.username,
      userDisplayName: options.username,
      timeout: this.configService.get('timeout'),
      extensions: options.extensions,
      supportedAlgorithmIDs: [-7, -257],
      authenticatorSelection: {
        // residentKey: 'preferred',
        userVerification: 'required',
      },
    });
    // Patch the options to match v1
    _options.user.id = options.username;
    delete _options.extensions.credProps;
    delete _options.hints;
    return _options;
  }

  /**
   *
   * @param expectedChallenge - The challenge sent to the client
   * @param ua - The User-Agent header
   * @param credential - The credential sent from the client
   */
  async response(
    expectedChallenge: string,
    ua: string,
    credential: RegistrationResponseJSON & {
      clientExtensionResults?: {
        liquid: {
          type: string;
          signature: string;
          address: string;
          device?: string;
        };
      };
    },
  ) {
    const expectedOrigin = this.appService.getOrigin(ua);
    const expectedRPID = this.configService.get<string>('hostname');

    // Validate the passkey
    // For Android, we accept any of the configured fingerprints
    const verifiedAttestation = await verifyRegistrationResponse({
      response: credential,
      expectedChallenge,
      expectedOrigin: Array.isArray(expectedOrigin) ? expectedOrigin : [expectedOrigin],
      expectedRPID,
    });
    const { registrationInfo } = verifiedAttestation;
    let { verified } = verifiedAttestation;

    // Handle Liquid Extension
    const isLiquid =
      typeof credential.clientExtensionResults !== 'undefined' &&
      typeof credential.clientExtensionResults.liquid !== 'undefined';
    // Check for extension results
    if (isLiquid && verified) {
      // Verify the Algorand signature (supports both Ed25519 and Falcon-1024)
      verified = await this.verify(
        this.algodService,
        credential.clientExtensionResults.liquid.type,
        expectedChallenge,
        credential.clientExtensionResults.liquid.signature,
        credential.clientExtensionResults.liquid.address,
      );
    }

    if (!verified) {
      throw 'User verification failed.';
    }

    return {
      device:
        credential?.clientExtensionResults?.liquid?.device || 'Unknown Device',
      publicKey: toBase64URL(registrationInfo.credential.publicKey),
      credId: registrationInfo.credential.id,
      prevCounter: registrationInfo.credential.counter,
    };
  }
}
