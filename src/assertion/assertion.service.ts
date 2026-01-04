import { Injectable, Logger } from '@nestjs/common';
import {
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from '@simplewebauthn/server';
import { User } from '../auth/auth.schema.js';
import {
  AuthenticationResponseJSON,
  PublicKeyCredentialRequestOptions,
} from '@simplewebauthn/server';
import { AppService } from '../app.service.js';
import { ConfigService } from '@nestjs/config';
import { fromBase64Url } from '../encoding/index.js';

@Injectable()
export class AssertionService {
  private readonly logger = new Logger(AssertionService.name);
  
  constructor(
    private appService: AppService,
    private configService: ConfigService,
  ) {}
  async request(
    user: User,
    credId: string | undefined,
    options: PublicKeyCredentialRequestOptions,
  ) {
    const userVerification = options.userVerification || 'required';

    const allowCredentials = [];
    for (const cred of user.credentials) {
      // `credId` is specified and matches
      if (credId && cred.credId == credId) {
        allowCredentials.push({
          id: cred.credId,
          type: 'public-key',
        });
      }
    }

    return generateAuthenticationOptions({
      timeout: this.configService.get<number>('timeout'),
      rpID: this.configService.get<string>('hostname'),
      allowCredentials,
      /**
       * This optional value controls whether the authenticator needs to be able to uniquely
       * identify the user interacting with it (via built-in PIN pad, fingerprint scanner, etc...)
       */
      userVerification,
    });
  }

  async response(
    user: User,
    credential: AuthenticationResponseJSON & {
      clientExtensionResults?: {
        liquid?: {
          type?: string;
          signature?: string;
          address?: string;
          publicKey?: string;
          requestId?: string;
          device?: string;
        };
      };
    },
    challenge: string,
    ua: string,
  ) {
    const expectedOrigin = this.appService.getOrigin(ua);
    const expectedRPID = this.configService.get('hostname');

    const userCredential = user.credentials.find(
      (cred) => cred.credId === credential.id,
    );

    if (!userCredential) {
      throw 'Authenticating credential not found.';
    }

    const verification = await verifyAuthenticationResponse({
      response: credential,
      expectedChallenge: challenge,
      expectedOrigin: Array.isArray(expectedOrigin) ? expectedOrigin : [expectedOrigin],
      expectedRPID,
      credential: {
        publicKey: fromBase64Url(userCredential.publicKey),
        counter: userCredential.prevCounter,
        id: userCredential.credId,
      },
    });

    let { verified } = verification;
    const { authenticationInfo } = verification;

    // Check for Liquid Extension with Falcon signature
    const hasLiquidExtension =
      credential.clientExtensionResults?.liquid?.type === 'falcon-1024' &&
      credential.clientExtensionResults?.liquid?.signature;

    if (hasLiquidExtension && verified) {
      this.logger.debug('Verifying Falcon-1024 signature from liquid extension');
      
      const falconServiceUrl = this.configService.get('falconServiceUrl') || 'http://localhost:3002';
      
      // Use public key from extension if provided, otherwise use stored public key
      let publicKeyBase64: string;
      if (credential.clientExtensionResults.liquid.publicKey) {
        publicKeyBase64 = credential.clientExtensionResults.liquid.publicKey;
        this.logger.debug('Using Falcon public key from extension');
      } else {
        // For Falcon, the stored publicKey should be the full 1793-byte key
        publicKeyBase64 = userCredential.publicKey;
        this.logger.debug('Using stored Falcon public key from database');
      }
      
      const publicKeyBytes = fromBase64Url(publicKeyBase64);
      const signatureBytes = fromBase64Url(credential.clientExtensionResults.liquid.signature);
      const challengeBytes = fromBase64Url(challenge);

      const verifyRequest = {
        publicKey: Array.from(publicKeyBytes),
        signature: Array.from(signatureBytes),
        message: Array.from(challengeBytes),
      };

      try {
        const response = await fetch(`${falconServiceUrl}/verify`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(verifyRequest),
        });

        if (!response.ok) {
          this.logger.error('Falcon service returned error:', response.status);
          verified = false;
        } else {
          const result = await response.json();
          verified = result.valid;
          
          if (verified) {
            this.logger.debug('✅ Falcon-1024 signature verified');
          } else {
            this.logger.warn('❌ Falcon-1024 signature invalid:', result.error);
          }
        }
      } catch (error) {
        this.logger.error('Error verifying Falcon signature:', error);
        verified = false;
      }
    }

    if (!verified) {
      throw 'User verification failed.';
    }

    userCredential.prevCounter = authenticationInfo.newCounter;

    return user;
  }
}
