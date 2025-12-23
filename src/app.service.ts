import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import UAParser from 'ua-parser-js';
import { toBase64URL } from './encoding/index.js';

//@ts-ignore, required for jest
import assetLinks from '../assetlinks.json' with { type: 'json' };

@Injectable()
export class AppService {
  private readonly logger = new Logger(AppService.name);
  constructor(private configService: ConfigService) {}
  getOrigin(ua: string): string | string[] {
    let origin: string | string[];
    const parser = new UAParser(ua);
    // Android APK origin
    if (
      parser.getOS().name.includes('Android') &&
      typeof parser.getBrowser().name !== 'string'
    ) {
      const pkgName = ua.split('/')[0];
      const statement = assetLinks.filter(
        (al) => al?.target?.package_name === pkgName,
      );
      // Get all fingerprints and convert to base64url format for multiple signing keys
      const androidHashes = statement[0].target.sha256_cert_fingerprints.map(fp => {
        const octArray: number[] = fp.split(':').map((h) => parseInt(h, 16));
        return toBase64URL(new Uint8Array(octArray));
      });
      // Return all possible origins (handles debug and release builds)
      origin = androidHashes.map(hash => `android:apk-key-hash:${hash}`);
    }
    // Web Origin
    else {
      origin = this.configService.get<string>('origin');
    }

    return origin;
  }
}
