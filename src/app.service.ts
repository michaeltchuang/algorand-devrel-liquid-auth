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
    const os = parser.getOS();
    const browser = parser.getBrowser();
    
    this.logger.debug(`Parsing User-Agent - OS: ${os.name || 'undefined'}, Browser: ${browser.name || 'none'}`);
    
    // Android APK origin
    if (
      os.name?.includes('Android') &&
      typeof browser.name !== 'string'
    ) {
      const pkgName = ua.split('/')[0];
      const statement = assetLinks.filter(
        (al) => al?.target?.package_name === pkgName,
      );
      
      // Check if package is found in assetlinks
      if (statement.length === 0 || !statement[0]?.target) {
        this.logger.warn(`Android package ${pkgName} not found in assetlinks.json, falling back to configured origin`);
        origin = this.configService.get<string>('origin');
      } else {
        // Get all fingerprints and convert to base64url format for multiple signing keys
        const androidHashes = statement[0].target.sha256_cert_fingerprints.map(fp => {
          const octArray: number[] = fp.split(':').map((h) => parseInt(h, 16));
          return toBase64URL(new Uint8Array(octArray));
        });
        // Return all possible origins (handles debug and release builds)
        origin = androidHashes.map(hash => `android:apk-key-hash:${hash}`);
        this.logger.log(`🤖 Android app detected: ${pkgName}, using ${origin.length} origins`);
      }
    }
    // Web Origin (includes iOS native apps and unknown user agents)
    else {
      origin = this.configService.get<string>('origin');
      if (os.name?.includes('iOS')) {
        this.logger.log(`🍎 iOS detected, using web origin: ${origin}`);
      } else if (!os.name) {
        this.logger.log(`📱 Mobile app (no user agent), using web origin: ${origin}`);
      } else {
        this.logger.debug(`Web/Browser detected, using origin: ${origin}`);
      }
    }

    return origin;
  }
}
