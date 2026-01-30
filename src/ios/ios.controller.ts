import { Controller, Get, Logger, Req } from '@nestjs/common';
import { readFileSync, existsSync } from 'fs';
import { join } from 'path';
import { ApiOperation, ApiTags } from '@nestjs/swagger';

// Read the apple-app-site-association file from the project root
// This works in both dev (where cwd is project root) and production
const projectRoot = process.cwd();
const appleAppSiteAssociationPath = join(projectRoot, 'apple-app-site-association');

// Fallback to dist folder if not found in project root (production build)
const finalPath = existsSync(appleAppSiteAssociationPath) 
  ? appleAppSiteAssociationPath 
  : join(projectRoot, 'dist', 'apple-app-site-association');

const appleAppSiteAssociationData = JSON.parse(
  readFileSync(finalPath, 'utf-8')
);

@Controller('.well-known')
@ApiTags('.well-known')
export class IosController {
  private readonly logger = new Logger(IosController.name);

  /**
   * Apple App Site Association
   *
   * @see https://developer.apple.com/documentation/xcode/supporting-associated-domains
   * @param req
   *
   */
  @ApiOperation({ summary: 'Apple App Site Association' })
  @Get('/apple-app-site-association')
  appleAppSiteAssociation(@Req() req: Request) {
    this.logger.debug(
      `GET /.well-known/apple-app-site-association ${req.headers['user-agent']}`,
    );
    
    const result = { ...appleAppSiteAssociationData };
    
    // In Development, allow for overriding the apple app site association
    if (process.env.NODE_ENV === 'development') {
      if (process.env.IOS_APPID) {
        const appID = process.env.IOS_APPID;
        const paths = process.env.IOS_PATHS 
          ? process.env.IOS_PATHS.split(',').map(p => p.trim())
          : ['*'];
        
        // Check if appID already exists in applinks
        const existingApplink = result.applinks?.details?.find(
          (detail) => detail.appID === appID
        );
        
        if (!existingApplink) {
          // Add to applinks
          if (!result.applinks) {
            result.applinks = { apps: [], details: [] };
          }
          result.applinks.details.push({
            appID,
            paths,
          });
        }
        
        // Check if appID already exists in webcredentials
        const existingWebcred = result.webcredentials?.apps?.includes(appID);
        
        if (!existingWebcred) {
          // Add to webcredentials
          if (!result.webcredentials) {
            result.webcredentials = { apps: [] };
          }
          result.webcredentials.apps.push(appID);
        }
      }
    }
    
    return result;
  }
}
