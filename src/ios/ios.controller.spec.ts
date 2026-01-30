import { Test, TestingModule } from '@nestjs/testing';
import { IosController } from './ios.controller.js';
import { readFileSync, existsSync } from 'fs';
import { join } from 'path';
import uaChromeFixtures from '../__fixtures__/user-agent.chrome.fixtures.json';

const projectRoot = process.cwd();
const appleAppSiteAssociationPath = join(projectRoot, 'apple-app-site-association');

// Fallback to dist folder if not found in project root
const finalPath = existsSync(appleAppSiteAssociationPath) 
  ? appleAppSiteAssociationPath 
  : join(projectRoot, 'dist', 'apple-app-site-association');

const appleAppSiteAssociation = JSON.parse(
  readFileSync(finalPath, 'utf-8')
);

describe('IosController', () => {
  let controller: IosController;
  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [IosController],
    }).compile();

    controller = module.get<IosController>(IosController);
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });

  it('should return apple app site association', () => {
    uaChromeFixtures.forEach((ua) => {
      expect(
        controller.appleAppSiteAssociation({
          headers: { 'user-agent': ua } as unknown as Headers,
        } as Request),
      ).toEqual(appleAppSiteAssociation);
    });
  });

  it('should return developer applinks', () => {
    process.env.NODE_ENV = 'development';
    process.env.IOS_APPID = '8W2L568H7X.com.example.app';
    process.env.IOS_PATHS = '/login,/register';
    
    const result = controller.appleAppSiteAssociation({
      headers: { 'user-agent': uaChromeFixtures[0] } as unknown as Headers,
    } as Request);

    expect(result.applinks.details).toContainEqual({
      appID: '8W2L568H7X.com.example.app',
      paths: ['/login', '/register'],
    });

    expect(result.webcredentials.apps).toContain('8W2L568H7X.com.example.app');

    process.env.NODE_ENV = 'test';
    delete process.env.IOS_APPID;
    delete process.env.IOS_PATHS;
  });

  it('should use default path when IOS_PATHS not provided', () => {
    process.env.NODE_ENV = 'development';
    process.env.IOS_APPID = '8W2L568H7X.com.example.default';
    
    const result = controller.appleAppSiteAssociation({
      headers: { 'user-agent': uaChromeFixtures[0] } as unknown as Headers,
    } as Request);

    expect(result.applinks.details).toContainEqual({
      appID: '8W2L568H7X.com.example.default',
      paths: ['*'],
    });

    process.env.NODE_ENV = 'test';
    delete process.env.IOS_APPID;
  });

  it('should not add duplicate applinks in development', () => {
    process.env.NODE_ENV = 'development';
    process.env.IOS_APPID = '8W2L568H7X.com.michaeltchuang.walletsdk.demo'; // Already exists in the file
    
    const result = controller.appleAppSiteAssociation({
      headers: { 'user-agent': uaChromeFixtures[0] } as unknown as Headers,
    } as Request);

    // Count occurrences of the appID
    const count = result.applinks.details.filter(
      (detail) => detail.appID === '8W2L568H7X.com.michaeltchuang.walletsdk.demo'
    ).length;

    expect(count).toBe(1); // Should only appear once

    process.env.NODE_ENV = 'test';
    delete process.env.IOS_APPID;
  });
});
