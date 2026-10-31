import test from 'node:test';
import assert from 'node:assert/strict';
import {migrationMetadataSource,isMigrationArchive} from '../src/migration-sources.js';

const tag='utility-v1.18.0.1-halo-keymind-cascade-dev-03214a16';
const metadata=`https://api.github.com/repos/mikecarper/MeshCore/releases/tags/${tag}`;
const archive=`https://github.com/mikecarper/MeshCore/releases/download/${tag}/heltec-v4-repeater-v1.18.0.1-migration.zip`;
const shared='https://github.com/mikecarper/MeshCore/releases/download/utility-usb-partition-v1-3d3d5827/meshcore-usb-partition-bridges.zip';

test('migration metadata recognizes only the canonical public utility release endpoint',()=>{
  assert.deepEqual(migrationMetadataSource(metadata),{url:metadata,owner:'mikecarper',repository:'MeshCore',tag,name:tag+'.json'});
  for(const version of ['1.18.0','1.18.0.2','1.18.0.2-preview.1','1.18.0-a_B.1'])assert.ok(migrationMetadataSource(metadata.replace(tag,'utility-v'+version)));
  for(const value of [null,undefined,{},new URL(metadata),metadata+'?x=1',metadata+'?',metadata+'#x',metadata+'#',metadata+'/',metadata.replace('api.github.com','api.github.com.evil.test'),metadata.replace('api.github.com','API.GITHUB.COM'),metadata.replace('api.github.com','api.github.com:443'),metadata.replace('api.github.com','api.github.com:8443'),metadata.replace('https:','http:'),metadata.replace('https://','https://user:pass@'),metadata.replace('/mikecarper/','/other/'),metadata.replace('/MeshCore/','/meshcore/'),metadata.replace('/tags/','/latest/'),metadata.replace(tag,'utility-v1.18'),metadata.replace(tag,'utility-v1.18.0.1.2'),metadata.replace(tag,'v1.18.0'),metadata.replace(tag,'utility-usb-partition-v1-3d3d5827'),metadata.replace(tag,'utility-v1.18.0-'),metadata.replace(tag,'%75tility-v1.18.0'),metadata.replace(tag,'utility-v1%2E18.0'),metadata.replace(tag,'utility-v1.18.0%2Fextra'),metadata.replace(tag,'utility-v1.18.0%00'),metadata.replace(tag,'utility-v1.18.0/'+tag),metadata.replace('/tags/','/tags/../tags/'),' '+metadata,metadata+'\n'])assert.equal(migrationMetadataSource(value),null,String(value));
});

test('migration archives allow only utility migration ZIPs and the exact pinned shared bridge set',()=>{
  assert.equal(isMigrationArchive(archive),true);assert.equal(isMigrationArchive(shared),true);
  assert.equal(isMigrationArchive(archive.replace(/[^/]+$/,'meshcore-usb-partition-bridges.zip')),true);
  assert.equal(isMigrationArchive(archive.replace(tag,'utility-v1.18.0')),true);
  for(const value of [null,undefined,{},new URL(archive),metadata,archive+'?download=1',archive+'?',archive+'#file',archive.replace('https:','http:'),archive.replace('https://','https://user@'),archive.replace('github.com','github.com:443'),archive.replace('github.com','github.com:8443'),archive.replace('github.com','GITHUB.COM'),archive.replace('github.com','github.com.evil.test'),archive.replace('/mikecarper/','/other/'),archive.replace('/MeshCore/','/meshcore/'),archive.replace('/download/','/tags/'),archive.replace(tag,'v1.18.0'),archive.replace(tag,'%75tility-v1.18.0'),archive.replace(tag,'utility-v1%2E18.0'),archive.replace('-migration.zip','.zip'),archive.replace('-migration.zip','-migration.ZIP'),archive.replace('-migration.zip','-migration.zip.exe'),archive.replace('-migration.zip','%2Dmigration.zip'),archive.replace(/[^/]+$/,'../x-migration.zip'),archive.replace(/[^/]+$/,'x%2Fy-migration.zip'),archive.replace(/[^/]+$/,'x%5Cy-migration.zip'),archive.replace(/[^/]+$/,'x%00-migration.zip'),archive.replace(/[^/]+$/,'x migration.zip'),shared.replace('3d3d5827','aaaaaaaa'),shared.replace('meshcore-usb-partition-bridges.zip','other-migration.zip'),' '+archive,archive+'\n'])assert.equal(isMigrationArchive(value),false,String(value));
});

test('migration names and tags remain bounded, safe URL and filename components',()=>{
  const maxTag='utility-v1.18.0-'+ 'a'.repeat(234);
  assert.equal(maxTag.length,250);
  assert.equal(migrationMetadataSource(metadata.replace(tag,maxTag)).name.length,255);
  assert.equal(migrationMetadataSource(metadata.replace(tag,maxTag+'a')),null);
  assert.equal(isMigrationArchive(archive.replace(tag,maxTag+'a')),false);
  assert.equal(isMigrationArchive(archive.replace(/[^/]+$/,'a'.repeat(242)+'-migration.zip')),true);
  assert.equal(isMigrationArchive(archive.replace(/[^/]+$/,'a'.repeat(243)+'-migration.zip')),false);
});
