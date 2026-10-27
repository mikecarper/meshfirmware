import { test } from 'node:test';
import assert from 'node:assert/strict';
import { migrationStatus, waitForMigration } from '../src/migration.js';
const mac='aa:bb:cc:dd:ee:ff';
const line=(extra={})=>'MESHCORE_USB_MIGRATION_STATE '+JSON.stringify({format:'meshcore-usb-partition-migration-v1',device_mac:'AABBCCDDEEFF',settled:true,restored:true,...extra});
test('UART migration status is exact, chip-bound and not a restoration proof',()=>{
  assert.equal(migrationStatus('unrelated private data',mac),null);
  assert.equal(migrationStatus(line({settled:false}),mac),null);
  assert.equal(migrationStatus(line({restored:1}),mac),null);
  assert.equal(migrationStatus(line({format:'other'}),mac),null);
  assert.throws(()=>migrationStatus(line({device_mac:'112233445566'}),mac),/different chip/);
  assert.equal(migrationStatus(line({restored:false}),mac).restored,false);
});
test('UART wait tolerates fragmented/noisy lines without writes or resets',async()=>{
  const chunks=['secret\n'+line().slice(0,30),line().slice(30)+'\r\n'];
  let now=0;
  const link={read:async()=>{now+=10;return new TextEncoder().encode(chunks.shift()||'');}};
  assert.equal((await waitForMigration(link,mac,100,()=>now)).settled,true);
  await assert.rejects(waitForMigration({read:async()=>{now+=10;return [];}},mac,20,()=>now),/No ROM reset/);
});
