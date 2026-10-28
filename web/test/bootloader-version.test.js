import test from 'node:test';
import assert from 'node:assert/strict';
import {assessBootloaderVersion} from '../src/bootloader-version.js';

const latest='2.4.12';
const assess=value=>assessBootloaderVersion(value,latest);

test('exact stable OTAFIX version is current without comparing the Adafruit prefix',()=>{
  for(const value of ['OTAFIX2.4.12','v0.11.0-OTAFIX2.4.12','0.9.2-OTAFIX2.4.12',' > v0.11.0-OTAFIX2.4.12 ', 'otafix2.4.12']){
    assert.deepEqual(assess(value),{status:'current',reported:value.trim().replace(/^>\s*/,''),installedVersion:latest,latestVersion:latest,offerUpdate:false},value);
  }
  assert.equal(assess('v99.99.99-OTAFIX2.4.11').status,'older');
  assert.equal(assess('v0.1.0-OTAFIX2.4.13').status,'newer');
});

test('older numeric OTAFIX versions offer the verified stable update',()=>{
  for(const [value,version]of [['OTAFIX2.4.9','2.4.9'],['v0.11.0-OTAFIX2.4.11','2.4.11'],['v0.9.2-OTAFIX2.2-BP1.3','2.2.0'],['OTAFIX2.4.11-preview.7','2.4.11'],['OTAFIX2.3.255-custom+build.abc','2.3.255']]){
    const result=assess(value);
    assert.equal(result.status,'older',value);assert.equal(result.offerUpdate,true,value);assert.equal(result.installedVersion,version,value);assert.equal(result.reported,value);
  }
});

test('same-version qualified previews offer stable; unknown custom suffixes remain manual',()=>{
  for(const value of ['OTAFIX2.4.12-preview.1','v0.11.0-OTAFIX2.4.12-preview.12','OTAFIX2.4.12-preview.254']){
    const result=assess(value);assert.equal(result.status,'preview',value);assert.equal(result.offerUpdate,true,value);assert.equal(result.reported,value);
  }
  for(const suffix of ['-preview','-preview.0','-preview.255','-preview.999','-preview.1-extra','-preview.1+build.abc','-BP1.3','-dirty-test-version-0x02040cff','+build.abcdef','_vendor']){
    const result=assess('OTAFIX2.4.12'+suffix);assert.equal(result.status,'custom',suffix);assert.equal(result.offerUpdate,false,suffix);assert.equal(result.installedVersion,latest,suffix);assert.equal(result.reported,'OTAFIX2.4.12'+suffix);
  }
});

test('newer stable or preview bootloaders do not offer an automatic downgrade',()=>{
  for(const value of ['OTAFIX2.4.13','OTAFIX2.4.13-preview.1','OTAFIX2.5.0-custom','OTAFIX3.0.0']){
    const result=assess(value);assert.equal(result.status,'newer',value);assert.equal(result.offerUpdate,false,value);
  }
});

test('a trailing numeric zero normalizes without treating a fourth component as a preview',()=>{
  assert.equal(assess('OTAFIX2.4.12.0').status,'current');
  assert.equal(assess('v0.11.0-OTAFIX2.4.12.0-preview.4').status,'preview');
  assert.equal(assess('OTAFIX2.4.11.0').installedVersion,'2.4.11');
  assert.equal(assess('OTAFIX2.4.12.1').status,'unknown');
});

test('stock, base-only, empty, unavailable and unrelated dotted versions remain unknown',()=>{
  for(const value of [null,undefined,42,{},'', 'unknown','unsupported','Error: unsupported','0.11.0 (base)','v0.11.0','0.9.2-Seeed','1.00','MeshCore v1.18.0.2','TinyUSB 0.12.0','SoftDevice 7.3.0','UF2 Bootloader v0.11.0-OTAFIX2.4.12']){
    const result=assess(value);assert.equal(result.status,'unknown',String(value));assert.equal(result.installedVersion,null,String(value));assert.equal(result.latestVersion,latest);assert.equal(result.offerUpdate,false);
  }
});

test('malformed, conflicting or multiline responses never become version evidence',()=>{
  for(const value of ['get bootloader.ver\r\n> OTAFIX2.4.12','OTAFIX2.4.12\nOTAFIX2.4.11','OTAFIX2.4.12\r','OTAFIX2.4.12\0','OTAFIX2.4.12\x1b[0m','>> OTAFIX2.4.12','OTAFIX2.4.12-OTAFIX2.4.11','notOTAFIX2.4.12','OTAFIX 2.4.12','OTAFIX2.x.12','OTAFIX2.4.','OTAFIX02.4.12','OTAFIX2.04.12','OTAFIX2.4.012','OTAFIX256.4.12','OTAFIX2.4.256','OTAFIX2.4.12-','OTAFIX2.4.12+','OTAFIX2.4.12_','OTAFIX2.4.12junk','OTAFIX2.4.12-<script>','OTAFIX2.4.12'+'a'.repeat(256)]){
    const result=assess(value);assert.equal(result.status,'unknown',JSON.stringify(value));assert.equal(result.installedVersion,null,JSON.stringify(value));assert.equal(result.offerUpdate,false,JSON.stringify(value));
  }
});

test('invalid or prerelease catalog versions cannot authorize a recommendation',()=>{
  for(const value of [null,undefined,42,'','2.4','v2.4.12','OTAFIX2.4.12','2.4.12-preview.1','2.4.12+build','2.4.12.0','02.4.12','2.4.256',' 2.4.12 ','2.4.12\n']){
    const result=assessBootloaderVersion('v0.11.0-OTAFIX2.4.9',value);assert.equal(result.status,'unknown',JSON.stringify(value));assert.equal(result.latestVersion,null,JSON.stringify(value));assert.equal(result.installedVersion,'2.4.9');assert.equal(result.offerUpdate,false);
  }
});

test('version comparison is numeric and bounded rather than lexical',()=>{
  assert.equal(assessBootloaderVersion('OTAFIX2.4.9','2.4.12').status,'older');
  assert.equal(assessBootloaderVersion('OTAFIX2.4.100','2.4.12').status,'newer');
  assert.equal(assessBootloaderVersion('OTAFIX2.12.0','2.4.255').status,'newer');
  assert.equal(assessBootloaderVersion('OTAFIX3.0.0','2.255.255').status,'newer');
  assert.equal(assessBootloaderVersion('OTAFIX0.0.0','0.0.1').status,'older');
});

test('the assessment is pure, returns a fresh result and performs no USB or network action',()=>{
  const a=assess('OTAFIX2.4.12'),b=assess('OTAFIX2.4.12');assert.notEqual(a,b);a.status='older';assert.equal(b.status,'current');
  assert.deepEqual(Object.keys(b),['status','reported','installedVersion','latestVersion','offerUpdate']);
});
