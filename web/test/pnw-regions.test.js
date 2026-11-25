import assert from 'node:assert/strict';
import test from 'node:test';
import { PNW_CONFIG_URL, pnwRegionSuggestion } from '../src/pnw-regions.js';

test('uses the PNW configurator in its published metro and inland areas', () => {
  assert.equal(PNW_CONFIG_URL, 'https://gessaman.com/meshcore/regions/config/');
  assert.deepEqual(pnwRegionSuggestion({ lat: 47.6062, lon: -122.3321 }),
    { tag: 'sea', label: 'Seattle / Tacoma / Bellevue' });
  for (const [lat, lon, tag] of [
    [45.6387, -122.6615, 'pdx'], // Vancouver, WA is part of cross-border Portland.
    [42.3265, -122.8756, 'mfr'], // Southern Oregon.
    [46.7298, -117.1817, 'puw'], // WA side of Palouse.
    [46.7324, -117.0002, 'lws'], // ID side of Palouse.
    [43.615, -116.2023, 'boi'],
    [48.1919, -114.3168, 'fca'],
  ]) assert.equal(pnwRegionSuggestion({ lat, lon })?.tag, tag);
});

test('applies the hard country border within overlapping Canadian and US areas', () => {
  assert.equal(pnwRegionSuggestion({ lat: 48.7519, lon: -122.4787 })?.tag, 'bli');
  assert.equal(pnwRegionSuggestion({ lat: 48.4284, lon: -123.3656 })?.tag, 'southisland');
  assert.equal(pnwRegionSuggestion({ lat: 49.2827, lon: -123.1207, countryCode: 'CA' })?.tag, 'swbc');
  // This approximate IP estimate sits near Canadian centers but is known to be in the US.
  assert.equal(pnwRegionSuggestion({ lat: 48.4284, lon: -123.3656, countryCode: 'US' }), null);
});

test('requires a valid fix inside a published local radius', () => {
  for (const location of [
    null,
    { lat: 47.6, lon: NaN },
    { lat: '47.6', lon: -122.33 },
    { lat: 47.6, lon: -181 },
    { lat: 47.6, lon: -122.33, countryCode: 'AU' },
    { lat: 48.1181, lon: -123.4307 }, // Port Angeles: nearby Canadian seeds are excluded.
    { lat: 46.8721, lon: -113.994 }, // Missoula: Montana coverage is Flathead Valley.
    { lat: 40.5865, lon: -122.3917 }, // Redding.
  ]) assert.equal(pnwRegionSuggestion(location), null);
});
