import assert from 'node:assert/strict';
import test from 'node:test';
import { lookup, nearby, point, refresh, snapshot } from '../../services/nearby-scopes/worker.mjs';
import { estimateIpLocation, lookupUrl, mapUrl } from '../src/nearby-scopes.js';

const now = 1_795_510_000;
const day = 86400;
const origin = 'https://mikecarper.github.io';
const endpoint = 'https://lookup.test/nearby-scopes';
const area = {
  type: 'FeatureCollection', features: [{
    properties: { code: 'SEA', name: 'Puget Sound' },
    geometry: { type: 'Polygon', coordinates: [[[-124, 46], [-121, 46], [-121, 49], [-124, 49], [-124, 46]]] },
  }],
};
const seen = (scope, observed_at = now - 3600) => ({ scope, observed_at, proof: 'multibyte' });
const site = (id, scopes, fields = {}) => ({
  hex_id: id.repeat(64), lat: 47, lon: -122.5, enabled: 1, scopes, ...fields,
});
const rows = [
  site('a', [seen('oly'), { scope: 'reported', reported_at: now }, seen('stale', now - 8 * day),
    seen('future', now + 1), { scope: 'unproved', observed_at: now }, seen('*')], { default_scope: 'default' }),
  site('b', [seen('oly', now - 1800), { ...seen('w-wa'), proof: 'floor' }], { lat: 47.12 }),
  site('c', [seen('far')], { lat: 49 }),
  site('d', [seen('missing')], { lat: 0, lon: 0 }),
  site('e', [seen('ambiguous')], { enabled: 2 }),
  site('f', [seen('mobile')], { is_carpeater: 1 }),
];

test('ranks unique nearby repeaters by recent observed forwarding only', () => {
  const data = snapshot(area, rows, now);
  const duplicate = snapshot(area, [site('a', [seen('oly', now - 900)])], now);
  const found = nearby([['pnw', data], ['sea', duplicate]], point(47, -122.5), 25, now);
  assert.deepEqual(found.regions, [{ code: 'SEA', name: 'Puget Sound', map: 'sea' }]);
  assert.deepEqual(found.scopes, [
    { name: 'oly', repeaters: 2, lastSeen: now - 900 },
    { name: 'w-wa', repeaters: 1, lastSeen: now - 3600 },
  ]);
  assert.equal(found.scopeCount, 2);
  assert.deepEqual(nearby([['pnw', data]], point(47, -122.5), 25, now + 7 * day).scopes, []);
});

test('boundary membership handles holes, the date line, and an undrawn zone', () => {
  const geo = structuredClone(area);
  geo.features[0].geometry.coordinates.push([[-123, 47], [-122, 47], [-122, 48], [-123, 48], [-123, 47]]);
  geo.features.push({ properties: { code: 'NUL', name: 'Undrawn' }, geometry: null });
  geo.features.push({ properties: { code: 'DAT', name: 'Date line' }, geometry: {
    type: 'Polygon', coordinates: [[[179, 0], [-179, 0], [-179, 2], [179, 2], [179, 0]]],
  } });
  const feeds = [['pnw', snapshot(geo, [], now)]];
  assert.equal(nearby(feeds, point(47.5, -122.5), 25, now).regions.length, 0);
  assert.equal(nearby(feeds, point(46, -122.5), 25, now).regions[0].code, 'SEA');
  assert.equal(nearby(feeds, point(1, -179.9), 25, now).regions[0].code, 'DAT');
  assert.equal(nearby(feeds, point(1, 0), 25, now).regions.length, 0);
  assert.equal(point('', 0), null);
  assert.equal(point(0, 181), null);
});

function request(body, { method = 'POST', requestOrigin = origin, cf, url = endpoint } = {}) {
  const req = new Request(url, { method, headers: { Origin: requestOrigin, 'Content-Type': 'application/json' },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
  if (cf) Object.defineProperty(req, 'cf', { value: cf });
  return req;
}

test('IP and manual lookups use cached records, never a public upstream proxy', async () => {
  const env = { MESHMAPPER_MAPS: 'pnw,other', SCOPE_SNAPSHOTS: { get: async key =>
    key.endsWith(':pnw') ? snapshot(area, rows, now) : null } };
  const res = await lookup(request({ mode: 'ip', radius: 50, lat: 0, lon: 0 }, {
    cf: { latitude: '47.005', longitude: '-122.5', city: 'Olympia', region: 'Washington' },
  }), env, now);
  assert.equal(res.status, 200);
  assert.equal(res.headers.get('Access-Control-Allow-Origin'), origin);
  assert.equal(res.headers.get('Cache-Control'), 'no-store');
  const json = await res.json();
  assert.equal(json.location.label, 'Olympia, Washington');
  assert.equal(json.partial, true);
  assert.equal(json.scopes[0].name, 'oly');
  assert.ok(!JSON.stringify(json).includes('a'.repeat(64)));
  const manual = await lookup(request({ mode: 'manual', radius: 25, lat: 0, lon: 10 }), env, now);
  assert.equal(manual.status, 200);
  assert.deepEqual((await manual.json()).scopes, []);
  assert.equal((await lookup(request({ mode: 'ip', radius: 50 }), env, now)).status, 422);
  assert.equal((await lookup(request({ mode: 'manual', radius: 25, lat: 47, lon: -122.5 }), env, now + 2 * day)).status, 503);
});

test('accepts only bounded JSON lookups from the configured site', async () => {
  const env = {};
  const preflight = await lookup(request(undefined, { method: 'OPTIONS' }), env, now);
  assert.equal(preflight.status, 204);
  assert.equal(preflight.headers.get('Access-Control-Allow-Headers'), 'Content-Type');
  const blocked = await lookup(request(undefined, { method: 'OPTIONS', requestOrigin: 'https://other.test' }), env, now);
  assert.equal(blocked.status, 403);
  assert.equal(blocked.headers.get('Access-Control-Allow-Origin'), null);
  assert.equal((await lookup(request(undefined, { method: 'GET' }), env, now)).status, 405);
  assert.equal((await lookup(request({ mode: 'ip', radius: 50, extra: 'a'.repeat(300) }), env, now)).status, 400);
  assert.equal((await lookup(request({ mode: 'manual', radius: 25, lat: false, lon: 20 }), env, now)).status, 400);
});

test('scheduled refresh uses only approved endpoints and preserves a good snapshot on failure', async () => {
  const saved = new Map();
  const env = { MESHMAPPER_MAPS: 'pnw,https://elsewhere.test', MESHMAPPER_API_KEY: 'test-server-only',
    SCOPE_SNAPSHOTS: { put: async (key, value) => saved.set(key, value) } };
  const called = [];
  await refresh(env, { now, fetcher: async (url, options) => {
    called.push(url);
    assert.deepEqual(options.headers, { 'X-API-Key': 'test-server-only' });
    assert.equal(options.redirect, 'error');
    return Response.json(url.endsWith('/get_geojson.php') ? area : rows);
  } });
  assert.deepEqual(called, ['https://pnw.meshmapper.net/get_geojson.php', 'https://pnw.meshmapper.net/get_repeaters.php']);
  const previous = saved.get('meshmapper:v1:pnw');
  assert.ok(previous && !previous.includes('test-server-only'));
  await assert.rejects(refresh(env, { now: now + 10, fetcher: async () => new Response(null, { status: 429 }) }));
  assert.equal(saved.get('meshmapper:v1:pnw'), previous);
});

test('flasher lookup accepts only the configured HTTPS service path', () => {
  assert.equal(lookupUrl(endpoint), endpoint);
  for (const invalid of [undefined, '', 'javascript:alert(1)', `http://${endpoint.slice(8)}`,
    `${endpoint}?key=test`, 'https://user:password@lookup.test/nearby-scopes', 'https://lookup.test/']) {
    assert.equal(lookupUrl(invalid), null);
  }
});

test('IP location works independently of the optional scopes endpoint', async () => {
  const at = await estimateIpLocation(async (url, options) => {
    assert.equal(url, 'https://get.geojs.io/v1/ip/geo.json');
    assert.equal(options.credentials, 'omit');
    assert.equal(options.referrerPolicy, 'no-referrer');
    return Response.json({ latitude: '47.12345', longitude: '-122.56789', city: 'Olympia',
      region: 'Washington', country: 'United States', ip: '192.0.2.1' });
  });
  assert.deepEqual(at, { lat: 47.12, lon: -122.57, label: 'Olympia, Washington, United States' });
  await assert.rejects(estimateIpLocation(async () => Response.json({ latitude: '', longitude: '0' })));
  await assert.rejects(estimateIpLocation(async () => Response.json({ latitude: 0, longitude: 0 })));
  await assert.rejects(estimateIpLocation(async () => new Response(null, { status: 429 })));
});

test('MeshMapper deep links center on coarse coordinates and enable scopes on regional maps', () => {
  const location = { lat: 47.12345, lon: -122.56789 };
  assert.equal(mapUrl('pnw', location), 'https://pnw.meshmapper.net/?lat=47.12&lon=-122.57&zoom=10&l=rep.sc');
  assert.equal(mapUrl(null, location), 'https://global.meshmapper.net/?lat=47.12&lon=-122.57&zoom=10');
  assert.equal(mapUrl('example.net/path', location), mapUrl(null, location));
  assert.equal(mapUrl('global', location), mapUrl(null, location));
  assert.equal(mapUrl(null, { lat: null, lon: Infinity }), 'https://global.meshmapper.net/');
});
