import assert from 'node:assert/strict';
import test from 'node:test';
import { requestIpLocation, subscribeIpLocation, whenVisible } from '../src/ip-location.js';

test('location consumers share a rounded estimate and reuse it without a second IP lookup', async () => {
  const fetcher = () => assert.fail('The in-progress scopes lookup should supply the location');
  let finish;
  const resolver = () => new Promise(resolve => { finish = resolve; });
  const scopes = requestIpLocation(fetcher, resolver);
  const presets = requestIpLocation(fetcher);
  assert.equal(scopes, presets);
  const updates = [];
  subscribeIpLocation(location => updates.push(location), fetcher);
  await Promise.resolve();
  finish({ lat: 47.1234, lon: -122.9876, label: 'Olympia, Washington, US' });
  const location = await presets;
  assert.deepEqual(location, { lat: 47.12, lon: -122.99, label: 'Olympia, Washington, US', countryCode: 'US' });
  assert.deepEqual(updates, [location]);
  subscribeIpLocation(current => updates.push(current), fetcher);
  assert.deepEqual(updates, [location, location]);
  assert.equal(await requestIpLocation(fetcher), location);
});

test('a failed estimate can be retried without keeping a failed promise in the session', async () => {
  let calls = 0;
  const fetcher = async () => {
    if (++calls === 1) return new Response('', { status: 503 });
    return Response.json({ latitude: '49.28', longitude: '-123.12', country_code: 'CA' });
  };
  await assert.rejects(requestIpLocation(fetcher), /unavailable/);
  assert.equal((await requestIpLocation(fetcher)).countryCode, 'CA');
  assert.equal(calls, 2);
});

test('visibility schedules a single lookup in the foreground viewport', () => {
  let intersect, onVisibility, observed, disconnects = 0, calls = 0;
  const doc = {
    visibilityState: 'hidden',
    defaultView: {
      IntersectionObserver: class {
        constructor(callback) { intersect = callback; }
        observe(element) { observed = element; }
        disconnect() { disconnects++; }
      },
    },
    addEventListener(name, listener) { assert.equal(name, 'visibilitychange'); onVisibility = listener; },
    removeEventListener(name, listener) {
      assert.equal(name, 'visibilitychange');
      assert.equal(listener, onVisibility);
      onVisibility = null;
    },
  };
  const element = { ownerDocument: doc };
  whenVisible(element, () => { calls++; });
  assert.equal(observed, element);
  intersect([{ target: element, isIntersecting: true, intersectionRatio: 0 }]);
  doc.visibilityState = 'visible';
  onVisibility();
  assert.equal(calls, 0);
  doc.visibilityState = 'hidden';
  intersect([{ target: element, isIntersecting: true, intersectionRatio: 0.5 }]);
  assert.equal(calls, 0);
  doc.visibilityState = 'visible';
  onVisibility();
  intersect([{ target: element, isIntersecting: true, intersectionRatio: 1 }]);
  assert.equal(calls, 1);
  assert.equal(disconnects, 1);
  assert.equal(onVisibility, null);
});
