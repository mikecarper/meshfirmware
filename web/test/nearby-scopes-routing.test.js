import test from 'node:test';
import assert from 'node:assert/strict';
import { initNearbyScopes } from '../src/nearby-scopes.js';
import { requestIpLocation } from '../src/ip-location.js';

const pnwConfig = 'https://gessaman.com/meshcore/regions/config/';
const workerUrl = 'https://lookup.test/nearby-scopes';
const seattle = { lat: 47.6062, lon: -122.3321 };
const sanFrancisco = { lat: 37.7749, lon: -122.4194 };

function element(tagName = '') {
  const listeners = new Map();
  return {
    tagName, children: [], value: '', hidden: true, disabled: false,
    addEventListener(name, listener) { listeners.set(name, listener); },
    dispatch(name) { listeners.get(name)({ preventDefault() {} }); },
    append(...nodes) { this.children.push(...nodes); },
    replaceChildren(...nodes) { this.children = nodes; },
    insertCell() {
      const cell = element('td');
      this.append(cell);
      return cell;
    },
  };
}

function panel(endpoint, fetcher) {
  const elements = new Map();
  let intersect, observed;
  function el(name = '') {
    if (!elements.has(name)) elements.set(name, element());
    return elements.get(name);
  }
  el('radius').value = '50';
  el('form').parentElement = element('details');
  el('lat').focus = () => {};
  const doc = {
    getElementById: id => el(id.slice('nearby-scopes'.length + 1)),
    defaultView: {
      location: { hash: '' },
      addEventListener() {},
      IntersectionObserver: class {
        constructor(callback) { intersect = callback; }
        observe(target) { observed = target; }
        disconnect() { intersect = null; }
      },
    },
    visibilityState: 'visible',
    addEventListener() {},
    removeEventListener() {},
    createElement: tag => element(tag),
    createTextNode: textContent => ({ textContent }),
  };
  el('controls').ownerDocument = doc;
  initNearbyScopes(doc, endpoint, fetcher);
  const settled = () => new Promise(resolve => setImmediate(resolve));
  return {
    el,
    links: () => el('maps').children.filter(node => node.tagName === 'a'),
    async useCoordinates({ lat, lon }) {
      el('lat').value = String(lat);
      el('lon').value = String(lon);
      el('lat').valueAsNumber = lat;
      el('lon').valueAsNumber = lon;
      el('form').dispatch('submit');
      await settled();
    },
    async useIp() {
      el('ip').dispatch('click');
      await settled();
    },
    async inViewport(isIntersecting) {
      intersect?.([{ target: observed, isIntersecting, intersectionRatio: isIntersecting ? 1 : 0 }]);
      await settled();
    },
  };
}

function workerResult(location, code, scope) {
  return Response.json({
    location, radius: 50, days: 7, partial: false,
    regions: [{ code, name: code, map: code.toLowerCase() }],
    scopeCount: 1,
    scopes: [{ name: scope, repeaters: 2, lastSeen: 1_766_000_000 }],
  });
}

function assertPnwLink(ui) {
  const links = ui.links();
  assert.deepEqual(links.map(link => link.href), [pnwConfig]);
  assert.equal(links[0].target, '_blank');
  assert.ok(links[0].rel.split(' ').includes('noreferrer'));
  assert.match(ui.el('maps').children.map(node => node.textContent).join(' '), /city or postal code/i);
  assert.equal(ui.el('results').hidden, false);
}

test('covered coordinates link to the PNW configurator without a forwarding service', async () => {
  const requests = [];
  const ui = panel(null, async url => { requests.push(url); });
  await ui.useCoordinates(seattle);
  assertPnwLink(ui);
  assert.equal(ui.el('table').hidden, true);
  await ui.useCoordinates(sanFrancisco);
  assert.ok(ui.links().some(link => new URL(link.href).hostname.endsWith('.meshmapper.net')));
  assert.ok(ui.links().every(link => link.href !== pnwConfig));
  assert.deepEqual(requests, []);
});

test('PNW location from the forwarding service replaces the map link and preserves observations', async () => {
  const ui = panel(workerUrl, async (url, request) => {
    assert.equal(url, workerUrl);
    const body = JSON.parse(request.body);
    if (body.mode === 'manual') {
      assert.deepEqual(body, { mode: 'manual', radius: 50, lat: 47.61, lon: -122.33 });
    } else {
      assert.deepEqual(body, { mode: 'ip', radius: 50 });
    }
    return workerResult(seattle, 'SEA', 'sea');
  });
  for (const lookup of [() => ui.useCoordinates(seattle), () => ui.useIp()]) {
    await lookup();
    assertPnwLink(ui);
    assert.equal(ui.el('table').hidden, false);
    assert.equal(ui.el('rows').children[0].children[0].textContent, 'sea');
  }
});

test('approximate IP location works for the PNW recommendation without forwarding data', async () => {
  const ui = panel(null, async url => {
    assert.equal(url, 'https://get.geojs.io/v1/ip/geo.json');
    return Response.json({ latitude: 48.4284, longitude: -123.3656, country_code: 'CA' });
  });
  await ui.useIp();
  assertPnwLink(ui);
  assert.equal(ui.el('table').hidden, true);
});

test('entering the viewport starts one approximate lookup and fills both coordinate fields', async () => {
  let requests = 0;
  const ui = panel(null, async () => {
    requests++;
    return Response.json({ latitude: 47.6062, longitude: -122.3321, country_code: 'US' });
  });
  await ui.inViewport(false);
  assert.equal(requests, 0);
  await ui.inViewport(true);
  assert.equal(ui.el('lat').value, '47.61');
  assert.equal(ui.el('lon').value, '-122.33');
  assertPnwLink(ui);
  await ui.inViewport(false);
  await ui.inViewport(true);
  assert.equal(requests, 1);
});

test('automatic lookup preserves manual coordinates entered before or during the request', async () => {
  let finishLookup;
  const ui = panel(null, () => new Promise(resolve => { finishLookup = resolve; }));
  await ui.inViewport(true);
  ui.el('lat').value = '45';
  ui.el('lat').dispatch('input');
  finishLookup(Response.json({ latitude: 47.6, longitude: -122.3, country_code: 'US' }));
  await ui.inViewport(true);
  assert.equal(ui.el('lat').value, '45');
  assert.equal(ui.el('lon').value, '');

  let requests = 0;
  const prefilled = panel(null, async () => {
    requests++;
    return Response.json({ latitude: 47.6, longitude: -122.3, country_code: 'US' });
  });
  prefilled.el('lat').value = '45';
  prefilled.el('lon').value = '-123';
  await prefilled.inViewport(true);
  assert.equal(requests, 0);
  await prefilled.useIp();
  assert.equal(prefilled.el('lat').value, '47.6');
  assert.equal(prefilled.el('lon').value, '-122.3');
});

test('nearby scopes reuses the preset location and requests only forwarding observations', async () => {
  const requests = [];
  let finishLookup;
  const fetcher = (url, config) => {
    requests.push([url, config.body]);
    if (url === workerUrl) return workerResult(seattle, 'SEA', 'sea');
    return new Promise(resolve => { finishLookup = resolve; });
  };
  const presetLocation = requestIpLocation(fetcher);
  const ui = panel(workerUrl, fetcher);
  await ui.inViewport(true);
  finishLookup(Response.json({ latitude: 47.6062, longitude: -122.3321, country_code: 'US' }));
  await presetLocation;
  await ui.inViewport(true);
  assert.deepEqual(requests, [
    ['https://get.geojs.io/v1/ip/geo.json', undefined],
    [workerUrl, JSON.stringify({ mode: 'manual', radius: 50, lat: 47.61, lon: -122.33 })],
  ]);
  assert.equal(ui.el('lat').value, '47.61');
  assert.equal(ui.el('lon').value, '-122.33');
  assert.equal(ui.el('table').hidden, false);
  assertPnwLink(ui);
});
