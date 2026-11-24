const MAP_HOME = 'https://global.meshmapper.net/';
const GEO_IP = 'https://get.geojs.io/v1/ip/geo.json';

export function lookupUrl(configured) {
  try {
    const url = new URL(configured);
    return url.protocol === 'https:' && url.pathname === '/nearby-scopes'
      && !url.username && !url.password && !url.search && !url.hash ? url.href : null;
  } catch {
    return null;
  }
}

function coordinate(value, limit) {
  const n = typeof value === 'number' || (typeof value === 'string' && value.trim()) ? Number(value) : NaN;
  return Number.isFinite(n) && Math.abs(n) <= limit ? Number(n.toFixed(2)) : null;
}

export function mapUrl(map, location) {
  const regional = typeof map === 'string' && /^[a-z0-9]{2,16}$/.test(map) && map !== 'global';
  const url = new URL(regional ? `https://${map}.meshmapper.net/` : MAP_HOME);
  const lat = coordinate(location?.lat, 90), lon = coordinate(location?.lon, 180);
  if (lat !== null && lon !== null) {
    url.searchParams.set('lat', lat);
    url.searchParams.set('lon', lon);
    url.searchParams.set('zoom', '10');
  }
  if (regional) url.searchParams.set('l', 'rep.sc');
  return url.href;
}

export async function estimateIpLocation(fetcher = fetch) {
  const response = await fetcher(GEO_IP, {
    credentials: 'omit', cache: 'no-store', redirect: 'error', referrerPolicy: 'no-referrer',
    signal: AbortSignal.timeout(7000),
  });
  if (!response.ok) throw Error('IP location unavailable');
  const data = await response.json();
  const lat = coordinate(data?.latitude, 90), lon = coordinate(data?.longitude, 180);
  if (lat === null || lon === null || (lat === 0 && lon === 0)) throw Error('IP location unavailable');
  const label = [...new Set([data.city, data.region, data.country]
    .filter(part => typeof part === 'string' && part.trim() && part.length <= 80).map(part => part.trim()))].join(', ');
  return { lat, lon, label };
}

export function initNearbyScopes(doc, endpoint, fetcher = fetch) {
  const el = name => doc.getElementById(`nearby-scopes${name ? `-${name}` : ''}`);
  const panel = el('');
  if (!panel) return;
  const reveal = () => { if (doc.defaultView.location.hash === '#nearby-scopes') panel.open = true; };
  doc.defaultView.addEventListener('hashchange', reveal);
  reveal();
  el('fallback').hidden = Boolean(endpoint);
  el('radius-field').hidden = !endpoint;
  const controls = [el('ip'), el('search'), el('radius')];
  const status = el('status');
  let busy = false, ipEstimate;

  function link(label, map, location) {
    const node = doc.createElement('a');
    node.href = mapUrl(map, location);
    node.target = '_blank'; node.rel = 'noopener noreferrer'; node.textContent = label;
    return node;
  }

  function areaLabel(location, mode) {
    const label = location.label || `${location.lat}, ${location.lon}`;
    return mode === 'ip' ? `Approximate IP location: ${label}.` : `Search location: ${label}.`;
  }

  function showMapOnly(location, mode) {
    status.textContent = `${areaLabel(location, mode)} Scope results aren’t available here.`;
    el('maps').replaceChildren(link('Open MeshMapper at this location', null, location));
    el('table').hidden = true;
    el('results').hidden = false;
    el('fallback').hidden = true;
  }

  function render(data, mode) {
    const { location, regions, scopes } = data;
    const area = areaLabel(location, mode);
    const window = `${data.radius} km radius, last ${data.days} days.`;
    const result = scopes.length
      ? `${data.scopeCount} observed scope${data.scopeCount === 1 ? '' : 's'}${data.scopeCount > scopes.length ? ` (showing ${scopes.length})` : ''}.`
      : 'No recent forwarding observed in available data.';
    status.textContent = [area, window, result, data.partial ? 'Some regional data is temporarily unavailable.' : ''].filter(Boolean).join(' ');
    const maps = el('maps');
    maps.replaceChildren(doc.createTextNode(regions.length ? 'MeshMapper: ' : 'No matching MeshMapper boundary. '));
    (regions.length ? regions : [{ name: 'Open MeshMapper at this location' }]).forEach((region, i) => {
      if (i) maps.append(', ');
      maps.append(link(region.code ? `${region.name} (${region.code})` : region.name, region.map, location));
    });
    const date = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' });
    el('rows').replaceChildren(...scopes.map(({ name, repeaters, lastSeen }) => {
      const row = doc.createElement('tr');
      for (const value of [name, repeaters, date.format(lastSeen * 1000)]) {
        const cell = row.insertCell(); cell.textContent = String(value);
      }
      return row;
    }));
    el('table').hidden = scopes.length === 0;
    el('results').hidden = false;
    el('fallback').hidden = true;
  }

  async function find(mode) {
    if (busy) return;
    busy = true;
    controls.forEach(control => { control.disabled = true; });
    status.textContent = endpoint ? 'Looking up nearby scopes...' : 'Looking up approximate location...';
    el('results').hidden = true;
    try {
      const manual = mode === 'manual' ? {
        lat: coordinate(el('lat').valueAsNumber, 90), lon: coordinate(el('lon').valueAsNumber, 180),
      } : null;
      if (manual && (manual.lat === null || manual.lon === null)) throw Error('Invalid coordinates');
      if (endpoint) {
        try {
          const response = await fetcher(endpoint, {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ mode, radius: Number(el('radius').value), ...manual }),
            credentials: 'omit', cache: 'no-store', redirect: 'error', signal: AbortSignal.timeout(10_000),
          });
          if (response.ok) { render(await response.json(), mode); return; }
        } catch {
          // The map link does not depend on the optional forwarding-data service.
        }
      }
      showMapOnly(manual ?? (ipEstimate ??= await estimateIpLocation(fetcher)), mode);
    } catch {
      status.textContent = mode === 'ip' ? 'IP location unavailable. Enter coordinates instead.' : 'Enter valid latitude and longitude.';
      if (mode === 'ip') {
        el('form').parentElement.open = true;
        el('lat').focus();
      }
      el('maps').replaceChildren(link('Open MeshMapper'));
      el('table').hidden = true;
      el('results').hidden = false;
    } finally {
      busy = false;
      controls.forEach(control => { control.disabled = false; });
    }
  }

  el('ip').addEventListener('click', () => void find('ip'));
  el('form').addEventListener('submit', event => { event.preventDefault(); void find('manual'); });
}

if (typeof document !== 'undefined') initNearbyScopes(document, lookupUrl(import.meta.env?.VITE_NEARBY_SCOPES_URL));
