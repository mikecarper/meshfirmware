import { meshMapperAirports } from './meshmapper-airports.js';
import { PNW_CONFIG_URL, pnwRegionSuggestion } from './pnw-regions.js';

const MAP_HOME = 'https://global.meshmapper.net/';
const GEO_IP = 'https://get.geojs.io/v1/ip/geo.json';
const AIRPORT_RADIUS_KM = 100;

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

export function airportMapSuggestion(location) {
  const lat = coordinate(location?.lat, 90), lon = coordinate(location?.lon, 180);
  if (lat === null || lon === null) return null;
  const radians = Math.PI / 180;
  let best = null;
  for (const [code, name, country, airportLat, airportLon, category] of meshMapperAirports) {
    if (location.countryCode && country !== location.countryCode) continue;
    const a = Math.sin((airportLat - lat) * radians / 2) ** 2
      + Math.cos(lat * radians) * Math.cos(airportLat * radians)
      * Math.sin((airportLon - lon) * radians / 2) ** 2;
    const km = 12742 * Math.asin(Math.sqrt(Math.min(1, a)));
    if (km > AIRPORT_RADIUS_KM) continue;
    const rank = category === 'large' ? 2 : 1;
    if (!best || rank > best.rank || (rank === best.rank && km < best.km)) best = { code, name, rank, km };
  }
  return best && { code: best.code, name: best.name, map: best.code.toLowerCase() };
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
  const countryCode = typeof data.country_code === 'string' && /^[A-Z]{2}$/.test(data.country_code) ? data.country_code : null;
  return { lat, lon, label, countryCode };
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

  function link(label, href) {
    const node = doc.createElement('a');
    node.href = href;
    node.target = '_blank'; node.rel = 'noopener noreferrer'; node.textContent = label;
    return node;
  }

  function areaLabel(location, mode) {
    const label = location.label || `${location.lat}, ${location.lon}`;
    return mode === 'ip' ? `Approximate IP location: ${label}.` : `Search location: ${label}.`;
  }

  function showRegionLinks(location, regions = []) {
    const maps = el('maps');
    const pnw = pnwRegionSuggestion(location);
    if (pnw) {
      maps.replaceChildren(
        doc.createTextNode(`Near ${pnw.label}. `),
        link('Open PNW repeater configurator', PNW_CONFIG_URL),
        doc.createTextNode(' Enter a city or postal code there for recommended regions.'),
      );
      return true;
    }
    if (regions.length) {
      maps.replaceChildren(doc.createTextNode('MeshMapper: '));
      regions.forEach((region, i) => {
        if (i) maps.append(', ');
        const label = region.code ? `${region.name} (${region.code})` : region.name;
        maps.append(link(label, mapUrl(region.map, location)));
      });
      return false;
    }
    const suggested = airportMapSuggestion(location);
    const global = link('Open global map', mapUrl(null, location));
    maps.replaceChildren(...(suggested ? [
      doc.createTextNode('Suggested by nearby airport: '),
      link(`${suggested.name} (${suggested.code}) scopes`, mapUrl(suggested.map, location)),
      doc.createTextNode(' · '),
      global,
    ] : [doc.createTextNode('No known airport map nearby. '), global]));
    return false;
  }

  function showMapOnly(location, mode) {
    const pnw = showRegionLinks(location);
    status.textContent = areaLabel(location, mode) + (pnw ? '' : ' Scope results aren’t available here.');
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
    showRegionLinks(location, regions);
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
    status.textContent = endpoint ? 'Looking up nearby scopes...' : 'Finding a regional link...';
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
      el('maps').replaceChildren(link('Open MeshMapper', MAP_HOME));
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
