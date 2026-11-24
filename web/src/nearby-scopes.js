const MAP_HOME = 'https://meshmapper.net/';

export function lookupUrl(configured) {
  try {
    const url = new URL(configured);
    return url.protocol === 'https:' && url.pathname === '/nearby-scopes'
      && !url.username && !url.password && !url.search && !url.hash ? url.href : null;
  } catch {
    return null;
  }
}

function mapUrl(map) {
  return typeof map === 'string' && /^[a-z0-9]{2,16}$/.test(map) ? `https://${map}.meshmapper.net/` : MAP_HOME;
}

export function initNearbyScopes(doc, endpoint, fetcher = fetch) {
  const el = name => doc.getElementById(`nearby-scopes${name ? `-${name}` : ''}`);
  const panel = el('');
  if (!panel) return;
  const reveal = () => { if (doc.defaultView.location.hash === '#nearby-scopes') panel.open = true; };
  doc.defaultView.addEventListener('hashchange', reveal);
  reveal();
  if (!endpoint) return;
  el('fallback').hidden = true;
  el('controls').hidden = false;
  const controls = [el('ip'), el('search'), el('radius')];
  const status = el('status');
  let busy = false;

  function render(data, mode) {
    const { location, regions, scopes } = data;
    const label = location.label || `${location.lat}, ${location.lon}`;
    const area = mode === 'ip' ? `Approximate IP location: ${label}.` : `Search location: ${label}.`;
    const window = `${data.radius} km radius, last ${data.days} days.`;
    const result = scopes.length
      ? `${data.scopeCount} observed scope${data.scopeCount === 1 ? '' : 's'}${data.scopeCount > scopes.length ? ` (showing ${scopes.length})` : ''}.`
      : 'No recent forwarding observed in available data.';
    status.textContent = [area, window, result, data.partial ? 'Some regional data is temporarily unavailable.' : ''].filter(Boolean).join(' ');
    const maps = el('maps');
    maps.replaceChildren(doc.createTextNode(regions.length ? 'MeshMapper: ' : 'No matching MeshMapper boundary. '));
    (regions.length ? regions : [{ name: 'Open MeshMapper' }]).forEach((region, i) => {
      if (i) maps.append(', ');
      const link = doc.createElement('a');
      link.href = mapUrl(region.map);
      link.target = '_blank'; link.rel = 'noopener noreferrer';
      link.textContent = region.code ? `${region.name} (${region.code})` : region.name;
      maps.append(link);
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
  }

  async function find(mode) {
    if (busy) return;
    busy = true;
    controls.forEach(control => { control.disabled = true; });
    status.textContent = 'Looking up nearby scopes...';
    el('results').hidden = true;
    try {
      const body = { mode, radius: Number(el('radius').value) };
      if (mode === 'manual') {
        body.lat = Number(el('lat').valueAsNumber.toFixed(2));
        body.lon = Number(el('lon').valueAsNumber.toFixed(2));
      }
      const response = await fetcher(endpoint, {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
        credentials: 'omit', cache: 'no-store', redirect: 'error', signal: AbortSignal.timeout(12_000),
      });
      if (response.status === 422 && mode === 'ip') {
        status.textContent = 'IP location unavailable. Enter coordinates instead.';
        el('form').parentElement.open = true;
        el('lat').focus();
      } else if (response.ok) {
        render(await response.json(), mode);
      } else {
        throw new Error('Lookup failed');
      }
    } catch {
      status.textContent = 'Nearby scope data is unavailable right now.';
      el('maps').replaceChildren();
      const link = doc.createElement('a');
      link.href = MAP_HOME; link.target = '_blank'; link.rel = 'noopener noreferrer';
      link.textContent = 'Open MeshMapper';
      el('maps').append(link);
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
