const DAY = 86_400;
const RADII = [25, 50, 100];
const MAP_SLUG = /^[a-z0-9]{2,16}$/;
const ORIGIN = 'https://mikecarper.github.io';
const SNAPSHOT_MAX_AGE = 2 * DAY;
const WINDOW = 7 * DAY;

function number(value) {
  return typeof value === 'number' || (typeof value === 'string' && value.trim() !== '')
    ? Number(value) : NaN;
}

export function point(lat, lon) {
  lat = number(lat); lon = number(lon);
  return Number.isFinite(lat) && Number.isFinite(lon) && Math.abs(lat) <= 90 && Math.abs(lon) <= 180
    ? [lon, lat] : null;
}

function includesPoint(ring, [lon, lat]) {
  let inside = false;
  const relative = x => ((x - ring[0][0] + 540) % 360) - 180;
  const center = relative(lon);
  for (let i = 0, j = ring.length - 1; i < ring.length; j = i++) {
    const x = relative(ring[i][0]) - center, y = ring[i][1] - lat;
    const px = relative(ring[j][0]) - center, py = ring[j][1] - lat;
    if (Math.abs(x * py - px * y) < 1e-10 && x * px <= 0 && y * py <= 0) return true;
    if ((y > 0) !== (py > 0) && x + (px - x) * -y / (py - y) > 0) inside = !inside;
  }
  return inside;
}

function covers(rings, at) {
  return rings && includesPoint(rings[0], at) && !rings.slice(1).some(ring => includesPoint(ring, at));
}

function distanceKm([lon, lat], [otherLon, otherLat]) {
  const rad = Math.PI / 180;
  const a = Math.sin((otherLat - lat) * rad / 2) ** 2
    + Math.cos(lat * rad) * Math.cos(otherLat * rad) * Math.sin((otherLon - lon) * rad / 2) ** 2;
  return 12_742 * Math.asin(Math.sqrt(Math.min(1, a)));
}

export function snapshot(boundaries, repeaters, now) {
  if (boundaries?.type !== 'FeatureCollection' || !Array.isArray(boundaries.features)
      || !boundaries.features.length || !Array.isArray(repeaters)) throw new Error('Invalid MeshMapper response');
  const regions = boundaries.features.map(feature => {
    const { code, name } = feature.properties ?? {};
    const coordinates = feature.geometry?.coordinates ?? null;
    if (!/^[A-Z0-9]{3}$/.test(code) || typeof name !== 'string' || !name || name.length > 100
        || (feature.geometry !== null && (feature.geometry?.type !== 'Polygon' || !Array.isArray(coordinates)
        || !coordinates.length || !coordinates.every(ring => Array.isArray(ring) && ring.length >= 4
        && ring.every(pair => Array.isArray(pair) && point(pair[1], pair[0])))))) {
      throw new Error('Invalid MeshMapper region');
    }
    return { code, name, coordinates: coordinates?.map(ring => ring.map(([lon, lat]) => point(lat, lon))) ?? null };
  });
  const sites = [];
  for (const repeater of repeaters) {
    const at = point(repeater?.lat, repeater?.lon);
    if (!at || (at[0] === 0 && at[1] === 0) || repeater.enabled !== 1
        || repeater.is_carpeater === 1 || !/^[a-f0-9]{64}$/i.test(repeater.hex_id)) continue;
    const scopes = [];
    for (const entry of Array.isArray(repeater.scopes) ? repeater.scopes : []) {
      const { scope, observed_at: seen, proof } = entry ?? {};
      if (typeof scope !== 'string' || !scope.trim() || scope === '*' || scope.startsWith('#')
          || scope.length > 30 || /[\x00-\x1f\x7f]/.test(scope) || !Number.isSafeInteger(seen)
          || seen <= now - WINDOW || seen > now || !['multibyte', 'floor'].includes(proof)) continue;
      scopes.push([scope, seen]);
    }
    if (scopes.length) sites.push({ id: repeater.hex_id.toUpperCase(), at, scopes });
  }
  return { updated: now, regions, sites };
}

export function nearby(feeds, at, radius, now) {
  const regions = new Map();
  const evidence = new Map();
  for (const [map, data] of feeds) {
    for (const region of data.regions) {
      if (covers(region.coordinates, at)) regions.set(region.code, { code: region.code, name: region.name, map });
    }
    for (const site of data.sites) {
      if (distanceKm(at, site.at) > radius) continue;
      for (const [scope, seen] of site.scopes) {
        if (seen <= now - WINDOW || seen > now) continue;
        if (!evidence.has(scope)) evidence.set(scope, new Map());
        const sites = evidence.get(scope);
        sites.set(site.id, Math.max(sites.get(site.id) ?? 0, seen));
      }
    }
  }
  const scopes = [...evidence].map(([name, sites]) => ({
    name, repeaters: sites.size, lastSeen: [...sites.values()].reduce((max, seen) => Math.max(max, seen), 0),
  })).sort((a, b) => b.repeaters - a.repeaters || b.lastSeen - a.lastSeen || a.name.localeCompare(b.name));
  return { regions: [...regions.values()], scopeCount: scopes.length, scopes: scopes.slice(0, 50) };
}

function maps(env) {
  return [...new Set(String(env.MESHMAPPER_MAPS ?? '').split(',').map(slug => slug.trim().toLowerCase()))]
    .filter(slug => MAP_SLUG.test(slug)).slice(0, 12);
}

export async function refresh(env, { fetcher = fetch, now = Math.floor(Date.now() / 1000) } = {}) {
  const feeds = maps(env);
  if (!env.MESHMAPPER_API_KEY || !feeds.length) throw new Error('MeshMapper feed is not configured');
  let failed = 0;
  for (const slug of feeds) {
    try {
      const read = async file => {
        const response = await fetcher(`https://${slug}.meshmapper.net/${file}`, {
          headers: { 'X-API-Key': env.MESHMAPPER_API_KEY }, redirect: 'error', signal: AbortSignal.timeout(15_000),
        });
        if (!response.ok) throw new Error('MeshMapper feed unavailable');
        return response.json();
      };
      const boundaries = await read('get_geojson.php');
      const repeaters = await read('get_repeaters.php');
      await env.SCOPE_SNAPSHOTS.put(`meshmapper:v1:${slug}`, JSON.stringify(snapshot(boundaries, repeaters, now)),
        { expirationTtl: SNAPSHOT_MAX_AGE });
    } catch {
      failed++;
    }
  }
  if (failed) throw new Error(`Could not refresh ${failed} of ${feeds.length} MeshMapper feeds`);
}

async function readBody(request) {
  if (request.headers.get('Content-Type') !== 'application/json' || !request.body) return null;
  const reader = request.body.getReader();
  const decoder = new TextDecoder('utf-8', { fatal: true });
  let size = 0, value = '';
  try {
    for (;;) {
      const { done, value: bytes } = await reader.read();
      if (done) return JSON.parse(value + decoder.decode());
      size += bytes.byteLength;
      if (size > 256) {
        void reader.cancel().catch(() => {});
        return null;
      }
      value += decoder.decode(bytes, { stream: true });
    }
  } catch {
    return null;
  }
}

export async function lookup(request, env, now = Math.floor(Date.now() / 1000)) {
  const origin = request.headers.get('Origin');
  const allowed = origin === ORIGIN || (env.EXTRA_ORIGIN && origin === env.EXTRA_ORIGIN);
  const headers = { 'Cache-Control': 'no-store', Vary: 'Origin' };
  if (allowed) headers['Access-Control-Allow-Origin'] = origin;
  const reply = (data, status = 200) => Response.json(data, { status, headers });
  if (!allowed) return reply({ error: 'origin' }, 403);
  if (new URL(request.url).pathname !== '/nearby-scopes') return reply({ error: 'not_found' }, 404);
  if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: {
    ...headers, 'Access-Control-Allow-Methods': 'POST', 'Access-Control-Allow-Headers': 'Content-Type',
  } });
  if (request.method !== 'POST') return reply({ error: 'method' }, 405);
  const body = await readBody(request);
  if (!body || !RADII.includes(body.radius) || !['ip', 'manual'].includes(body.mode)) return reply({ error: 'request' }, 400);
  const auto = body.mode === 'ip';
  const at = auto ? point(request.cf?.latitude, request.cf?.longitude) : point(body.lat, body.lon);
  if (!at || (auto && at[0] === 0 && at[1] === 0)) return reply({ error: auto ? 'ip_unavailable' : 'request' }, auto ? 422 : 400);
  const slugs = maps(env);
  let feeds;
  try {
    feeds = (await Promise.all(slugs.map(async slug => [slug, await env.SCOPE_SNAPSHOTS.get(`meshmapper:v1:${slug}`, 'json')]))
      ).filter(([, data]) => data && data.updated <= now && data.updated > now - SNAPSHOT_MAX_AGE);
  } catch {
    return reply({ error: 'data_unavailable' }, 503);
  }
  if (!feeds.length) return reply({ error: 'data_unavailable' }, 503);
  const country = request.cf?.country;
  const countryCode = auto && typeof country === 'string' && /^[A-Z]{2}$/.test(country) ? country : null;
  return reply({
    ...nearby(feeds, at, body.radius, now), radius: body.radius, days: WINDOW / DAY,
    partial: feeds.length < slugs.length, updated: Math.min(...feeds.map(([, data]) => data.updated)),
    location: { lat: Number(at[1].toFixed(2)), lon: Number(at[0].toFixed(2)), ...(countryCode ? { countryCode } : {}),
      label: auto ? [request.cf?.city, request.cf?.region, request.cf?.country]
        .filter(part => typeof part === 'string' && part.length <= 80).join(', ') : '' },
  });
}

export default {
  fetch: (request, env) => lookup(request, env),
  scheduled: (_event, env, ctx) => ctx.waitUntil(refresh(env)),
};
