const geoIpUrl = 'https://get.geojs.io/v1/ip/geo.json';
const sessions = new WeakMap();

function session(fetcher) {
  if (!sessions.has(fetcher)) sessions.set(fetcher, { location: null, pending: null, listeners: new Set() });
  return sessions.get(fetcher);
}

function coordinate(value, limit) {
  const n = typeof value === 'number' || (typeof value === 'string' && value.trim()) ? Number(value) : NaN;
  return Number.isFinite(n) && Math.abs(n) <= limit ? Number(n.toFixed(2)) : null;
}

function normalizeLocation(location) {
  const lat = coordinate(location?.lat, 90);
  const lon = coordinate(location?.lon, 180);
  if (lat === null || lon === null || (lat === 0 && lon === 0)) throw new Error('IP location unavailable');
  const label = typeof location.label === 'string' ? location.label.trim().slice(0, 250) : '';
  // Older scopes Workers append the two-letter Cloudflare country code to the label.
  const country = location.countryCode ?? label.split(', ').at(-1);
  const countryCode = typeof country === 'string' && /^[A-Z]{2}$/.test(country) ? country : null;
  return Object.freeze({ lat, lon, label, countryCode });
}

export async function estimateIpLocation(fetcher = globalThis.fetch) {
  const response = await fetcher(geoIpUrl, {
    credentials: 'omit', cache: 'no-store', redirect: 'error', referrerPolicy: 'no-referrer',
    signal: AbortSignal.timeout(7000),
  });
  if (!response.ok) throw new Error('IP location unavailable');
  const data = await response.json();
  const label = [...new Set([data?.city, data?.region, data?.country]
    .filter(part => typeof part === 'string' && part.trim() && part.length <= 80).map(part => part.trim()))].join(', ');
  return normalizeLocation({ lat: data?.latitude, lon: data?.longitude, label, countryCode: data?.country_code ?? '' });
}

export function requestIpLocation(fetcher = globalThis.fetch, lookup = estimateIpLocation) {
  const entry = session(fetcher);
  if (entry.location) return Promise.resolve(entry.location);
  if (!entry.pending) {
    entry.pending = Promise.resolve().then(() => lookup(fetcher))
      .then(location => {
        entry.location = normalizeLocation(location);
        for (const listener of entry.listeners) listener(entry.location);
        return entry.location;
      })
      .finally(() => { entry.pending = null; });
  }
  return entry.pending;
}

export function subscribeIpLocation(listener, fetcher = globalThis.fetch) {
  const entry = session(fetcher);
  entry.listeners.add(listener);
  if (entry.location) listener(entry.location);
  return () => entry.listeners.delete(listener);
}

// Do not estimate a location for a hidden panel or background tab.
export function whenVisible(element, callback) {
  const doc = element?.ownerDocument;
  const Observer = doc?.defaultView?.IntersectionObserver;
  if (!Observer) return;
  let inView = false, fired = false;
  const check = () => {
    if (fired || !inView || doc.visibilityState === 'hidden') return;
    fired = true;
    observer.disconnect();
    doc.removeEventListener('visibilitychange', check);
    callback();
  };
  const observer = new Observer(entries => {
    inView = entries.some(entry => entry.target === element && entry.isIntersecting && entry.intersectionRatio > 0);
    check();
  }, { threshold: [0, 0.01] });
  doc.addEventListener('visibilitychange', check);
  observer.observe(element);
}
