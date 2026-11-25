export const PNW_CONFIG_URL = 'https://gessaman.com/meshcore/regions/config/';

// Local areas and the hard US/Canada border from Gessaman's region data
// (2026-09-06): https://gessaman.com/meshcore/regions/regions.json
// Each row contains the scope, display name, country, center, and radius in km.
const areas = [
  ['sea', 'Seattle / Tacoma / Bellevue', 'US', 47.4502, -122.3088, 68],
  ['oly', 'Olympia / Lacey / Tumwater', 'US', 46.9694, -122.9022, 34],
  ['kit', 'Kitsap / Bremerton', 'US', 47.4902, -122.7643, 30],
  ['grh', 'Grays Harbor / WA Coast', 'US', 46.9712, -123.8139, 44],
  ['bvs', 'Skagit Valley', 'US', 48.4699, -122.4201, 24],
  ['bli', 'Bellingham / Whatcom', 'US', 48.7928, -122.5375, 32],
  ['cls', 'Centralia / Chehalis', 'US', 46.676, -122.983, 24],
  ['kls', 'Kelso / Longview', 'US', 46.118, -122.898, 24],
  ['ykm', 'Yakima', 'US', 46.5682, -120.5449, 30],
  ['eat', 'Wenatchee', 'US', 47.398, -120.207, 26],
  ['eln', 'Ellensburg', 'US', 46.997, -120.531, 22],
  ['eph', 'Ephrata', 'US', 47.3169, -119.5481, 30],
  ['geg', 'Spokane', 'US', 47.6199, -117.5338, 44],
  ['alw', 'Walla Walla', 'US', 46.0949, -118.288, 24],
  ['puw', 'Pullman', 'US', 46.7439, -117.1096, 22],
  ['psc', 'Tri-Cities (Pasco / Kennewick / Richland)', 'US', 46.2396, -119.1006, 30],
  ['pdx', 'Portland Metro', 'US', 45.5898, -122.5951, 46],
  ['mmv', 'McMinnville / Yamhill', 'US', 45.1944, -123.1361, 18],
  ['sle', 'Salem / Keizer', 'US', 44.9095, -123.0025, 26],
  ['cvo', 'Corvallis / Albany', 'US', 44.4972, -123.2906, 27],
  ['eug', 'Eugene / Springfield', 'US', 44.1246, -123.2119, 32],
  ['mfr', 'Medford / Ashland', 'US', 42.3742, -122.8735, 30],
  ['rbg', 'Roseburg', 'US', 43.2388, -123.355, 24],
  ['lmt', 'Klamath Falls', 'US', 42.1611, -121.7333, 26],
  ['onp', 'Newport / Lincoln City', 'US', 44.5804, -124.058, 26],
  ['ast', 'Astoria / Seaside', 'US', 46.158, -123.878, 23],
  ['otk', 'Tillamook', 'US', 45.4563, -123.8443, 18],
  ['oth', 'North Bend / Coos Bay', 'US', 43.4171, -124.246, 26],
  ['bend', 'Bend / Redmond', 'US', 44.2541, -121.1499, 33],
  ['pdt', 'Pendleton', 'US', 45.6951, -118.8418, 24],
  ['bke', 'Baker City', 'US', 44.8383, -117.809, 23],
  ['boi', 'Boise Metro', 'US', 43.5644, -116.223, 43],
  ['cda', "Coeur d'Alene / N. Idaho", 'US', 47.7069, -116.82, 38],
  ['lws', 'Lewiston / Moscow / Clearwater', 'US', 46.5, -116.8, 50],
  ['fca', 'Flathead Valley / Kalispell', 'US', 48.3105, -114.2558, 58],
  ['swbc', 'Southwest BC / Lower Mainland', 'CA', 49.17, -122.7, 80],
  ['vanisle', 'Vancouver Island', 'CA', 49.5, -124.8, 150],
  ['southisland', 'South Vancouver Island / Victoria', 'CA', 48.5, -123.4, 50],
  ['salishmesh', 'Salish Sea / Gulf Islands', 'CA', 48.85, -123.3, 65],
];

const border = [
  [-125, 48.4], [-124.7, 48.4], [-123.55, 48.3], [-123.25, 48.42],
  [-123.15, 48.66], [-123.08, 48.9], [-123.02, 49], [-114, 49],
];

function countryAt(lat, lon) {
  const next = border.findIndex(([edgeLon]) => lon <= edgeLon);
  let borderLat;
  if (next === 0) borderLat = border[0][1];
  else if (next === -1) borderLat = border.at(-1)[1];
  else {
    const [leftLon, leftLat] = border[next - 1];
    const [rightLon, rightLat] = border[next];
    const fraction = (lon - leftLon) / (rightLon - leftLon);
    borderLat = leftLat + fraction * (rightLat - leftLat);
  }
  return lat > borderLat ? 'CA' : 'US';
}

export function pnwRegionSuggestion(location) {
  const { lat, lon, countryCode } = location ?? {};
  if (!Number.isFinite(lat) || Math.abs(lat) > 90 || !Number.isFinite(lon) || Math.abs(lon) > 180) return null;
  const country = countryCode ?? countryAt(lat, lon);
  if (country !== 'US' && country !== 'CA') return null;
  const radians = Math.PI / 180;
  let best = null;
  let bestScore = Infinity;
  for (const [tag, label, areaCountry, areaLat, areaLon, radius] of areas) {
    if (areaCountry !== country) continue;
    const a = Math.sin((areaLat - lat) * radians / 2) ** 2
      + Math.cos(lat * radians) * Math.cos(areaLat * radians)
      * Math.sin((areaLon - lon) * radians / 2) ** 2;
    const distance = 12742 * Math.asin(Math.sqrt(Math.min(1, a)));
    // Prefer upstream's weighted match, but only within a published local radius.
    const score = distance - radius;
    if (score <= 0 && score < bestScore) {
      best = { tag, label };
      bestScore = score;
    }
  }
  return best;
}
