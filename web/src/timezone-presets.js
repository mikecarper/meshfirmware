// These are coarse, user-facing hints, not location or regulatory detection.
// Time zone identifiers and the returned suggestions stay in this browser.
const titleByZone = new Map();
function zones(names, titles) { for (const name of names) titleByZone.set(name, Object.freeze(titles)); }

zones(['America/Los_Angeles'], ['USA', 'USA - Southern California']);
zones(['America/New_York','America/Chicago','America/Denver','America/Phoenix','America/Anchorage','Pacific/Honolulu','America/Detroit','America/Boise','America/Indiana/Indianapolis'], ['USA']);
zones(['America/Toronto','America/Vancouver','America/Edmonton','America/Winnipeg','America/Halifax','America/St_Johns'], ['Canada']);
zones(['Australia/Sydney','Australia/Melbourne','Australia/Brisbane','Australia/Perth','Australia/Adelaide','Australia/Hobart','Australia/Darwin'], ['Australia', 'Australia (Narrow)', 'Australia (Mid)']);
zones(['Pacific/Auckland','Pacific/Chatham'], ['New Zealand (Narrow)', 'New Zealand (Gisborne)']);
zones(['America/Sao_Paulo'], ['Brazil']);
zones(['America/Costa_Rica'], ['Costa Rica']);
zones(['Europe/London'], ['EU/UK (Narrow)']);
zones(['Europe/Prague'], ['Czech Republic (Narrow)', 'EU/UK (Narrow)']);
zones(['Europe/Budapest'], ['Hungary', 'EU/UK (Narrow)']);
zones(['Europe/Amsterdam'], ['Netherlands', 'Netherlands (Limburg)', 'EU/UK (Narrow)']);
zones(['Europe/Lisbon'], ['Portugal 433', 'Portugal 868', 'EU/UK (Narrow)']);
zones(['Europe/Bratislava'], ['Slovakia', 'EU/UK (Narrow)']);
zones(['Europe/Zurich'], ['Switzerland', 'EU/UK (Narrow)']);
zones(['Asia/Bangkok'], ['Thailand']);
zones(['Asia/Ho_Chi_Minh', 'Asia/Saigon'], ['Vietnam (Narrow)']);

/** Return only unambiguous, exact titles present in the validated preset list. */
export function timezonePresetSuggestions(presets, timezone) {
  if (!Array.isArray(presets) || typeof timezone !== 'string') return [];
  const titles = titleByZone.get(timezone);
  if (!titles) return [];
  return titles.flatMap(title => {
    const matches = presets.filter(p => p?.title === title && typeof p.id === 'string' && p.id);
    return matches.length === 1 ? [matches[0]] : [];
  });
}

export function browserTimezonePresetSuggestions(presets) {
  try { return timezonePresetSuggestions(presets, Intl.DateTimeFormat().resolvedOptions().timeZone); }
  catch { return []; }
}
