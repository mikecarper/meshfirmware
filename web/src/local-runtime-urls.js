// Both Vite source modules (/src/) and built chunks (/assets/) sit one level
// below the app root. Resolve explicit public FILES through a parameter so
// Vite cannot rewrite a directory URL into an asset URL without its slash.
// All resources stay beside this app, including a GitHub Pages subdirectory;
// there is deliberately no CDN or cross-origin runtime fallback.
export function localRuntimeUrls(moduleUrl) {
  const moduleURL = new URL('../python/pyodide.mjs', moduleUrl);
  const manifestURL = new URL('../validators/integrity.json', moduleUrl);
  return {
    moduleURL: moduleURL.href,
    indexURL: new URL('./', moduleURL).href,
    validatorsURL: new URL('./', manifestURL).href,
  };
}
