export function httpsUrl(value, base) {
  const url = new URL(value, base);
  if (url.protocol !== 'https:' || url.username || url.password) throw new Error('Firmware URLs must use HTTPS without credentials.');
  return url.href;
}
export function catalogItems(config, releases = [], provider = 'MeshCore') {
  const items = [];
  for (const device of config.device || []) for (const firmware of device.firmware || []) {
    if (firmware.github?.files) for (const [action, pattern] of Object.entries(firmware.github.files)) {
      if (String(pattern).length > 512) continue;
      let re; try { re = new RegExp(`^(?:${pattern})$`,'i'); } catch { continue; }
      for (const release of releases.filter(r => r.type === firmware.github.type)) for (const file of release.files || []) {
        if (!re.test(file.name)) continue;
        items.push({ project: 'MeshCore', provider, hardware: device.name, architecture: device.type, role: firmware.role, version: release.version, action, name: file.name, url: httpsUrl(file.url,'https://github.com/meshcore-dev/MeshCore') });
      }
    }
    for (const [version, release] of Object.entries(firmware.version || {})) for (const file of release.files || []) {
      const raw = file.url || (typeof file.name === 'string' && /^https:/.test(file.name) ? file.name : `${config.staticPath || '/firmware'}/${file.name}`);
      items.push({ project: 'MeshCore', provider, hardware: device.name, architecture: device.type, role: firmware.role, version, action: file.type, name: String(file.name).split('/').pop(), url: httpsUrl(raw,'https://flasher.meshcore.io') });
    }
  }
  // nRF52 is always the CLI-style serial DFU path, never a UF2 drive action.
  return items.filter(item => item.architecture !== 'nrf52' || /\.zip$/i.test(item.name));
}
export async function getCatalog() {
  const response = await fetch(new URL('../catalog.json', import.meta.url));
  if (!response.ok) throw new Error('Catalog snapshot unavailable. Choose a local firmware file or an HTTPS URL.');
  return response.json();
}
