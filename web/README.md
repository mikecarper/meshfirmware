# Browser USB flasher

https://mikecarper.github.io/meshfirmware/

A static GitHub Pages app: it talks directly to the port you select. It does
not launch `firmware.cmd`, contact a localhost service, install Python, or
upload your firmware, identity, settings or backups. Public firmware/catalog
downloads contact their named hosts. GitHub receives ordinary site requests.

This is a **hardware preview**. Automated protocol, safety, simulated serial
and WebAssembly tests pass. Physical flashing, visual browser QA and actual
IndexedDB persistence have not yet been verified. Start with a recoverable
bench radio, not a remote USB-only node.

## Use

1. Open the page in desktop Chrome/Edge and choose a USB port.
2. Read the running MeshCore node and download a backup
   while application firmware is running. ROM/DFU cannot export its settings.
3. Select a release, an HTTPS URL or a local BIN/DFU ZIP/UF2/release ZIP. If a
   host blocks browser fetches, use Download, then choose that local file.
4. Choose the correct connection type, inspect the device, review the exact
   operation and hash, and type the confirmation token to flash.
5. ESP32 writes require target MD5 readback before the one-time reset action.
   Re-select the application port and read the node to check startup. DFU/UF2
   transfer completion alone does not prove which application started.

CH340/CP210x/FTDI work through the installed OS serial driver. The page cannot
install drivers or expose device interfaces the browser/OS does not permit.
TinyUSB application handoff and hardware USB-Serial/JTAG are separate choices;
the shared `303a:1001` ID is not used to guess their reset mechanism.

## Features and boundaries

| Feature | Browser behavior |
| --- | --- |
| MeshCore / Keymind catalog | Public snapshot rebuilt daily and on deployment; exact board/role filters |
| ESP32/S2/C3/S3/C6 | Validated application updates and merged installs; chip/security/MAC/capacity checks |
| ESP components | Checksum-valid bootloader/component image, explicit address, typed acknowledgement; never guess an offset |
| nRF52 | Serial DFU like `adafruit-nrfutil`: application, bootloader, SoftDevice or combined SD/bootloader ZIP; no mounted-drive workflow or generic Nordic secure-DFU substitution |
| Other UF2 boards | Validated blocks; explicitly chosen bootloader directory and identity recheck; nRF52 UF2 is refused in favor of serial DFU ZIP |
| MeshCore companion backup | Private identity when exposed, channels, contacts, settings and optional snapshots; integrity checked locally |
| MeshCore companion restore | Browser JSON and existing script companion JSON; exact Python archive validator in WASM; model/capacity/key checks and deliberate cross-hardware identity replacement |
| Full Companion text mode | Explicit binary handoff; turning USB logging off requires acknowledgement |
| CommonCLI repeater/room | Partial read-only snapshot, no automatic restore |
| OS/tool management | Not a browser operation: no pip/driver installs, Raspberry Pi USB-speed changes or shell execution |

Every web backup is deliberately marked **not wipe-safe**. Unexposed secrets,
messages, files, logs and firmware may be absent. Imported MeshCore archives
are validated from their original JSON text to preserve Python's canonical
floating-point integrity. Diagnostic firmware versions are never restored.
Unstructured optional CLI settings are retained for manual comparison.

### Settings-preserving partition expansion

The unchanged `tools/meshcore_partition_expansion.py` validator runs inside
Pyodide WebAssembly on demand. Only reviewed exact ESP32/C3/S3 board/role/release
packages qualify. Unsupported layouts/chips do not silently become full wipes.

The page reads the physical table, NVS and OTA state; the exact validator
selects a release-pinned USB-safe middle firmware and binds the plan to the
physical chip MAC and final firmware SHA-256. The public plan and bridge are
persisted in this browser's IndexedDB **before** bridge writes. Raw NVS/OTA
snapshots and private backups are memory-only, not stored in that cache.

Keep power, this browser profile and its storage available. The bridge must
finish before the final write. Native USB bridges return to ROM automatically;
select that port with **already in ROM / no reset**. Classic ESP32 USB-UART
bridges must report the exact chip-bound settled status before another reset.
Then the validator checks the new table, restoration flags and OTA state.

If the page closed before starting a verified bridge, choose its original
firmware and ROM port without resetting, then use **Recover verified bridge
start**. The page revalidates the cached package and every on-device bridge
slot before allowing one reset. A partial/mismatched bridge is not reset.
Do not clear browser storage during recovery. Lost power during table rewriting
can still require physical access; there is no atomic/brick-proof claim.

## Build and test

Node 24 and pnpm 11.25.0:

```sh
cd web
pnpm install --frozen-lockfile --ignore-scripts
pnpm test
node scripts/catalog.mjs
pnpm build
node scripts/check-dist.mjs
pnpm preview
```

Only `web/dist` is published. The build copies an explicit runtime/validator
allowlist; an artifact check refuses backup names, credentials, source maps,
symlinks or unexpected root files. The workflow never publishes the repository
root. Runtime dependencies are pinned; third-party licenses ship with the app.

References: [official MeshCore flasher](https://github.com/meshcore-dev/flasher.meshcore.io),
[Espressif esptool-js](https://github.com/espressif/esptool-js),
[Web Serial](https://developer.chrome.com/docs/capabilities/serial).
