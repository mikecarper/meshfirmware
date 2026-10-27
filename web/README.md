# Browser USB flasher

https://mikecarper.github.io/meshfirmware/

A static GitHub Pages app: it talks directly to the port you select. It does
not launch `firmware.cmd`, contact a localhost service, install Python, or
upload your firmware, identity, settings or backups. Public firmware/catalog
downloads contact their named hosts. GitHub receives ordinary site requests.

This is a **hardware preview**. Automated protocol, safety, simulated serial,
WebAssembly and simulated IndexedDB persistence tests pass. Physical flashing,
visual browser QA and real-browser persistence have not yet been verified.
Start with a recoverable bench radio, not a remote USB-only node.

## Use

1. Open the page in desktop Chrome/Edge and choose a USB port.
2. Select a release, an HTTPS URL or a local BIN/DFU ZIP/UF2/release ZIP. If a
   host blocks browser fetches, use Download, then choose that local file.
3. Choose the correct connection type and use **Back up & inspect**. Before
   resetting an application or entering ROM/DFU, the page offers a backup by
   default. Auto-detection distinguishes a binary companion from CommonCLI.
   Confirm that the downloaded archive was saved; partial/failed backups need
   separate acknowledgement. A backup-only button is also available.
4. Review the exact file, operation, target evidence and hash, then type the
   confirmation token. An already-running ROM/DFU interface cannot export
   application settings: select **Already in ROM/DFU** and explicitly accept
   continuing without a backup, or return to the application first.
5. ESP32 writes require target MD5 readback before the one-time reset action.
   Re-select the application port to run startup verification automatically.
   The page checks retained node identity/model when applicable, protected
   nRF52 board family, payload version when verified metadata is available,
   and an ESP32 `get storage.layout` response. **Verify running application**
   retries that check. Transfer completion alone is not startup verification;
   bootloader/SoftDevice-only transfers do not claim application success.

CH340/CP210x/FTDI work through the installed OS serial driver. The page cannot
install drivers or expose device interfaces the browser/OS does not permit.
TinyUSB application handoff and hardware USB-Serial/JTAG are separate choices;
the shared `303a:1001` ID is not used to guess their reset mechanism.

## Features and boundaries

| Feature | Browser behavior |
| --- | --- |
| MeshCore / Keymind catalog | Rebuilt daily/on deployment; newest versioned Keymind manifest discovery; primary/proxy/validated-cache fallback; board/role/variant context and newest-first versions |
| ESP32/S2/C3/S3/C6 | Validated application updates and merged installs; chip/security/MAC/capacity checks; factory-only/non-OTA updates and larger OTA metadata partitions supported |
| Merged ESP32 installs | Populate missing secondary OTA slots from the exact embedded app, with independent readback; refuse ambiguous source boundaries rather than guessing |
| ESP components | Checksum-valid bootloader/component image, explicit address, typed acknowledgement; never guess an offset |
| nRF52 | Serial DFU like `adafruit-nrfutil`: application, bootloader, SoftDevice or combined SD/bootloader ZIP; guided erase/reconnect/final-write; no mounted-drive workflow or generic Nordic secure-DFU substitution |
| Other UF2 boards | Validated blocks; explicitly chosen bootloader directory and identity recheck; nRF52 UF2 is refused in favor of serial DFU ZIP |
| MeshCore companion backup | Private identity when exposed, channels, contacts, settings, battery/storage and optional CLI snapshots; completeness and unavailable sections shown separately from integrity |
| MeshCore companion restore | New native-format exports, existing script JSON and legacy browser JSON; exact Python serialization/validation in WASM; model/capacity/key checks, TX/logging readback, deliberate cross-hardware identity replacement |
| Full Companion text mode | Explicit binary handoff; turning USB logging off requires acknowledgement |
| CommonCLI repeater/room | Partial read-only snapshot, no automatic restore |
| OS/tool management | Not a browser operation: no pip/driver installs, Raspberry Pi USB-speed changes or shell execution |

Every web backup is deliberately marked **not wipe-safe**. Unexposed secrets,
messages, files, logs and firmware may be absent. Imported MeshCore archives
are validated from their original JSON text to preserve Python's canonical
floating-point integrity. Diagnostic firmware versions are never restored.
Unstructured optional CLI settings are retained for manual comparison.

### nRF52 erase and recovery

Choose **Erase, reconnect, then write selected ZIP**. The final firmware and
the selected board's erase ZIP are validated before erase. Use the published
erase choice or its exact local ZIP if browser downloads are blocked. Only
application erase packages qualify; bootloader/SoftDevice components cannot be
used as the guided erase step. Official v6/v7 utilities are recognized by their
payload hashes even after renaming. A name-marked custom eraser requires an
additional **CUSTOM ERASE** acknowledgement, not an automatic trust decision.
Erase packages require destructive acknowledgement even when
their DFU manifest calls them an `application`.

Protected RAK checks examine embedded payload identity and retained pre-DFU
board evidence, not just filenames. Unknown or conflicting evidence requires
a directional, one-write override. That override is separate from the wipe
acknowledgement; neither is a permanent bypass.

After each reset/handoff, explicitly choose the **same physical radio** and
confirm it. The browser cannot compare physical USB serial numbers. After
erase, the final ZIP remains loaded, but no final write occurs until you
reselect its DFU port, inspect again and confirm the write. Recovery state
records only public filenames/hashes and board hints; if the page reloads,
select the original exact final ZIP. Do not disconnect power during recovery.

### Backup compatibility and physical-target checks

New browser downloads use `org.meshfirmware.meshcore-backup/v1`, the native
script archive format. The exact Python serializer seals the archive inside
WebAssembly; the exact validator verifies it before download. Existing script
archives and older browser-format archives still import into this page.

Web Serial exposes VID/PID and port permission, **not** USB serial/location.
The archive explicitly records `browser-port-permission` attestation and null
physical-identity fields; it never invents a physical serial. Updated
`restore.cmd` can use these companion archives, but prompts for the exact
connected target USB serial. The Python restore helper requires
`--target-serial` for a browser capture; moving to a different model also
requires `--new-hardware`. Hardware, public identity, private-key proof and
explicit identity-replacement checks remain in force.

CommonCLI captures remain partial and cannot be automatically restored.
Missing private identity or unavailable required sections cannot become a
complete restore merely because the archive checksum is valid. Files are
downloaded through the browser: the page cannot prove the download reached
disk or set the file permissions, so keep the archive in a private location.

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
The catalog and its compressed last-known cache contain public release metadata
only. Browser storage is not a substitute for a downloaded private backup.

References: [official MeshCore flasher](https://github.com/meshcore-dev/flasher.meshcore.io),
[Espressif esptool-js](https://github.com/espressif/esptool-js),
[Web Serial](https://developer.chrome.com/docs/capabilities/serial).
