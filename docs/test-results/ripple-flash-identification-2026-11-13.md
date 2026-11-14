# Installed ESP32 firmware identification — 2026-11-13

## Scope

User-authorized inspection of the attached radio reported as a T-Deck running
Ripple 9.6. This was a native esptool 5.5.0 diagnostic, not a browser feature
test. No firmware was installed, erased or modified. Existing application
detection and slot-selector worktree changes were preserved.

## Result

- ROM confirmed ESP32-S3 revision 0.2, with 8 MB embedded PSRAM and 16 MB SPI
  flash. Secure Boot and flash encryption were disabled.
- The partition table's MD5 validated. `app0` begins at `0x10000`; `app1`
  begins at `0x650000`. Each application partition is `0x640000` bytes.
- `app0` contained a structurally valid 1,588,016-byte ESP32-S3 application.
  Its image checksum, appended SHA-256 and device readback MD5 all validated.
- Embedded markers included `Ripple`, `v9.6`, `rippleradios.com` and
  `register.rippleradios.com`: strong evidence for installed Ripple-family
  firmware containing version v9.6. No official release artifact was available
  for an authenticated/exact release comparison.
- The ESP-IDF descriptor instead reported `arduino-lib-builder`, IDF 4.4.6 and
  an October 2023 toolchain date. These are not a reliable Ripple release name,
  version or build date. A header-only implementation would miss this result.
- MeshCore strings also appeared in the image. A single `MeshCore` keyword must
  not classify this firmware as the MeshCore Companion USB application.
- `app1`'s first 512 bytes were erased, so no ESP application header was found
  there. The rest of that partition was not read or asserted empty.

Validated application image SHA-256:

```text
267a94e6bc88ecf027c2b8a2d7175040ab6b85eb0b39a5fb4e167b66a8a19985
```

## Read boundaries and side effects

Reads were limited to the partition table (`0x8000`, 4096 bytes), application
prefixes (512 bytes each), segment headers within app0, and its validated
application-image extent. The full app0 code read took about 6.5 seconds.
No NVS, OTA-selection metadata, filesystem, coredump, settings or identity-store
contents were read. Firmware bytes were processed in memory, not exported as a
full-flash dump or uploaded anywhere.

The device briefly entered its ROM downloader for each of two inspection
passes. A temporary esptool RAM stub performed the reads. At the end of each
pass, the same chip MAC was checked, the volatile forced-download bit was
cleared and a watchdog restart requested. No flash writes or erase commands
were used. Normal application startup is not proven by a successful restart
request; visual confirmation was requested from the user.

## Limits and browser implementation guidance

This establishes the processor and installed-image evidence, not the physical
board model, exact Ripple edition, current running slot or boot-selected slot.
OTA-selection metadata was intentionally not read. Do not label app0 active
solely because it contains the only observed valid header.

A browser fallback can inspect validated application metadata first, then
optionally read only the bounded app image when descriptors are generic.
Keep chip identity, image integrity, inferred firmware identity and physical
board confidence separate. Unknown/encrypted/unsupported images must remain
unknown, and a generic toolchain descriptor must not become a firmware match.
Entering the bootloader interrupts the running application and needs explicit
user consent; it is not a consequence-free background detection attempt.

## Follow-up: user-authorized stored-configuration inspection

After the initial application-only test, the user explicitly authorized reading
stored configuration to look for the board model. The same chip was rechecked
before each pass; no persistent writes were used.

- The NVS partition was erased/uninitialized, with no live namespaces or entries.
- The reviewed SPIFFS directory contained 1,995 unique live file headers.
  Only configuration-related metadata was reported; other file contents,
  private keys, passwords and message contents were not printed.
- A live `conf.txt` file was located and its content pages validated against
  their index/lookup entries. It was 15 bytes, but did not expose a recognized
  JSON or key/value hardware/model field. Its raw value was not disclosed.
- No readable, source-backed `T-Deck` board identifier was established in the
  inspected configuration. Unknown short/binary values were not mapped to a
  board name by assumption.

SPIFFS/NVS data was processed in memory and not saved as a raw filesystem dump
or uploaded. Sanitized metadata reports and temporary diagnostic helpers remain
local. The metadata parsers passed seven synthetic tests, including deleted
SPIFFS entries, wrong page references, invalid NVS CRCs, duplicate live settings
and secret-value suppression. Each inspection ended with a normal-boot restart
request; physical display/startup confirmation remains unavailable while the
user is away.
