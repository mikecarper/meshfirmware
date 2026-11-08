# Generic ESP32 recovery validation - 2026-11-08

The generic path has hardware-free tests for every ESP32 family in esptool
5.1.0, including bootloader offsets at zero, 0x1000 and 0x2000. Fixtures exercise
both zero-padded merged files and files beginning at the bootloader offset.

The recovery suite covers single/dual-slot and factory application layouts,
custom partition offsets, preserved NVS/filesystems/other app slots, full-flash
input boundaries, explicit factory erase, interrupted writes and failed
verification, chip/flash mismatch, secure devices, USB identity, reset dispatch,
image checksum/digest failures, catalog filtering and honest startup reporting.
S3-specific register writes are asserted absent for other chips and UART S3.

Actual published images were downloaded and validated without opening hardware:

| Board | Chip | Image flash capacity |
| --- | --- | --- |
| Heltec v2 | ESP32 | 8 MiB |
| Heltec v3 | ESP32-S3 | 8 MiB |
| Heltec v4 | ESP32-S3 | 16 MiB |
| Tenstar C3 | ESP32-C3 | 4 MiB |
| Seeed Studio Xiao C6 | ESP32-C6 | 4 MiB |
| LilyGo T-Deck | ESP32-S3 | 16 MiB |

These are image checks, not physical board qualification. Physical flash
capacity is independently checked when recovering a device. A larger image is
refused on a smaller flash chip.

No radios were flashed for the generic extension. The earlier Station-specific
preservation path passed on a physical G2; that result does not qualify every
new chip/reset/layout combination. See [the Station report](station-recovery-2026-11-08.md).
