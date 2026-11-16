// Reviewed Wadamesh builds use 2,000 contacts and 40 channels. DEVICE_INFO
// predates these builds: uint8(MAX_CONTACTS / 2) wraps 1,000 to 232. Require
// the live firmware's own CLI identity as well as that exact legacy layout;
// neither a selected provider nor an imported archive identifies the target.
// Source: ALLFATHER-BV/wadamesh 6e2993099e6e, platformio.ini and MyMesh.cpp.
export function isLargeWadameshLayout(info) {
  return info?.[0] === 13 && info[1] >= 10 && info[2] === 232 && info[3] === 40;
}
export function isWadameshProtocolProfile(info, version) {
  return isLargeWadameshLayout(info) && typeof version === 'string' && /^(?:>\s*)?(?:Meshcomod|Wadamesh)\s+\S+/i.test(version.trim());
}
export function companionContactCapacity(info, version) {
  return isWadameshProtocolProfile(info, version) ? 2000 : info[2] * 2;
}
