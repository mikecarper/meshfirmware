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
// The reviewed TAK beta_105.8 touch builds identify themselves using the
// Companion `ver` reply rather than Meshcomod's `version` command. This is a
// compatible protocol fingerprint, not proof of an exact release or board.
// Source: jade-on-mesh/wadamesh-tak tag tak-beta_105.8, MyMesh.cpp/.h and platformio.ini.
export function isWadameshTakTouchProfile(info, version) {
  if (!isLargeWadameshLayout(info) || info[1] !== 27 || info.length < 80 || typeof version !== 'string') return false;
  const field = info.subarray(60, 80), end = field.indexOf(0);
  const identity = new TextDecoder().decode(end < 0 ? field : field.subarray(0, end));
  const reply=version.trim(),release=/^(wadamesh-tak beta_\d+(?:\.\d+){0,3})\s+\(Build: [^\r\n]{1,64}\)$/i.exec(reply);
  if(release)return identity===release[1].slice(0,19);
  return identity === 'v1.18.0.1-touch' && /^v1\.18\.0\.1-touch\s+\(Build: [^\r\n]{1,64}\)$/i.test(reply);
}
export function companionContactCapacity(info, version) {
  return isWadameshProtocolProfile(info, version) ? 2000 : info[2] * 2;
}
