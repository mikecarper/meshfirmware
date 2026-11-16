import { ed25519 } from '@noble/curves/ed25519';
import { bytesToHex } from '@noble/hashes/utils.js';
import { fail } from './firmware.js';

export function expandedPublicKey(key) {
  if (!(key instanceof Uint8Array) || key.length !== 64) fail('A MeshCore private key must contain 64 bytes.');
  let scalar = 0n;
  for (let i = 31; i >= 0; i--) scalar = scalar * 256n + BigInt(key[i]);
  scalar %= ed25519.CURVE.n;
  if (!scalar) fail('Invalid zero identity.');
  return ed25519.ExtendedPoint.BASE.multiply(scalar).toRawBytes();
}

// LocalIdentity stores public[32], private[64]. Some export buffers reverse
// these fields. Require the derived public key beside the complete private
// key; a clamped scalar or a plausible hex string alone is not an identity.
export async function findRippleIdentity(memory, { alignment = 4, progress = () => {}, yieldTask = () => new Promise(resolve => setTimeout(resolve, 0)) } = {}) {
  if (!(memory instanceof Uint8Array) || memory.length > 0x78000) fail('Invalid Ripple memory capture.');
  if (![1, 4].includes(alignment)) fail('Invalid identity scan alignment.');
  const matches = new Map();
  let candidates = 0;
  for (let offset = 0; offset + 64 <= memory.length; offset += alignment) {
    if ((memory[offset] & 7) || (memory[offset + 31] & 0xc0) !== 0x40) continue;
    const key = memory.subarray(offset, offset + 64);
    const publicKey = expandedPublicKey(key);
    const equalAt = at => at >= 0 && at + 32 <= memory.length && publicKey.every((byte, i) => byte === memory[at + i]);
    if (equalAt(offset - 32) || equalAt(offset + 64)) {
      const privateHex = bytesToHex(key);
      matches.set(privateHex, { privateKey: privateHex, publicKey: bytesToHex(publicKey) });
    }
    if (++candidates % 64 === 0) {
      progress(offset / memory.length, 'Verifying the loaded Ripple identity');
      await yieldTask();
    }
  }
  if (matches.size !== 1) fail(matches.size ? 'Several different identities were found. No key was selected automatically.' : 'No verified Ripple identity was found. Start Ripple normally and try again, or import its SD-card identity file.');
  return matches.values().next().value;
}
