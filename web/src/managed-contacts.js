import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';

// Contact edits operate on the node's advertised name, not a private alias.
// Keep all untouched fields as the device returned them, including the route.
const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });
const fail = message => { throw new Error(message); };
const validKey = value => typeof value === 'string' && /^[a-f\d]{64}$/i.test(value);

function context(core, { assertCurrent, maxContacts, publicKey } = {}) {
  if (!core || typeof core.self !== 'function' || typeof core.contacts !== 'function' || typeof core.request !== 'function' ||
      typeof assertCurrent !== 'function' || !Number.isInteger(maxContacts) || maxContacts < 1 || maxContacts > 2000 || !validKey(publicKey))
    fail('A verified device and contact capacity are required.');
  return { core, assertCurrent, maxContacts, publicKey:publicKey.toLowerCase() };
}

async function identity(ctx) {
  ctx.assertCurrent();
  const self = await ctx.core.self();
  ctx.assertCurrent();
  if (!(self instanceof Uint8Array) || self.length < 36 || self[0] !== 5 || bytesToHex(self.subarray(4, 36)) !== ctx.publicKey)
    fail('The connected device identity changed. No further contact changes were sent.');
}

function parse(row) {
  if (!(row instanceof Uint8Array) || row.length !== 148 || row[0] !== 3) fail('Invalid contact response.');
  const packed=row[35], data=new DataView(row.buffer,row.byteOffset,row.byteLength);
  if (packed !== 255 && (packed & 63) * ((packed >> 6) + 1) > 64 || Math.abs(data.getInt32(136,true)) > 90000000 || Math.abs(data.getInt32(140,true)) > 180000000)
    fail('Invalid contact data.');
  const nameBytes=row.subarray(100,132), end=nameBytes.indexOf(0);
  let name;
  try { name=decoder.decode(nameBytes.subarray(0,end < 0 ? nameBytes.length : end)); }
  catch { fail('A contact name is not valid UTF-8.'); }
  if (/[\p{Cc}\p{Cf}\p{Cs}\u2028\u2029]/u.test(name)) fail('A contact name contains unsupported control characters.');
  return Object.freeze({publicKey:bytesToHex(row.subarray(1,33)),name,type:row[33],flags:row[34],recordHex:bytesToHex(row)});
}

function contactName(name) {
  if (typeof name !== 'string' || !name.trim() || /[\p{Cc}\p{Cf}\p{Cs}\u2028\u2029]/u.test(name) || encoder.encode(name).length > 31)
    fail('Contact name must be 1–31 UTF-8 bytes without control characters.');
  return encoder.encode(name);
}

function selectedContact(contact) {
  if (!contact || !validKey(contact.publicKey) || typeof contact.recordHex !== 'string' || !/^[a-f\d]{296}$/i.test(contact.recordHex))
    fail('Select a previously read contact first.');
  const saved=parse(hexToBytes(contact.recordHex));
  if (saved.publicKey !== contact.publicKey.toLowerCase()) fail('Contact identity does not match the selected record.');
  return saved;
}

async function unchangedContact(ctx, saved) {
  const before=(await inventory(ctx)).find(row=>row.publicKey===saved.publicKey);
  if (!before || before.recordHex.slice(0,288) !== saved.recordHex.slice(0,288))
    fail('The contact changed since it was read. Reload it before editing.');
  return before;
}

async function inventory(ctx) {
  await identity(ctx);
  ctx.assertCurrent();
  const rows=await ctx.core.contacts({maxContacts:ctx.maxContacts});
  ctx.assertCurrent();
  if (!Array.isArray(rows) || rows.length > ctx.maxContacts) fail('Invalid contact inventory.');
  const seen=new Set(), result=rows.map(row=>{
    const contact=parse(row);
    if(seen.has(contact.publicKey))fail('Duplicate contact in the inventory.');
    seen.add(contact.publicKey);return contact;
  });
  await identity(ctx);
  return Object.freeze(result);
}

/** Read contact summaries without reading/exporting the node's private key. */
export async function readManagedContacts(core, options) {
  return inventory(context(core, options));
}

/** Rename one existing advertised contact name, preserving all other fields. */
export async function renameManagedContact(core, {contact, name, ...options} = {}) {
  const ctx=context(core,options);
  const saved=selectedContact(contact),nameBytes=contactName(name),before=await unchangedContact(ctx,saved);
  const desired=hexToBytes(before.recordHex);
  desired.fill(0,100,132);desired.set(nameBytes,100);
  if (bytesToHex(desired.subarray(0,144)) === before.recordHex.slice(0,288)) return before;
  await identity(ctx);
  ctx.assertCurrent();
  try {
    const response=await ctx.core.request([9,...desired.subarray(1,144)],0);
    ctx.assertCurrent();
    if (!(response instanceof Uint8Array) || response.length !== 1 || response[0] !== 0)
      fail('Contact update was not acknowledged.');
    const updated=(await inventory(ctx)).find(row=>row.publicKey===saved.publicKey);
    if (!updated || updated.recordHex.slice(0,288) !== bytesToHex(desired.subarray(0,144)))
      fail('Contact readback did not match.');
    return updated;
  } catch {
    fail('The contact update could not be verified and may have been saved. Reconnect the same radio and reload to check; it will not be retried.');
  }
}

/** Add a contact by public key. Unknown route and unreported advert/location
 * are explicitly represented as unknown/zero; no guessed route is installed. */
export async function addManagedContact(core, {contactPublicKey, name, type, ...options} = {}) {
  const ctx=context(core,options),nameBytes=contactName(name);
  if (!validKey(contactPublicKey) || /^0{64}$/i.test(contactPublicKey) || contactPublicKey.toLowerCase()===ctx.publicKey)
    fail('Enter a valid public key belonging to another node.');
  if (!Number.isInteger(type) || ![1,2,3,4].includes(type)) fail('Choose a supported contact type.');
  const key=contactPublicKey.toLowerCase(),rows=await inventory(ctx);
  if(rows.some(row=>row.publicKey===key))fail('This contact is already present. Reload contacts before making changes.');
  if(rows.length>=ctx.maxContacts)fail('The contact list is full. No contact was added.');
  const desired=new Uint8Array(148);desired[0]=3;desired.set(hexToBytes(key),1);desired[33]=type;desired[35]=255;desired.set(nameBytes,100);
  await identity(ctx);ctx.assertCurrent();
  try {
    const response=await ctx.core.request([9,...desired.subarray(1,144)],0);ctx.assertCurrent();
    if(!(response instanceof Uint8Array)||response.length!==1||response[0]!==0)fail('Contact addition was not acknowledged.');
    const added=(await inventory(ctx)).find(row=>row.publicKey===key);
    if(!added||added.recordHex.slice(0,288)!==bytesToHex(desired.subarray(0,144)))fail('Contact readback did not match.');
    return added;
  } catch {
    fail('The contact addition could not be verified and may have been saved. Reconnect the same radio and reload to check; it will not be retried.');
  }
}

/** Remove one previously reviewed contact. TAK also deletes its associated
 * stored blob and removes its chat thread; record restoration cannot recover it. */
export async function removeManagedContact(core, {contact, ...options} = {}) {
  const ctx=context(core,options),saved=selectedContact(contact);
  await unchangedContact(ctx,saved);
  await identity(ctx);ctx.assertCurrent();
  try {
    const response=await ctx.core.request([15,...hexToBytes(saved.publicKey)],0);ctx.assertCurrent();
    if(!(response instanceof Uint8Array)||response.length!==1||response[0]!==0)fail('Contact removal was not acknowledged.');
    if((await inventory(ctx)).some(row=>row.publicKey===saved.publicKey))fail('Contact is still present.');
    return true;
  } catch {
    fail('The contact removal could not be verified and may have occurred. Associated stored data may have been deleted. Reconnect the same radio and reload to check; it will not be retried.');
  }
}
