import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { inflateSync } from 'fflate';
import { crc32 } from '../src/firmware.js';
import { openReader, packBook, parseBooks, ReaderLink } from '../src/reader-books.js';

function unpack({ bytes }) {
  const decoder = new TextDecoder('utf-8', { fatal: true });
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.length);
  const u16 = at => view.getUint16(at, true), u32 = at => view.getUint32(at, true);
  const cstring = (b, at) => decoder.decode(b.subarray(at, b.indexOf(0, at)));
  assert.equal(decoder.decode(bytes.subarray(0, 4)), 'MRB1');
  assert.equal(u32(4), bytes.length);
  const count = u16(8), table = 64 + 36 * count;
  return { title: cstring(bytes, 12), chapters: Array.from({ length: count }, (_, chapter) => {
    const at = 64 + chapter * 36;
    return { title: cstring(bytes, at + 4), passages: Array.from({ length: u16(at + 2) }, (_, index) => {
      const record = table + 10 * (u16(at) + index), start = u32(record);
      const raw = inflateSync(bytes.subarray(start, start + u16(record + 4)));
      assert.equal(raw.length, u16(record + 6));
      assert.ok(raw.length <= 768);
      return cstring(raw, u16(record + 8));
    }) };
  }) };
}

test('numbered, plain, Markdown and both JSON structures pack round-trip', () => {
  const inputs = [
    ['### Notes\n[1:1] First.\n[1:2] Second.\n\n### Next\n[1:1] Third.', 'notes.txt'],
    ['One line\nwrapped.\n\nNext paragraph.', 'Notes.txt'],
    ['# Notes\n## Radio\nFirst.\n\nSecond.\n## Maps\nThird.', 'notes.md'],
    ['{"books":[{"title":"Notes","chapters":[{"title":"Radio","passages":["First.","Second."]}]}]}', 'notes.json'],
    ['[{"title":"Shelter","category":"Outdoors","steps":["Find cover."],"doNotDo":["Do not go into a flood channel."]}]', 'Notes.json'],
  ];
  for (const [source, filename] of inputs) for (const book of parseBooks(source, filename)) assert.deepEqual(unpack(packBook(book)), book);
  assert.throws(() => parseBooks('### Notes\n[1:2] Missing first.'), /Unexpected passage/);
  assert.throws(() => parseBooks('[{"title":"Bad","chapters":[]}]'), /least one chapter/);
});

test('packing shares compression blocks and splits long UTF-8 passages without cutting characters', () => {
  const text = '\u00e9'.repeat(600);
  const [book] = parseBooks(`# Notes\n## Radio\n${text}\n\nTwo.\n\nThree.`, 'notes.md');
  const pack = packBook(book), view = new DataView(pack.bytes.buffer);
  const out = unpack(pack).chapters[0].passages;
  assert.equal(out[0] + out[1], text);
  assert.deepEqual(out.slice(2), ['Two.', 'Three.']);
  assert.equal(view.getUint32(120, true), view.getUint32(130, true));
  const [cyrillic] = parseBooks('Caf\u00e9 \u041c\u043e\u0441\u043a\u0432\u0430.');
  assert.deepEqual(unpack(packBook(cyrillic, { ascii: true })).chapters[0].passages, ['Cafe Moskva.']);
  assert.throws(() => packBook(parseBooks('\u5b57')[0], { ascii: true }), /without an ASCII mapping/);
});

test('bundled field guides fit small libraries as individual books', async () => {
  const source = await readFile(new URL('../public/reader/field-guides.json', import.meta.url), 'utf8');
  const guides = parseBooks(source, 'field-guides.json');
  assert.deepEqual(guides.map(book => book.title), ['Survivor Guide', 'Land Navigation', 'First Aid']);
  for (const book of guides) {
    const pack = packBook(book, { ascii: true });
    assert.ok(pack.bytes.length < 4096, book.title);
    assert.deepEqual(unpack(pack), book);
  }
});

test('upload, inventory and removal use exact checksums and selected slot', async () => {
  const { bytes } = packBook(parseBooks('One.\n\nTwo.', 'My book.txt')[0]);
  let published = false;
  const chunks = [], calls = [];
  const reader = new ReaderLink(async command => {
    calls.push(command);
    if (command === 'rdb info') return `RDB INFO 1 4096 ${published ? 2 ** 31 : 0}`;
    if (command === 'rdb book 31') return `RDB BOOK 31 1 ${bytes.length} My book`;
    if (command === `rdb begin ${bytes.length}`) return 'RDB OK';
    if (command.startsWith('rdb data ')) {
      const [, , offset, hex] = command.split(' '), data = Buffer.from(hex, 'hex');
      assert.equal(+offset, chunks.reduce((n, chunk) => n + chunk.length, 0));
      assert.ok(data.length <= 76);
      chunks.push(data);
      return `RDB AT ${+offset + data.length}`;
    }
    if (command === `rdb commit ${crc32(bytes)}`) {
      assert.deepEqual([...Buffer.concat(chunks)], [...bytes]);
      published = true;
      return `RDB ADDED 31 ${crc32(bytes)}`;
    }
    if (command === `rdb remove 31 ${bytes.length} My book`) { published = false; return 'RDB OK'; }
    throw new Error(`Unexpected command: ${command}`);
  });
  assert.equal(await reader.add(bytes), 31);
  const inventory = await reader.inventory();
  assert.equal(inventory.books[0].title, 'My book');
  await reader.remove(inventory.books[0]);
  assert.deepEqual(await reader.inventory(), { free: 4096, books: [] });
  assert.ok(!calls.includes('rdb abort'));
});

test('interrupted transfers abort; low storage rejects before writing; changed port blocks mutations', async () => {
  const { bytes } = packBook(parseBooks('Some text.')[0]);
  const calls = [];
  let free = 4096, changed = false;
  const reader = new ReaderLink(async command => {
    calls.push(command);
    return command === 'rdb info' ? `RDB INFO 1 ${free} 0` : command.startsWith('rdb data ') ? 'RDB AT 1' : 'RDB OK';
  }, () => { if (changed) throw new Error('Selected port changed'); });
  await assert.rejects(reader.add(bytes), /wrong upload offset/);
  assert.equal(calls.at(-1), 'rdb abort');
  calls.length = 0;
  free = 3;
  await assert.rejects(reader.add(bytes), /Not enough room/);
  assert.deepEqual(calls, ['rdb info']);
  changed = true;
  await assert.rejects(reader.remove({ slot: 0, bytes: 100, title: 'Other radio' }), /Selected port changed/);
  assert.deepEqual(calls, ['rdb info']);
});

test('text-mode probe handles split echo and UTF-8 replies without a mode change', async () => {
  const encoder = new TextEncoder(), decoder = new TextDecoder(), queued = [];
  const link = {
    async write(data) {
      const command = decoder.decode(data).trim();
      const response = command === 'rdb info' ? 'RDB INFO 1 4096 1' : 'RDB BOOK 0 1 88 Caf\u00e9';
      const bytes = encoder.encode(`> ${command}\r\n${response}\r\n> `);
      for (let i = 0; i < bytes.length; i += 3) queued.push(bytes.subarray(i, i + 3));
    },
    async read() { return queued.shift() ?? new Uint8Array(); },
  };
  const reader = await openReader(link);
  assert.equal((await reader.inventory()).books[0].title, 'Caf\u00e9');
});
