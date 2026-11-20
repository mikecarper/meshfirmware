import { deflateSync } from 'fflate';
import transliterate from '@sindresorhus/transliterate';
import { MeshCore } from './meshcore.js';
import { crc32 } from './firmware.js';

export const READER_MAX_SOURCE = 16 * 1024 * 1024;
const maxPack = 8 * 1024 * 1024, maxBlock = 768, slots = 32;
const encoder = new TextEncoder();
const clean = text => text.replace(/\s+/gu, ' ').trim();
const fail = message => { throw new Error(message); };

function numberedBooks(source) {
  const books = [];
  let book, chapter, chapterNumber = 0;
  for (const original of source.split('\n')) {
    const line = original.trim();
    if (!line) continue;
    const heading = /^###\s+(.+)$/.exec(line);
    if (heading) {
      book = { title: heading[1], chapters: [] };
      books.push(book);
      chapterNumber = 0;
      continue;
    }
    const passage = /^\[(\d+):(\d+)\]\s+(.+)$/.exec(line);
    if (!book || !passage) fail('Expected a book heading or numbered passage.');
    const [, chapterId, passageId, text] = passage;
    if (+chapterId !== chapterNumber) {
      if (+chapterId !== chapterNumber + 1) fail(`Unexpected chapter ${chapterId} in ${book.title}.`);
      ++chapterNumber;
      chapter = { title: `Chapter ${chapterId}`, passages: [] };
      book.chapters.push(chapter);
    }
    if (!chapter || +passageId !== chapter.passages.length + 1) fail(`Unexpected passage ${chapterId}:${passageId} in ${book.title}.`);
    chapter.passages.push(text);
  }
  return books;
}

function guideBook(articles, title) {
  const chapters = new Map();
  for (const article of articles) {
    if (typeof article.title !== 'string' || !article.title.trim()) fail('Every guide article needs a title.');
    const category = typeof article.category === 'string' && article.category.trim() || 'Articles';
    if (!chapters.has(category)) chapters.set(category, { title: category, passages: [] });
    const passages = chapters.get(category).passages;
    passages.push([article.title, typeof article.subtitle === 'string' ? article.subtitle : ''].filter(Boolean).join(': '));
    for (const [field, label] of [['steps', 'Step'], ['doNotDo', 'Avoid']]) {
      if (article[field] == null) continue;
      if (!Array.isArray(article[field]) || !article[field].every(item => typeof item === 'string')) fail(`Expected text entries in ${field}.`);
      for (const [index, item] of article[field].entries()) passages.push(`${label} ${index + 1}: ${item}`);
    }
  }
  return [{ title, chapters: [...chapters.values()] }];
}

function plainBook(source, title) {
  const chapters = [];
  let chapter = { title: 'Chapter 1', passages: [] }, paragraph = [];
  const flush = () => { if (paragraph.length) chapter.passages.push(paragraph.join(' ')); paragraph = []; };
  for (const original of source.split('\n')) {
    const line = original.trim();
    const heading = /^(#{1,6})\s+(.+)$/.exec(line);
    if (heading) {
      flush();
      if (heading[1] === '#' && !chapters.length && !chapter.passages.length && chapter.title === 'Chapter 1') title = heading[2];
      else {
        if (chapter.passages.length) chapters.push(chapter);
        chapter = { title: heading[2], passages: [] };
      }
    } else if (line) paragraph.push(line);
    else flush();
  }
  flush();
  if (chapter.passages.length) chapters.push(chapter);
  return [{ title, chapters }];
}

export function parseBooks(source, filename = 'Untitled book') {
  source = source.replace(/^\ufeff/, '').replace(/\r\n?/g, '\n');
  const title = filename.replace(/\.(?:txt|md|markdown|json)$/i, '').trim() || 'Untitled book';
  if (!source.trim() || source.length > READER_MAX_SOURCE || /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(source)) fail('Choose nonempty UTF-8 text, up to 16 MiB.');
  let books;
  if (/\.json$/i.test(filename) || /^[\s]*[\[{]\s*[{"\]]/u.test(source)) {
    const data = JSON.parse(source);
    if (Array.isArray(data) && data.length && data.every(article => article && !article.chapters && ('steps' in Object(article) || 'doNotDo' in Object(article)))) books = guideBook(data, title);
    else books = Array.isArray(data) ? data : data?.books ?? [data];
  } else if (/^###\s+\S[^\n]*\n(?:[ \t]*\n)*[ \t]*\[\d+:\d+\]/m.test(source)) books = numberedBooks(source);
  else books = plainBook(source, title);
  if (!Array.isArray(books) || !books.length || books.length > 1024) fail('Expected 1 to 1024 books.');
  return books.map(book => {
    if (typeof book?.title !== 'string' || !clean(book.title) || !Array.isArray(book.chapters) || !book.chapters.length) fail('Each book needs a title and at least one chapter.');
    return { title: clean(book.title), chapters: book.chapters.map((chapter, i) => {
      if (!Array.isArray(chapter?.passages) || !chapter.passages.length) fail('Every chapter needs passages.');
      return { title: typeof chapter.title === 'string' && clean(chapter.title) || `Chapter ${i + 1}`, passages: chapter.passages.map(passage => {
        if (typeof passage !== 'string' || !clean(passage) || /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(passage)) fail('Every passage must be nonempty text without control characters.');
        return clean(passage);
      }) };
    }) };
  });
}

function convert(text, ascii) {
  if (!ascii) return text;
  const result = clean(transliterate(text));
  if (!result || /[^\x20-\x7e]/.test(result)) fail('This book contains characters without an ASCII mapping. Turn off transliteration to keep them.');
  return result;
}

function truncateLabel(text, size) {
  if (/[\x00-\x1f\x7f]/.test(text)) fail('Book and chapter titles cannot contain control characters.');
  const bytes = encoder.encode(text);
  let end = Math.min(size - 1, bytes.length);
  while ((bytes[end] & 0xc0) === 0x80) --end;
  return bytes.subarray(0, end);
}

function* splitPassage(text) {
  // Retain all words, preferring a space at the boundary, and never split a
  // UTF-8 codepoint. Each passage is NUL terminated inside its block.
  const bytes = encoder.encode(text);
  for (let start = 0; start < bytes.length;) {
    let end = Math.min(start + maxBlock - 1, bytes.length);
    if (end < bytes.length) {
      while ((bytes[end] & 0xc0) === 0x80) --end;
      let space = end;
      while (space > start && bytes[space] !== 32) --space;
      if (space > start) end = space;
    }
    yield bytes.subarray(start, end);
    start = end;
    if (bytes[start] === 32) ++start;
  }
}

export function packBook(book, { ascii = false } = {}) {
  const title = truncateLabel(convert(book.title, ascii), 48);
  const chapters = [], passages = [], blocks = [];
  let block = new Uint8Array(maxBlock), used = 0, payloadBytes = 0, plainBytes = 0;
  function flush() {
    if (!used) return;
    const compressed = deflateSync(block.subarray(0, used), { level: 6 });
    blocks.push({ compressed, payloadBytes, plain: used });
    payloadBytes += compressed.length;
    plainBytes += used;
    if (payloadBytes > maxPack) fail('Book exceeds the 8 MiB pack limit. Split it into smaller books.');
    block = new Uint8Array(maxBlock);
    used = 0;
  }
  for (const chapter of book.chapters) {
    const first = passages.length;
    for (const passage of chapter.passages) {
      for (const bytes of splitPassage(convert(passage, ascii))) {
        if (used + bytes.length + 1 > maxBlock) flush();
        passages.push({ block: blocks.length, start: used });
        if (passages.length > 65535) fail('Book has more than 65,535 passages. Split it into smaller books.');
        block.set(bytes, used);
        used += bytes.length + 1;
      }
    }
    chapters.push({ title: truncateLabel(convert(chapter.title, ascii), 32), first, count: passages.length - first });
  }
  flush();
  const table = 64 + 36 * chapters.length, body = table + 10 * passages.length;
  if (body + payloadBytes > maxPack) fail('Book exceeds the 8 MiB pack limit. Split it into smaller books.');
  const bytes = new Uint8Array(body + payloadBytes), view = new DataView(bytes.buffer);
  const u16 = (at, n) => view.setUint16(at, n, true), u32 = (at, n) => view.setUint32(at, n, true);
  bytes.set(encoder.encode('MRB1'));
  u32(4, bytes.length); u16(8, chapters.length); u16(10, passages.length);
  bytes.set(title, 12);
  chapters.forEach((chapter, i) => {
    const at = 64 + i * 36;
    u16(at, chapter.first); u16(at + 2, chapter.count); bytes.set(chapter.title, at + 4);
  });
  passages.forEach((passage, i) => {
    const at = table + 10 * i, block = blocks[passage.block];
    u32(at, body + block.payloadBytes); u16(at + 4, block.compressed.length);
    u16(at + 6, block.plain); u16(at + 8, passage.start);
  });
  for (const block of blocks) bytes.set(block.compressed, body + block.payloadBytes);
  return { bytes, plainBytes, title: new TextDecoder().decode(title) };
}

function readInfo(reply) {
  const match = /^RDB INFO 1 (\d{1,10}) (\d{1,10})$/.exec(reply);
  if (!match || +match[1] > 0xffffffff || +match[2] > 0xffffffff) return null;
  return { free: +match[1], mask: +match[2] };
}

export async function textReaderCommand(link, command, timeout = 2500) {
  await link.write(encoder.encode(command + '\r\n'));
  const decoder = new TextDecoder(), until = Date.now() + timeout;
  let pending = '';
  while (Date.now() < until) {
    const chunk = await link.read(Math.min(100, Math.max(1, until - Date.now())), 4096);
    pending += decoder.decode(chunk, { stream: true });
    const lines = pending.split(/[\r\n]/);
    pending = lines.pop();
    for (const line of lines) if (line.startsWith('RDB ')) return line;
    if (pending.length > 4096) pending = '';
  }
  return '';
}

export async function openReader(link, assertCurrent = () => {}) {
  // Use either physical USB mode without changing logging or firmware settings.
  let send = command => textReaderCommand(link, command, command === 'rdb info' ? 1000 : 2500);
  let reply = await send('rdb info');
  if (!readInfo(reply) && !reply.startsWith('RDB ERR ')) {
    const binary = new MeshCore(link, { timeoutMs: 2500 });
    send = command => binary.cli(command);
    try { reply = await send('rdb info'); } catch { reply = ''; }
  }
  assertCurrent();
  if (reply.startsWith('RDB ERR ')) fail(reply.slice(8));
  if (!readInfo(reply)) fail('Reader books are unavailable on this port. Select a running Full Companion with Reader library support.');
  return new ReaderLink(send, assertCurrent);
}

export class ReaderLink {
  constructor(send, assertCurrent = () => {}) { this.send = send; this.assertCurrent = assertCurrent; }
  async command(command) {
    this.assertCurrent();
    const response = await this.send(`rdb ${command}`);
    this.assertCurrent();
    if (response.startsWith('RDB ERR ')) fail(response.slice(8));
    if (!response.startsWith('RDB ')) fail('Reader did not acknowledge the command.');
    return response;
  }
  async inventory() {
    const info = readInfo(await this.command('info'));
    if (!info) fail('Invalid Reader storage response.');
    const books = [];
    for (let slot = 0; slot < slots; ++slot) if ((info.mask >>> slot) & 1) {
      const reply = await this.command(`book ${slot}`);
      if (reply === `RDB BAD ${slot}`) { books.push({ slot, title: `Unreadable book in slot ${slot + 1}`, bad: true }); continue; }
      const match = /^RDB BOOK (\d{1,2}) (\d{1,5}) (\d{1,8}) ([^\x00-\x1f\x7f]+)$/.exec(reply);
      if (!match || +match[1] !== slot || +match[2] < 1 || +match[3] > maxPack || +match[3] <= 64) fail('Invalid Reader book response.');
      books.push({ slot, chapters: +match[2], bytes: +match[3], title: match[4] });
    }
    return { free: info.free, books };
  }
  async add(bytes, report = () => {}) {
    const checksum = crc32(bytes);
    const info = readInfo(await this.command('info'));
    if (!info || info.mask === 0xffffffff || bytes.length > info.free) fail('Not enough room in the Reader library for this book.');
    if (await this.command(`begin ${bytes.length}`) !== 'RDB OK') fail('The radio did not open book storage.');
    let committed = false;
    try {
      for (let offset = 0; offset < bytes.length; offset += 76) {
        const chunk = bytes.subarray(offset, offset + 76);
        const hex = Array.from(chunk, byte => byte.toString(16).padStart(2, '0')).join('');
        if (await this.command(`data ${offset} ${hex}`) !== `RDB AT ${offset + chunk.length}`) fail('Reader acknowledged the wrong upload offset.');
        report(offset + chunk.length);
      }
      const reply = /^RDB ADDED (\d{1,2}) (\d{1,10})$/.exec(await this.command(`commit ${checksum}`));
      if (!reply || +reply[1] >= slots || ((info.mask >>> +reply[1]) & 1) || +reply[2] !== checksum) fail('The upload did not verify. Refresh the library before retrying.');
      committed = true;
      return +reply[1];
    } finally {
      if (!committed) await this.command('abort').catch(() => {});
    }
  }
  async remove(book) {
    if (await this.command(book.bad ? `remove-bad ${book.slot}` : `remove ${book.slot} ${book.bytes} ${book.title}`) !== 'RDB OK') fail('The radio did not confirm removal.');
  }
}
