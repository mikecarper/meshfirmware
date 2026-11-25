import { openReader, packBook, parseBooks, READER_MAX_SOURCE } from './reader-books.js';

const size = bytes => bytes < 1024 ? `${bytes} bytes` : `${(bytes / 1024).toFixed(1)} KiB`;

function bookText(book) {
  const chapters = book.chapters.map((chapter, index) => {
    const number = index + 1;
    const label = `Chapter ${number}`;
    const heading = chapter.title === label ? label : `${label}: ${chapter.title}`;
    const passages = chapter.passages.map((passage, i) => `[${number}:${i + 1}] ${passage}`);
    return [heading, ...passages].join('\n\n');
  });
  return [book.title, ...chapters].join('\n\n');
}

export function readerPanel({ $, operation, linkOperation, getTarget, allowed, busy, confirmRemove }) {
  let imported = [], packed = null, installed = [], inventory = null, verified = null;
  let guidesLoaded = false, guidesLoading = null;
  const guideAsset = new URL(`${import.meta.env?.BASE_URL ?? './'}reader/field-guides.json`, document.baseURI);
  const status = text => { $('reader-status').textContent = text; };
  const select = (id, labels, empty, keep = '') => {
    const node = $(id);
    node.replaceChildren(...(labels.length ? labels : [empty]).map((label, index) => {
      const option = document.createElement('option');
      option.value = labels.length ? String(index) : '';
      option.textContent = label;
      return option;
    }));
    node.value = !labels.length ? '' : labels[+keep] != null ? String(+keep) : '0';
  };
  const same = target => {
    const current = getTarget();
    return target && current.port === target.port && current.generation === target.generation;
  };
  function renderInventory(result, target) {
    const keep = $('reader-installed').value;
    verified = target;
    inventory = result;
    installed = result?.books ?? [];
    select('reader-installed', installed.map(book => book.bad ? book.title : `${book.title} (${size(book.bytes)})`), result ? 'No books loaded' : 'Library not read', keep);
    $('reader-free').textContent = result ? `${size(result.free)} available for books` : '';
  }
  function controls() {
    if (verified && !same(verified)) renderInventory(null, null);
    const locked = busy(), connected = allowed();
    $('reader-refresh').disabled = locked || !connected;
    $('reader-imported').disabled = locked || !imported.length;
    $('reader-installed').disabled = locked || !installed.length;
    $('reader-add').disabled = locked || !connected || !packed || (!!inventory && (inventory.free < packed.bytes.length || installed.length >= 32));
    $('reader-remove').disabled = locked || !connected || !installed.length;
  }
  function choose({ preserveStatus = false } = {}) {
    packed = null;
    $('reader-pack-size').textContent = '';
    const book = imported[+$('reader-imported').value];
    $('reader-text').textContent = book ? bookText(book) : 'Select a book to read.';
    if (book) {
      try {
        packed = packBook(book, { ascii: $('reader-ascii').checked });
        $('reader-pack-size').textContent = `${size(packed.bytes.length)} packed`;
        if (!preserveStatus) status('');
      } catch (error) { if (!preserveStatus) status(error.message); }
    }
    controls();
  }
  function importBooks(books, keepSelection = false) {
    if (imported.length + books.length > 1024) throw new Error('Import limit reached. Reload this tab to start a new collection.');
    const first = imported.length;
    imported = imported.concat(books);
    select('reader-imported', imported.map(book => book.title), 'No books imported', keepSelection && first ? $('reader-imported').value : first);
    choose({ preserveStatus: keepSelection });
  }
  const action = fn => operation(async () => {
    try { await fn(); } catch (error) { status(error.message || String(error)); }
  }, { scrollNextStep: false });
  const serialAction = fn => action(async () => {
    if (!allowed()) throw new Error('Choose the running application USB port.');
    const target = getTarget();
    const check = () => { if (!same(target) || !allowed()) throw new Error('The selected USB port changed. Refresh the radio library.'); };
    await linkOperation(async link => {
      check();
      const reader = await openReader(link, check);
      await fn(reader, target);
    });
  });
  $('reader-files').onchange = () => action(async () => {
    const files = Array.from($('reader-files').files);
    $('reader-files').value = '';
    if (!files.length) return;
    if (files.reduce((bytes, file) => bytes + file.size, 0) > READER_MAX_SOURCE) throw new Error('Select up to 16 MiB of UTF-8 text at a time.');
    const decoder = new TextDecoder('utf-8', { fatal: true });
    const books = [];
    for (const file of files) books.push(...parseBooks(decoder.decode(await file.arrayBuffer()), file.name));
    importBooks(books);
  });
  function loadGuides() {
    if (guidesLoaded) return Promise.resolve();
    if (guidesLoading) return guidesLoading;
    $('reader-guides').hidden = true;
    guidesLoading = (async () => { try {
      const response = await fetch(guideAsset);
      if (!response.ok) throw new Error('The field guides could not be loaded.');
      importBooks(parseBooks(await response.text(), 'field-guides.json'), true);
      guidesLoaded = true;
      $('reader-guide-status').textContent = '';
    } catch {
      $('reader-guides').hidden = false;
      if (!imported.length) select('reader-imported', [], 'No books available');
      $('reader-guide-status').textContent = 'The field guides could not be loaded. Try again.';
    } finally { guidesLoading = null; } })();
    return guidesLoading;
  }
  $('reader-guides').onclick = loadGuides;
  $('reader-imported').onchange = $('reader-ascii').onchange = () => choose();
  const refresh = async (reader, target) => renderInventory(await reader.inventory(), target);
  $('reader-refresh').onclick = () => serialAction(async (reader, target) => {
    status('Reading library...');
    await refresh(reader, target);
    status('Library read.');
  });
  $('reader-add').onclick = () => serialAction(async (reader, target) => {
    if (!packed) return;
    const { title, bytes } = packed;
    status(`Adding ${title}...`);
    let percent = -1;
    await reader.add(bytes, offset => {
      const next = Math.floor(offset * 100 / bytes.length);
      if (next !== percent) { status(`Adding ${title}: ${next}%`); percent = next; }
    });
    status(`Added ${title}.`);
    try { await refresh(reader, target); } catch { renderInventory(null, null); status(`Added ${title}. Refresh the library to check storage.`); }
  });
  $('reader-remove').onclick = () => serialAction(async (reader, target) => {
    if (!same(verified)) throw new Error('Read the library on this radio first.');
    const book = installed[+$('reader-installed').value];
    if (!book || !await confirmRemove(book)) return;
    await reader.remove(book);
    status(`Removed ${book.title}.`);
    try { await refresh(reader, target); } catch { renderInventory(null, null); status(`Removed ${book.title}. Refresh the library to check storage.`); }
  });
  void loadGuides();
  return { controls };
}
