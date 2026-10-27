export class BrowserPlanner {
  constructor({ worker, timeout = 180000 } = {}) {
    this.worker = worker || new Worker(new URL('./planner-worker.js', import.meta.url), { type: 'module' });
    this.pending = new Map(); this.serial = 0; this.timeout = timeout; this.closed = false;
    this.worker.onmessage = event => {
      const { id, result, error, download } = event.data || {};
      const pending = this.pending.get(id);
      if (!pending) return;
      this.pending.delete(id); clearTimeout(pending.timer);
      if (error) { const failure = new Error(error); failure.download = download; pending.reject(failure); }
      else pending.resolve(result);
    };
    this.worker.onerror = () => this.close('Browser validator failed to load or stopped. No flash is authorized.');
    this.worker.onmessageerror = () => this.close('Browser validator returned unreadable data. No flash is authorized.');
  }
  call(op, data) {
    if (this.closed) return Promise.reject(new Error('Browser validator is closed. Reload before trying again.'));
    return new Promise((resolve, reject) => {
      const id = ++this.serial;
      const timer = setTimeout(() => this.close('Browser validator timed out. No flash is authorized. Reload before trying again.'), this.timeout);
      this.pending.set(id, { resolve, reject, timer });
      try { this.worker.postMessage({ id, op, data }); } catch (error) { this.pending.delete(id); clearTimeout(timer); reject(error); }
    });
  }
  close(message = 'Browser validator closed.') {
    this.closed = true; this.worker.terminate();
    for (const pending of this.pending.values()) { clearTimeout(pending.timer); pending.reject(new Error(message)); }
    this.pending.clear();
  }
}
