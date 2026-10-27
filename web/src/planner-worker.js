// Python executes inside this browser worker in WebAssembly, never on the host.
import { createPlannerService } from './planner-runtime.js';

const service = createPlannerService();
// A single Python interpreter / filesystem must never process overlapping jobs.
let queue = Promise.resolve();
self.onmessage = event => {
  queue = queue.then(async () => {
    const { id, op, data } = event.data || {};
    try {
      self.postMessage({ id, result: await service.call(op, data) });
    } catch (error) {
      self.postMessage({ id, error: String(error.message || error), download: error.download || null });
    }
  });
};
