// `template` is imported but no call site exists in this module —
// leftover from a refactor.  CVE-2021-23337 is unreachable because
// the function is never invoked.
import { template, debounce, throttle } from 'lodash';

// debounce + throttle are actually used; template is dead.
export const queue = [];

export const enqueue = debounce((item) => {
  queue.push(item);
}, 100);

export const flush = throttle(() => {
  const out = queue.splice(0);
  return out;
}, 1000);
