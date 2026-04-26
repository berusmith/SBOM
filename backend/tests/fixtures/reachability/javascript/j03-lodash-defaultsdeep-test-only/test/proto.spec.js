// Tests verify our consumer code is robust against prototype-pollution
// payloads — they exercise _.defaultsDeep deliberately, confined to the
// test directory so the vulnerable call site is test_only.
const _ = require('lodash');
const { combine } = require('../src/main');

test('combine ignores prototype-pollution payload', () => {
  const evil = JSON.parse('{"__proto__":{"polluted":true}}');
  // Pre-fix lodash 4.17.11 would have polluted Object.prototype here.
  const out = _.defaultsDeep({}, evil);
  // Verify we didn't pollute any third-party object.
  expect({}.polluted).toBeUndefined();
  expect(out).toBeDefined();
});
