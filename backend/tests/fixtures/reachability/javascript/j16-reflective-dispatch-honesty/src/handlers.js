// A small dispatch table.  Which entry is selected is decided in
// dispatch.js based on runtime input.
module.exports = {
  safe(payload) {
    return { kind: 'safe', payload };
  },
  fast(payload) {
    return { kind: 'fast', payload };
  },
  detailed(payload) {
    return { kind: 'detailed', size: JSON.stringify(payload).length };
  },
};
