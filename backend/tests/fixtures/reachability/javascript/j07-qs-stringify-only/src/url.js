// qs.stringify only — converts an object to URL-encoded form.
// CVE-2022-24999 is in the parse direction (URL → object); never
// fires from stringify alone.
const qs = require('qs');

function buildUrl(base, params) {
  const query = qs.stringify(params, { encode: true });
  return `${base}?${query}`;
}

module.exports = { buildUrl };
