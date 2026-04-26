// Reachable use of qs.parse on user input — CVE-2022-24999.
const qs = require('qs');

function parseRequestBody(rawBody) {
  // qs.parse on attacker-controlled input is the trigger.
  // Pre-6.10.3 a payload like __proto__[admin]=true pollutes
  // every Object in the runtime.
  return qs.parse(rawBody);
}

module.exports = { parseRequestBody };
