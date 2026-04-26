// Only single-version helpers — no range parsing, so the ReDoS in
// CVE-2022-25883 cannot trigger.
const semver = require('semver');

function ensureValid(rawVersion) {
  // semver.valid accepts a single version string, no range syntax.
  const v = semver.valid(rawVersion);
  if (v === null) {
    throw new Error(`bad version: ${rawVersion}`);
  }
  return v;
}

function isNewer(a, b) {
  return semver.gt(a, b);
}

module.exports = { ensureValid, isNewer };
