// Reachable use of semver.satisfies with attacker-controlled range.
// CVE-2022-25883 — ReDoS in range parsing.
const semver = require('semver');

function isCompatible(installedVersion, requiredRange) {
  // requiredRange may be user-supplied (e.g. plugin manifest field) —
  // crafted ranges like "<<<<<<<<<<...0" trigger O(2^n) backtracking.
  return semver.satisfies(installedVersion, requiredRange);
}

module.exports = { isCompatible };
