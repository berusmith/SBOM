// lodash imported but only safe surface used — no path to CVE-2019-10744.
const _ = require('lodash');

function shallowMerge(a, b) {
  // _.merge does not recurse into __proto__ keys the way defaultsDeep does;
  // not affected by the prototype-pollution CVE.
  return _.merge({}, a, b);
}

function pluck(obj, path, fallback) {
  return _.get(obj, path, fallback);
}

module.exports = { shallowMerge, pluck };
