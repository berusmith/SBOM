// Reachable use of lodash.defaultsDeep — CVE-2019-10744 prototype pollution.
const _ = require('lodash');

function applyUserDefaults(config, userOverrides) {
  // _.defaultsDeep is the CVE-2019-10744 trigger when userOverrides
  // contains a __proto__ key (e.g. {"__proto__": {"polluted": true}}).
  return _.defaultsDeep(config, userOverrides);
}

module.exports = { applyUserDefaults };
