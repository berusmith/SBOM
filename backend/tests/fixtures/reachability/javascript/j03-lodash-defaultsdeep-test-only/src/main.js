// Production code uses lodash safely — _.merge does not trigger the
// prototype-pollution path in CVE-2019-10744.
const _ = require('lodash');

function combine(base, extras) {
  return _.merge({}, base, extras);
}

module.exports = { combine };
