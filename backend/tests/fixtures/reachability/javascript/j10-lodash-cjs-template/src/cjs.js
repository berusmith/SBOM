// CJS alias edge — `_` is the bound name for the lodash module via
// require().  Analyzer must trace _.template back to lodash.template.
const _ = require('lodash');

function compileBanner(tplSource, vars, customDelim) {
  // sourceURL flowing from external config triggers CVE-2021-23337
  // when evaluated by the compiled template function.
  const tpl = _.template(tplSource, { sourceURL: customDelim });
  return tpl(vars);
}

module.exports = { compileBanner };
