// ES6 default import of lodash, then call _.template — CVE-2021-23337.
import _ from 'lodash';

export function renderEmail(templateString, vars, sourceURL) {
  // sourceURL flows from request input — lodash.template w/ pre-4.17.21
  // interpolates it into eval'd code, achieving RCE.
  const compiled = _.template(templateString, { sourceURL });
  return compiled(vars);
}
