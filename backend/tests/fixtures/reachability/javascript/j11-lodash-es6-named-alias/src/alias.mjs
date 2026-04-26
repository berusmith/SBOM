// ES6 named-import alias — `t` is the local name for lodash.template.
// Naïve regex scanning that just looks for the literal `template`
// identifier in call positions would miss this entirely.
import { template as t, escape as esc } from 'lodash';

export function buildSnippet(source, ctx, urlHint) {
  // sourceURL passed in from outside — the CVE-2021-23337 trigger.
  const fn = t(source, { sourceURL: urlHint });
  return esc(fn(ctx));
}
