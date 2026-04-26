// Reflective dispatch — handler module is statically known but the
// invoked property is computed at runtime from config/env.
// Production-realistic plugin pattern.
const handlers = require('./handlers');

function dispatch(req) {
  // The chosen handler comes from runtime state — no static
  // resolution possible.  Outputting `reachable` for any single
  // handler property would be a guess; only `unknown` is honest.
  const methodName = process.env.HANDLER_OVERRIDE || req.method || 'safe';
  return handlers[methodName](req.payload);
}

module.exports = { dispatch };
