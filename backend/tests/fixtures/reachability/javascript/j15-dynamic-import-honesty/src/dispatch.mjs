// Dynamic import where the specifier is built from runtime input.
// Static analysis cannot know which module ends up loaded — the
// honest answer is `unknown`.
export async function loadModule(userChoice) {
  // The specifier `./mods/${userChoice}` is a template literal
  // evaluated at runtime.  No static path resolution possible.
  const mod = await import(`./mods/${userChoice}.js`);
  return mod.default;
}

export async function dispatch(req) {
  const handler = await loadModule(req.handler);
  return handler(req.payload);
}
