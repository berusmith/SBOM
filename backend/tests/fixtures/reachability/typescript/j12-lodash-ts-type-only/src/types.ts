// `import type` is a TS-only construct — it disappears at compile
// time, no runtime import is emitted.  CVE-2021-23337 is unreachable
// because lodash is never actually loaded.
import type { TemplateOptions, DebouncedFunc } from 'lodash';

export interface MyTemplateOptions extends TemplateOptions {
  customDelimiter?: string;
}

export type AnyDebounced<F extends (...args: any[]) => any> = DebouncedFunc<F>;

// Pure type-level code below — no runtime calls into lodash.
export function describe(opts: MyTemplateOptions): string {
  return `template with ${Object.keys(opts).length} options`;
}
