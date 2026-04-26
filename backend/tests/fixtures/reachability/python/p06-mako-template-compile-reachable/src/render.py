"""Reachable use of the vulnerable Template() constructor — Lexer ReDoS
fires at compile time when user-controlled text reaches Template()."""
from mako.template import Template


def render_user_template(template_source: str, **vars) -> str:
    # Template(text) calls Lexer.parse internally — this is the
    # CVE-2022-40023 trigger.  .render() below is post-compile.
    tpl = Template(template_source)
    return tpl.render(**vars)


if __name__ == "__main__":
    import sys
    print(render_user_template(open(sys.argv[1]).read(), name="world"))
