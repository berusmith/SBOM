"""Production code uses pyyaml safely — no vulnerable symbol called here."""
import yaml


def parse_safe(text: str) -> dict:
    return yaml.safe_load(text)


if __name__ == "__main__":
    import sys
    print(parse_safe(open(sys.argv[1], encoding="utf-8").read()))
