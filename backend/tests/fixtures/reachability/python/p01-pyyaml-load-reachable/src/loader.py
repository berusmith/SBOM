"""Reachable use of yaml.load — the vulnerable symbol is called from a
main-code entry point with attacker-controlled input."""
import yaml


def load_config(path: str) -> dict:
    with open(path, encoding="utf-8") as f:
        # yaml.load without Loader= is the CVE-2020-1747 trigger
        return yaml.load(f.read())


if __name__ == "__main__":
    import sys
    print(load_config(sys.argv[1]))
