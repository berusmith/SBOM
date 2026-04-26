"""Imports pyyaml but only the safe surface — no path to CVE-2020-1747."""
import yaml


def serialise(data: dict) -> str:
    # yaml.dump is the inverse direction; never deserialises.
    return yaml.dump(data, default_flow_style=False)


def parse_safe(text: str) -> dict:
    # yaml.safe_load uses SafeLoader explicitly — Python tags rejected.
    return yaml.safe_load(text)


if __name__ == "__main__":
    print(serialise({"hello": "world"}))
