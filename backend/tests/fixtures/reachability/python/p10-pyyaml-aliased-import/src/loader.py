"""Same as p01 but with an aliased import — tests Phase 3 alias
tracking in the AST analyzer."""
import yaml as yl


def load_config(path: str) -> dict:
    with open(path, encoding="utf-8") as f:
        # `yl.load` resolves to `yaml.load` via the import alias
        return yl.load(f.read())


if __name__ == "__main__":
    import sys
    print(load_config(sys.argv[1]))
