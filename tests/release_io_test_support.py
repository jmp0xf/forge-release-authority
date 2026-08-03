from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType


ROOT = Path(__file__).resolve().parents[1]
PACKAGE_NAME = "_forge_authority_release_io_tests"


def _load(name: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot create test module spec for {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        sys.modules.pop(name, None)
        raise
    return module


def load_release_io_modules() -> tuple[ModuleType, ModuleType]:
    package = sys.modules.get(PACKAGE_NAME)
    if package is None:
        package = ModuleType(PACKAGE_NAME)
        package.__path__ = [str(ROOT / "scripts")]  # type: ignore[attr-defined]
        sys.modules[PACKAGE_NAME] = package
    portable_name = f"{PACKAGE_NAME}.release_io"
    posix_name = f"{PACKAGE_NAME}.release_io_posix"
    portable = sys.modules.get(portable_name)
    if portable is None:
        portable = _load(portable_name, ROOT / "scripts" / "release_io.py")
    posix = sys.modules.get(posix_name)
    if posix is None:
        posix = _load(posix_name, ROOT / "scripts" / "release_io_posix.py")
    return portable, posix
