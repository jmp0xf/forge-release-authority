from __future__ import annotations

import ast
import subprocess
import sys
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


MATERIALS_HELPER = textwrap.dedent("""
def runtime_materials(verifier):
    return verifier._ResolvedMaterials(
        cargo_lock=b"lock",
        source_license_notices=b"notice",
        authority_policy=verifier.AUTHORITY_POLICY_PATH.read_bytes(),
        authority_release_io=verifier.AUTHORITY_RELEASE_IO_PATH.read_bytes(),
        authority_release_io_posix=verifier.AUTHORITY_RELEASE_IO_POSIX_PATH.read_bytes(),
        authority_verifier=verifier.AUTHORITY_VERIFIER_PATH.read_bytes(),
    )
""").strip()


def script_with_materials(source: str) -> str:
    """Compose independently dedented fragments into one subprocess program."""
    return MATERIALS_HELPER + "\n\n" + textwrap.dedent(source)


class ReleaseIoLoadingTests(unittest.TestCase):
    def run_script(self, source: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, "-W", "error::ResourceWarning", "-c", source],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )

    def assert_script_ok(self, source: str) -> None:
        result = self.run_script(source)
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)

    def test_package_mode_verifies_bytes_before_execution_and_serializes_loaders(
        self,
    ) -> None:
        self.assert_script_ok(
            script_with_materials(
                """
                import sys
                import threading
                from scripts import verify_release as verifier

                materials = runtime_materials(verifier)
                original_verify = verifier._verify_local_authority_runtime
                events = []

                def observe(candidate):
                    events.append(
                        (
                            "scripts.release_io" in sys.modules,
                            "scripts.release_io_posix" in sys.modules,
                        )
                    )
                    return original_verify(candidate)

                verifier._verify_local_authority_runtime = observe
                barrier = threading.Barrier(8)
                results = []
                failures = []

                def load_again():
                    try:
                        barrier.wait()
                        results.append(verifier._load_release_io(materials))
                    except BaseException as error:
                        failures.append(error)

                threads = [threading.Thread(target=load_again) for _ in range(8)]
                for thread in threads:
                    thread.start()
                for thread in threads:
                    thread.join(timeout=10)
                assert not any(thread.is_alive() for thread in threads)
                assert not failures, failures
                assert len(results) == 8
                loaded = results[0]
                assert all(result is loaded for result in results)
                assert events[0] == (False, False)
                assert events[1:] == [(True, True)] * 7
                assert loaded.portable.__name__ == "scripts.release_io"
                assert loaded.posix.__name__ == "scripts.release_io_posix"
                assert loaded.posix.VerificationError is loaded.portable.VerificationError
                """
            )
        )

    def test_script_mode_verifies_bytes_before_execution(self) -> None:
        self.assert_script_ok(
            script_with_materials(
                f"""
                import runpy
                import sys
                from pathlib import Path

                root = Path({str(ROOT)!r})
                sys.path.insert(0, str(root / "scripts"))
                namespace = runpy.run_path(
                    str(root / "scripts" / "verify_release.py"),
                    run_name="_authority_verifier_script_mode_test",
                )
                load = namespace["_load_release_io"]
                runtime_globals = load.__globals__
                verifier = type("ScriptVerifier", (), runtime_globals)

                materials = runtime_materials(verifier)
                original_verify = runtime_globals["_verify_local_authority_runtime"]
                events = []

                def observe(candidate):
                    assert "release_io" not in sys.modules
                    assert "release_io_posix" not in sys.modules
                    events.append("verified")
                    return original_verify(candidate)

                runtime_globals["_verify_local_authority_runtime"] = observe
                loaded = load(materials)
                assert events == ["verified"]
                assert loaded.portable.__name__ == "release_io"
                assert loaded.posix.__name__ == "release_io_posix"
                assert loaded.posix.VerificationError is loaded.portable.VerificationError
                """
            )
        )

    def test_preloaded_alias_and_byte_mismatch_poison_the_process(self) -> None:
        self.assert_script_ok(
            script_with_materials(
                """
                import sys
                from scripts import release_io
                from scripts import verify_release as verifier

                materials = runtime_materials(verifier)
                try:
                    verifier._load_release_io(materials)
                except verifier.VerificationError as error:
                    assert "imported before byte binding" in str(error)
                else:
                    raise AssertionError("preloaded module was accepted")
                try:
                    verifier._load_release_io(materials)
                except verifier.VerificationError as error:
                    assert "permanently failed" in str(error)
                else:
                    raise AssertionError("poisoned loader retried")
                """
            )
        )

        self.assert_script_ok(
            script_with_materials(
                f"""
                import sys
                from pathlib import Path

                root = Path({str(ROOT)!r})
                sys.path.insert(0, str(root / "scripts"))
                import release_io
                from scripts import verify_release as verifier

                materials = runtime_materials(verifier)
                try:
                    verifier._load_release_io(materials)
                except verifier.VerificationError as error:
                    assert "imported before byte binding" in str(error)
                    assert "release_io" in str(error)
                else:
                    raise AssertionError("unqualified preloaded module was accepted")
                try:
                    verifier._load_release_io(materials)
                except verifier.VerificationError as error:
                    assert "permanently failed" in str(error)
                else:
                    raise AssertionError("poisoned loader retried")
                """
            )
        )

        self.assert_script_ok(
            script_with_materials(
                """
                import sys
                from scripts import verify_release as verifier

                materials = runtime_materials(verifier)
                changed = verifier._ResolvedMaterials(
                    cargo_lock=materials.cargo_lock,
                    source_license_notices=materials.source_license_notices,
                    authority_policy=materials.authority_policy,
                    authority_release_io=materials.authority_release_io + b"\\n#mismatch\\n",
                    authority_release_io_posix=materials.authority_release_io_posix,
                    authority_verifier=materials.authority_verifier,
                )
                try:
                    verifier._load_release_io(changed)
                except verifier.VerificationError as error:
                    assert "differs from the protected authority commit" in str(error)
                else:
                    raise AssertionError("runtime byte mismatch was accepted")
                assert verifier._release_io_state == verifier._RELEASE_IO_FAILED
                for name in (
                    "release_io",
                    "release_io_posix",
                    "scripts.release_io",
                    "scripts.release_io_posix",
                ):
                    assert name not in sys.modules, name
                try:
                    verifier._load_release_io(materials)
                except verifier.VerificationError as error:
                    assert "permanently failed" in str(error)
                else:
                    raise AssertionError("byte-mismatch poison was retried")
                """
            )
        )

    def test_executes_bound_bytes_not_replaced_source_or_unchecked_pyc(self) -> None:
        self.assert_script_ok(
            script_with_materials(
                """
                import py_compile
                import tempfile
                from pathlib import Path
                from scripts import verify_release as verifier

                materials = runtime_materials(verifier)
                with tempfile.TemporaryDirectory() as directory:
                    scripts = Path(directory)
                    portable_path = scripts / "release_io.py"
                    posix_path = scripts / "release_io_posix.py"

                    portable_path.write_text(
                        "PY_CACHE_WAS_EXECUTED = True\\n",
                        encoding="utf-8",
                    )
                    py_compile.compile(
                        str(portable_path),
                        doraise=True,
                        invalidation_mode=py_compile.PycInvalidationMode.UNCHECKED_HASH,
                    )
                    portable_path.write_bytes(materials.authority_release_io)
                    posix_path.write_bytes(materials.authority_release_io_posix)
                    verifier.AUTHORITY_RELEASE_IO_PATH = portable_path
                    verifier.AUTHORITY_RELEASE_IO_POSIX_PATH = posix_path

                    original_verify = verifier._verify_local_authority_runtime

                    def verify_then_replace(candidate):
                        runtime = original_verify(candidate)
                        portable_path.write_text(
                            "raise AssertionError('replaced source executed')\\n",
                            encoding="utf-8",
                        )
                        posix_path.write_text(
                            "raise AssertionError('replaced adapter executed')\\n",
                            encoding="utf-8",
                        )
                        return runtime

                    verifier._verify_local_authority_runtime = verify_then_replace
                    loaded = verifier._load_release_io(materials)
                    assert loaded.portable.__file__ == str(portable_path)
                    assert loaded.posix.__file__ == str(posix_path)
                    assert not hasattr(loaded.portable, "PY_CACHE_WAS_EXECUTED")
                    assert loaded.portable.require_safe_basename("ok", "name") == "ok"
                    assert loaded.posix.VerificationError is loaded.portable.VerificationError
                """
            )
        )

    def test_partial_bound_execution_failure_cleans_modules_and_poison_state(
        self,
    ) -> None:
        self.assert_script_ok(
            script_with_materials(
                """
                import sys
                import tempfile
                from pathlib import Path
                from scripts import verify_release as verifier

                materials = runtime_materials(verifier)
                failing_posix = b"raise RuntimeError('adapter failed')\\n"
                with tempfile.TemporaryDirectory() as directory:
                    scripts = Path(directory)
                    portable_path = scripts / "release_io.py"
                    posix_path = scripts / "release_io_posix.py"
                    portable_path.write_bytes(materials.authority_release_io)
                    posix_path.write_bytes(failing_posix)
                    verifier.AUTHORITY_RELEASE_IO_PATH = portable_path
                    verifier.AUTHORITY_RELEASE_IO_POSIX_PATH = posix_path
                    changed = verifier._ResolvedMaterials(
                        cargo_lock=materials.cargo_lock,
                        source_license_notices=materials.source_license_notices,
                        authority_policy=materials.authority_policy,
                        authority_release_io=materials.authority_release_io,
                        authority_release_io_posix=failing_posix,
                        authority_verifier=materials.authority_verifier,
                    )
                    try:
                        verifier._load_release_io(changed)
                    except verifier.VerificationError as error:
                        assert "execution failed" in str(error)
                    else:
                        raise AssertionError("failing adapter source was accepted")
                    for name in (
                        "release_io",
                        "release_io_posix",
                        "scripts.release_io",
                        "scripts.release_io_posix",
                    ):
                        assert name not in sys.modules, name
                    try:
                        verifier._load_release_io(materials)
                    except verifier.VerificationError as error:
                        assert "permanently failed" in str(error)
                    else:
                        raise AssertionError("failed execution was retried")
                """
            )
        )

    def test_swallowed_reentrant_load_still_cleans_and_poison_state(self) -> None:
        self.assert_script_ok(
            script_with_materials(
                """
                import sys
                from scripts import verify_release as verifier

                materials = runtime_materials(verifier)
                original_verify = verifier._verify_local_authority_runtime
                reentrant_errors = []

                def verify_and_swallow_reentry(candidate):
                    runtime = original_verify(candidate)
                    try:
                        verifier._load_release_io(materials)
                    except verifier.VerificationError as error:
                        reentrant_errors.append(str(error))
                    else:
                        raise AssertionError("reentrant load unexpectedly succeeded")
                    return runtime

                verifier._verify_local_authority_runtime = verify_and_swallow_reentry
                try:
                    verifier._load_release_io(materials)
                except verifier.VerificationError as error:
                    assert "state changed during binding" in str(error)
                else:
                    raise AssertionError("swallowed reentry was published")
                assert reentrant_errors == [
                    "Authority exact-I/O runtime loader re-entered"
                ]
                assert verifier._release_io_state == verifier._RELEASE_IO_FAILED
                assert verifier._LOADED_RELEASE_IO is None
                for name in (
                    "release_io",
                    "release_io_posix",
                    "scripts.release_io",
                    "scripts.release_io_posix",
                ):
                    assert name not in sys.modules, name
                try:
                    verifier._load_release_io(materials)
                except verifier.VerificationError as error:
                    assert "permanently failed" in str(error)
                else:
                    raise AssertionError("poisoned loader retried")
                """
            )
        )

    def test_runtime_imports_are_a_closed_standard_library_plus_sibling_set(
        self,
    ) -> None:
        allowed_siblings = {
            "verify_release.py": set(),
            "release_io.py": set(),
            "release_io_posix.py": {"release_io"},
        }
        dynamic_calls: dict[str, list[tuple[str, str | None]]] = {}

        class DynamicCallVisitor(ast.NodeVisitor):
            def __init__(self) -> None:
                self.function: str | None = None
                self.calls: list[tuple[str, str | None]] = []

            def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
                previous = self.function
                self.function = node.name
                self.generic_visit(node)
                self.function = previous

            def visit_Call(self, node: ast.Call) -> None:
                if isinstance(node.func, ast.Name):
                    name = node.func.id
                    candidates = {
                        "SourceFileLoader",
                        "__import__",
                        "compile",
                        "eval",
                        "exec",
                        "import_module",
                        "run_path",
                        "spec_from_file_location",
                    }
                elif isinstance(node.func, ast.Attribute):
                    name = node.func.attr
                    candidates = {
                        "SourceFileLoader",
                        "import_module",
                        "run_path",
                        "spec_from_file_location",
                    }
                else:
                    name = ""
                    candidates = set()
                if name in candidates:
                    self.calls.append((name, self.function))
                self.generic_visit(node)

        for filename, siblings in allowed_siblings.items():
            path = ROOT / "scripts" / filename
            tree = ast.parse(path.read_bytes(), filename=str(path))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        root = alias.name.split(".", 1)[0]
                        self.assertIn(root, sys.stdlib_module_names, (filename, root))
                elif isinstance(node, ast.ImportFrom):
                    module = node.module or ""
                    root = module.split(".", 1)[0]
                    if node.level:
                        self.assertEqual((node.level, module), (1, "release_io"))
                        self.assertIn(root, siblings)
                    else:
                        self.assertTrue(
                            root in sys.stdlib_module_names or root in siblings,
                            (filename, root),
                        )
            visitor = DynamicCallVisitor()
            visitor.visit(tree)
            dynamic_calls[filename] = visitor.calls

        self.assertEqual(
            dynamic_calls,
            {
                "verify_release.py": [
                    ("compile", "_execute_bound_authority_module"),
                    ("exec", "_execute_bound_authority_module"),
                ],
                "release_io.py": [],
                "release_io_posix.py": [],
            },
        )

    def test_runtime_repo_origin_module_footprint_is_exact(self) -> None:
        self.assert_script_ok(
            script_with_materials(
                """
                import sys
                from pathlib import Path
                from scripts import verify_release as verifier

                materials = runtime_materials(verifier)
                verifier._load_release_io(materials)
                root = verifier.AUTHORITY_ROOT.resolve()
                origins = {}
                for name, module in tuple(sys.modules.items()):
                    origin = getattr(module, "__file__", None)
                    if not isinstance(origin, str):
                        continue
                    try:
                        path = Path(origin).resolve(strict=True)
                    except (OSError, RuntimeError):
                        continue
                    if path.is_relative_to(root):
                        origins[name] = path.relative_to(root).as_posix()
                assert origins == {
                    "scripts.verify_release": "scripts/verify_release.py",
                    "scripts.release_io": "scripts/release_io.py",
                    "scripts.release_io_posix": "scripts/release_io_posix.py",
                }, origins
                """
            )
        )


if __name__ == "__main__":
    unittest.main()
