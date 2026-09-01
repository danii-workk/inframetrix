"""Tests for the file walker."""

from pathlib import Path

from inframetrix.file_walker import collect_files


def test_collect_files_standard_extensions(tmp_path: Path):
    (tmp_path / "index.js").write_text("console.log(1);", encoding="utf-8")
    (tmp_path / "app.ts").write_text("const x = 1;", encoding="utf-8")
    (tmp_path / "module.mjs").write_text("export default 42;", encoding="utf-8")
    (tmp_path / "component.tsx").write_text("export const C = () => <div/>;", encoding="utf-8")
    (tmp_path / "script.py").write_text("print(1)", encoding="utf-8")
    (tmp_path / "ignored.bin").write_bytes(b"\x00\x01\x02")

    files = collect_files(tmp_path)
    filenames = [f.name for f in files]

    assert "index.js" in filenames
    assert "app.ts" in filenames
    assert "module.mjs" in filenames
    assert "component.tsx" in filenames
    assert "script.py" in filenames
    assert "ignored.bin" not in filenames


def test_collect_files_env_variations(tmp_path: Path):
    (tmp_path / ".env").write_text("A=1", encoding="utf-8")
    (tmp_path / ".env.local").write_text("B=2", encoding="utf-8")
    (tmp_path / ".env.staging").write_text("C=3", encoding="utf-8")
    (tmp_path / ".env.production").write_text("D=4", encoding="utf-8")

    files = collect_files(tmp_path)
    filenames = [f.name for f in files]

    assert ".env" in filenames
    assert ".env.local" in filenames
    assert ".env.staging" in filenames
    assert ".env.production" in filenames


def test_collect_files_dockerfiles(tmp_path: Path):
    (tmp_path / "Dockerfile").write_text("FROM alpine", encoding="utf-8")
    (tmp_path / "Dockerfile.dev").write_text("FROM alpine", encoding="utf-8")
    (tmp_path / "app.dockerfile").write_text("FROM alpine", encoding="utf-8")

    files = collect_files(tmp_path)
    filenames = [f.name for f in files]

    assert "Dockerfile" in filenames
    assert "Dockerfile.dev" in filenames
    assert "app.dockerfile" in filenames


def test_collect_files_ignores_directories(tmp_path: Path):
    git_dir = tmp_path / ".git"
    git_dir.mkdir()
    (git_dir / "config.yml").write_text("key: value", encoding="utf-8")

    node_modules = tmp_path / "node_modules"
    node_modules.mkdir()
    (node_modules / "pkg.json").write_text("{}", encoding="utf-8")

    src = tmp_path / "src"
    src.mkdir()
    (src / "valid.py").write_text("x = 1", encoding="utf-8")

    files = collect_files(tmp_path)
    filenames = [f.name for f in files]

    assert "valid.py" in filenames
    assert "config.yml" not in filenames
    assert "pkg.json" not in filenames
