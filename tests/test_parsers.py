from pathlib import Path
from analyzer.parsers import PythonParser, NodeParser, JavaParser, GoParser, RustParser


def test_python_parser(tmp_path):
    req_file = tmp_path / "requirements.txt"
    req_file.write_text("requests==2.25.1\nflask>=2.0.0\n# comment\n", encoding="utf-8")

    parser = PythonParser()
    assert parser.can_parse(req_file) is True

    deps = parser.parse(req_file)
    assert len(deps) == 2
    assert deps[0].name == "requests"
    assert deps[0].version == "2.25.1"
    assert deps[0].ecosystem == "PyPI"


def test_node_parser(tmp_path):
    pkg_file = tmp_path / "package.json"
    pkg_file.write_text('{"dependencies": {"express": "4.16.0"}, "devDependencies": {"jest": "^27.0.0"}}', encoding="utf-8")

    parser = NodeParser()
    assert parser.can_parse(pkg_file) is True

    deps = parser.parse(pkg_file)
    assert len(deps) == 2
    assert deps[0].name == "express"
    assert deps[0].version == "4.16.0"
    assert deps[0].is_direct is True
    assert deps[1].name == "jest"
    assert deps[1].is_direct is False


def test_go_parser(tmp_path):
    go_file = tmp_path / "go.mod"
    go_file.write_text("module myapp\n\ngo 1.18\n\nrequire (\n\tgithub.com/gin-gonic/gin v1.7.0\n)\n", encoding="utf-8")

    parser = GoParser()
    assert parser.can_parse(go_file) is True

    deps = parser.parse(go_file)
    assert len(deps) == 1
    assert deps[0].name == "github.com/gin-gonic/gin"
    assert deps[0].version == "1.7.0"
    assert deps[0].ecosystem == "Go"


def test_rust_parser(tmp_path):
    cargo_file = tmp_path / "Cargo.lock"
    cargo_file.write_text('[[package]]\nname = "tokio"\nversion = "1.20.0"\n', encoding="utf-8")

    parser = RustParser()
    assert parser.can_parse(cargo_file) is True

    deps = parser.parse(cargo_file)
    assert len(deps) == 1
    assert deps[0].name == "tokio"
    assert deps[0].version == "1.20.0"
    assert deps[0].ecosystem == "crates.io"
