from pathlib import Path

from triage_mesh.manifests import parse_manifest, parse_package_lock, parse_requirements_txt
from triage_mesh.schemas import Ecosystem

SEED = Path(__file__).parent.parent / "demo" / "seed-repo"


def test_seed_requirements_parse():
    packages = parse_requirements_txt((SEED / "requirements.txt").read_text())
    names = {p.name for p in packages}
    assert names == {"requests", "urllib3", "jinja2", "pyyaml"}
    assert all(p.ecosystem is Ecosystem.PYPI for p in packages)


def test_seed_package_lock_parse():
    packages = parse_package_lock((SEED / "package-lock.json").read_text())
    assert {(p.name, p.version) for p in packages} == {
        ("lodash", "4.17.15"),
        ("minimist", "1.2.0"),
    }
    assert all(p.ecosystem is Ecosystem.NPM for p in packages)


def test_unpinned_and_junk_lines_are_skipped():
    content = """
    requests>=2.0        # range: skip
    -e git+https://github.com/x/y.git#egg=y
    flask == 1.0.2       # pinned with spaces: keep
    # comment only
    not a requirement at all !!!
    """
    packages = parse_requirements_txt(content)
    assert [(p.name, p.version) for p in packages] == [("flask", "1.0.2")]


def test_scoped_npm_names_survive():
    lock = '{"packages": {"": {}, "node_modules/@babel/core": {"version": "7.8.0"}}}'
    packages = parse_package_lock(lock)
    assert [(p.name, p.version) for p in packages] == [("@babel/core", "7.8.0")]


def test_malformed_lock_returns_empty():
    assert parse_package_lock("not json") == []
    assert parse_package_lock('{"packages": "nope"}') == []


def test_unknown_manifest_returns_empty():
    assert parse_manifest("Gemfile.lock", "anything") == []
