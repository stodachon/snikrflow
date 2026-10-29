"""
CLI behaviour through Typer's CliRunner: exit codes, JSON output, and the
stdout/stderr split (the banner must never pollute --json output).
"""

import json
import zipfile

import pytest
from typer.testing import CliRunner

from snikrflow.cli import app

from conftest import FIXTURES, addr_of


def make_runner():
    # Click < 8.2 mixes stderr into .stdout unless told not to; 8.2+ always separates.
    try:
        return CliRunner(mix_stderr=False)
    except TypeError:
        return CliRunner()


runner = make_runner()
T1, T2, T3 = (str(FIXTURES / n) for n in ("test_target", "test_target2", "test_target3"))


def run(*args):
    return runner.invoke(app, [str(a) for a in args])


def parse_json(result):
    assert result.exit_code == 0, result.output
    return json.loads(result.stdout)       # raises if anything but JSON is on stdout


# --- version / banner -------------------------------------------------------

def test_version_flag_prints_version_and_no_banner():
    result = run("--version")
    assert result.exit_code == 0
    assert result.stdout.startswith("SnikrFlow v")
    assert "Stodachon" not in result.stdout


def test_version_command():
    result = run("version")
    assert result.exit_code == 0 and "SnikrFlow v" in result.stdout


def test_banner_goes_to_stderr_not_stdout():
    result = run("info", T1, "--json")
    assert result.exit_code == 0
    assert "Stodachon" in result.stderr           # banner attribution is on stderr...
    assert "Stodachon" not in result.stdout       # ...and stdout is clean
    json.loads(result.stdout)


# --- JSON output of each command --------------------------------------------

def test_info_json():
    data = parse_json(run("info", T1, "--json"))
    assert data["architecture"] == "x86_64"
    assert data["elf_type"] == "ET_EXEC"
    assert data["is_shared_object"] is False


def test_functions_json():
    names = {f["name"] for f in parse_json(run("functions", T1, "--json"))}
    assert {"check_password", "sink_reached", "main"} <= names


def test_jni_json():
    [f] = parse_json(run("jni", T3, "--json"))
    assert f["name"] == "Java_com_example_Native_parse"
    assert f["likely_java_class"] == "com.example.Native"
    assert f["likely_java_method"] == "parse"


def test_sinks_json():
    [sink] = parse_json(run("sinks", T3, "--json"))
    assert (sink["name"], sink["category"]) == ("strncpy", "memory")
    assert sink["call_sites"][0]["caller_name"] == "copy_it"


def test_cfg_json_and_bad_mode():
    data = parse_json(run("cfg", T1, "--json"))
    assert data["mode"] == "fast" and data["edge_count"] > 0
    bad = run("cfg", T1, "--cfg-mode", "bogus")
    assert bad.exit_code == 1 and "Unknown CFG mode" in bad.stdout


def test_callers_and_callees_json(target1):
    sink = hex(addr_of(target1, "sink_reached"))
    check = hex(addr_of(target1, "check_password"))
    assert [f["name"] for f in parse_json(run("callers", T1, sink, "--json"))] == ["check_password"]
    assert [f["name"] for f in parse_json(run("callees", T1, check, "--json"))] == ["sink_reached"]


def test_reach_json(target1):
    src, sink = hex(addr_of(target1, "check_password")), hex(addr_of(target1, "sink_reached"))
    data = parse_json(run("reach", T1, "--source", src, "--sink", sink, "--json"))
    assert data["reachable"] is True
    assert data["reachability_type"] == "statically_reachable"

    reverse = parse_json(run("reach", T1, "--source", sink, "--sink", src, "--json"))
    assert reverse["reachable"] is False and reverse["reachability_type"] == "not_reachable"


def test_solve_json(target1):
    src, tgt = hex(addr_of(target1, "check_password")), hex(addr_of(target1, "sink_reached"))
    data = parse_json(run("solve", T1, "--source", src, "--target", tgt, "--input-size", 8, "--json"))
    assert data["solver_status"] == "sat"
    assert data["candidate_input_hex"].startswith("536e696b")      # "Snik"
    assert "byte_constraints" not in data                          # only with --verbose
    verbose = parse_json(run("solve", T1, "--source", src, "--target", tgt, "--input-size", 8, "--json", "--verbose"))
    assert verbose["byte_constraints"][0] == "input[0] == 0x53"


def test_dataflow_json(target2):
    src, sink = hex(addr_of(target2, "relay")), hex(addr_of(target2, "strlen", plt=True))
    data = parse_json(run("dataflow", T2, "--source", src, "--sink", sink, "--json"))
    assert data["status"] == "possible"


def test_audit_json_and_sarif(tmp_path):
    sarif = tmp_path / "out.sarif"
    data = parse_json(run("audit", T3, "--json", "--deep-timeout", 60, "--sarif", sarif))
    [finding] = data["findings"]
    assert finding["sink"]["name"] == "strncpy"
    assert finding["risk_level"] == "high"
    doc = json.loads(sarif.read_text(encoding="utf-8"))
    assert doc["version"] == "2.1.0"
    assert doc["runs"][0]["results"][0]["level"] == "error"


def test_audit_accepts_an_apk(tmp_path):
    apk = tmp_path / "app.apk"
    with zipfile.ZipFile(apk, "w") as zf:
        zf.write(T3, "lib/x86_64/libjni.so")
    saved = tmp_path / "libs"
    data = parse_json(run("audit", apk, "--json", "--deep-timeout", 60, "--save-libs", saved))
    [lib] = data["analyzed"]
    assert lib["abi"] == "x86_64"
    assert lib["audit"]["findings"][0]["sink"]["name"] == "strncpy"
    assert (saved / "x86_64" / "libjni.so").exists()


# --- human-readable output ---------------------------------------------------

def test_audit_terminal_report_is_readable(tmp_path):
    result = run("audit", T3, "--deep-timeout", 60)
    assert result.exit_code == 0
    for expected in ("SnikrFlow Security Audit", "[HIGH]", "strncpy", "prioritization aid"):
        assert expected in result.stdout


# --- failure modes: clean errors, never tracebacks ---------------------------

@pytest.mark.parametrize("args", [
    ("info", "/definitely/not/here.so"),
    ("functions", "/definitely/not/here.so"),
    ("audit", "/definitely/not/here.so"),
])
def test_missing_file_is_a_clean_error(args):
    result = run(*args)
    assert result.exit_code == 1
    assert "File not found" in result.stdout
    assert "Traceback" not in result.output


def test_invalid_address_is_a_clean_error():
    result = run("callers", T1, "zzz")
    assert result.exit_code == 1
    assert "Invalid address" in result.stdout


def test_garbage_binary_is_a_clean_error(tmp_path):
    junk = tmp_path / "junk.so"
    junk.write_bytes(b"not an elf at all" * 10)
    result = run("info", junk)
    assert result.exit_code == 1
    assert "Traceback" not in result.output
