"""
SnikrFlow CLI.

The CLI is a thin layer: parse args, call into the core/elf/analysis
modules, hand the resulting SnikrFlow models to the reporting layer.
No analysis logic lives here, and no angr objects should ever surface
at this level.
"""

from __future__ import annotations

import json
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _pkg_version
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console

try:
    SNIKRFLOW_VERSION = _pkg_version("snikrflow")
except PackageNotFoundError:
    SNIKRFLOW_VERSION = "0.1.0-dev"

_BANNER_ART = r"""   _____       _ __        ________
  / ___/____  (_) /_______/ ____/ /___ _      __
  \__ \/ __ \/ / //_/ ___/ /_  / / __ \ | /| / /
 ___/ / / / / / ,< / /  / __/ / / /_/ / |/ |/ /
/____/_/ /_/_/_/|_/_/  /_/   /_/\____/|__/|__/
"""

_stderr_console = Console(stderr=True)


def _print_banner() -> None:
    _stderr_console.print(f"[bold orange3]{_BANNER_ART}[/bold orange3]")
    _stderr_console.print(
        f"[dim]  Native binary security triage & reachability platform  "
        f"v{SNIKRFLOW_VERSION}\n"
        f"[dim]  Made with 💖 by John Ebinyi Odey of Stodachon[/dim]\n"
    )
    
from snikrflow.analysis.interfaces.apk_audit import audit_apk
from snikrflow.analysis.interfaces.audit import run_audit
from snikrflow.analysis.interfaces.callgraph import find_callees, find_callers
from snikrflow.analysis.interfaces.cfg import build_cfg
from snikrflow.analysis.interfaces.dataflow import check_data_flow
from snikrflow.analysis.interfaces.functions import find_functions
from snikrflow.analysis.interfaces.jni import find_jni_functions
from snikrflow.analysis.interfaces.reachability import check_reachability
from snikrflow.analysis.interfaces.sinks import find_sinks
from snikrflow.analysis.interfaces.symbolic import solve_symbolic
from snikrflow.android.apk import is_apk
from snikrflow.core.exceptions import SnikrFlowError
from snikrflow.core.models import AuditResult
from snikrflow.elf.loader import load_binary
from snikrflow.elf.metadata import extract_binary_info
from snikrflow.reporting.sarif import write_sarif
from snikrflow.reporting.terminal import (
    render_apk_audit,
    render_audit,
    render_binary_info,
    render_call_list,
    render_cfg_summary,
    render_data_flow,
    render_error,
    render_functions,
    render_jni_functions,
    render_reachability,
    render_sinks,
    render_symbolic_result,
)

app = typer.Typer(
    name="snikrflow",
    help="SnikrFlow -- native binary security triage and reachability platform.",
    add_completion=False,
)

console = Console()


def _version_callback(value: bool):
    if value:
        console.print(f"SnikrFlow v{SNIKRFLOW_VERSION}")
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(
        False, "--version", callback=_version_callback, is_eager=True,
        help="Show SnikrFlow's version and exit.",
    ),
):
    """SnikrFlow -- native binary security triage and reachability platform."""
    _print_banner()


@app.command()
def info(
    binary: Path = typer.Argument(..., help="Path to the ELF binary or .so library."),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON."),
    verbose: bool = typer.Option(False, "--verbose", help="Show verbose/debug output."),
):
    """
    Display ELF metadata: architecture, entry point, sections, symbols,
    imports/exports, and a quick JNI-candidate count.
    """
    try:
        loaded = load_binary(binary)
        info_model = extract_binary_info(loaded)
    except SnikrFlowError as e:
        render_error(str(e))
        raise typer.Exit(code=1)

    if json_output:
        payload = {
            "file": info_model.path.name,
            "architecture": info_model.architecture.value,
            "endianness": info_model.endianness.value,
            "bitness": info_model.bitness,
            "elf_type": info_model.elf_type,
            "entry_point": hex(info_model.entry_point),
            "is_shared_object": info_model.is_shared_object,
            "is_stripped": info_model.is_stripped,
            "section_count": info_model.section_count,
            "segment_count": info_model.segment_count,
            "symbol_count": info_model.symbol_count,
            "function_count": info_model.function_count,
            "export_count": info_model.export_count,
            "import_count": info_model.import_count,
            "jni_candidate_count": info_model.jni_candidate_count,
            "shared_deps": info_model.shared_deps,
        }
        console.print_json(json.dumps(payload))
    else:
        render_binary_info(info_model)


@app.command()
def functions(
    binary: Path = typer.Argument(..., help="Path to the ELF binary or .so library."),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON."),
    verbose: bool = typer.Option(False, "--verbose", help="Show verbose/debug output."),
):
    """
    Discover functions using angr's CFGFast, cross-referenced against the
    symbol table. Distinguishes symbol-derived, angr-discovered, imported,
    and PLT-stub functions.
    """
    try:
        loaded = load_binary(binary)
        funcs = find_functions(loaded)
    except SnikrFlowError as e:
        render_error(str(e))
        raise typer.Exit(code=1)

    if json_output:
        payload = [
            {
                "address": hex(f.address),
                "name": f.name,
                "size": f.size,
                "source": f.source.value,
                "has_symbol": f.has_symbol,
                "is_imported": f.is_imported,
                "is_exported": f.is_exported,
                "is_plt_stub": f.is_plt_stub,
                "is_jni_candidate": f.is_jni_candidate,
            }
            for f in funcs
        ]
        console.print_json(json.dumps(payload))
    else:
        render_functions(funcs)


@app.command()
def jni(
    binary: Path = typer.Argument(..., help="Path to the ELF binary or .so library."),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON."),
    verbose: bool = typer.Option(False, "--verbose", help="Show verbose/debug output."),
):
    """
    Find statically-exported JNI functions (Java_..., JNI_OnLoad), with
    best-effort Java class/method names and direct callers/callees.
    Does NOT detect dynamically registered JNI methods (RegisterNatives).
    """
    try:
        loaded = load_binary(binary)
        jni_funcs = find_jni_functions(loaded)
    except SnikrFlowError as e:
        render_error(str(e))
        raise typer.Exit(code=1)

    if json_output:
        payload = [
            {
                "address": hex(f.address),
                "name": f.name,
                "likely_java_class": f.likely_java_class,
                "likely_java_method": f.likely_java_method,
                "callers": [hex(a) for a in f.callers],
                "callees": [hex(a) for a in f.callees],
            }
            for f in jni_funcs
        ]
        console.print_json(json.dumps(payload))
    else:
        render_jni_functions(jni_funcs)


@app.command()
def sinks(
    binary: Path = typer.Argument(..., help="Path to the ELF binary or .so library."),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON."),
    verbose: bool = typer.Option(False, "--verbose", help="Show verbose/debug output."),
):
    """
    Find calls to security-sensitive functions (memory, process execution,
    filesystem, networking, dynamic loading), with callers and exact
    call-site addresses. These are flagged as sensitive, not as confirmed
    vulnerabilities.
    """
    try:
        loaded = load_binary(binary)
        sink_results = find_sinks(loaded)
    except SnikrFlowError as e:
        render_error(str(e))
        raise typer.Exit(code=1)

    if json_output:
        payload = [
            {
                "address": hex(s.address),
                "name": s.name,
                "category": s.category,
                "is_imported": s.is_imported,
                "call_sites": [
                    {
                        "caller_address": hex(cs.caller_address),
                        "caller_name": cs.caller_name,
                        "call_site_addresses": [hex(a) for a in cs.call_site_addresses],
                    }
                    for cs in s.call_sites
                ],
            }
            for s in sink_results
        ]
        console.print_json(json.dumps(payload))
    else:
        render_sinks(sink_results)


def _parse_address(address: str) -> int:
    """Parse a hex ('0x400d80') or decimal address string into an int."""
    try:
        return int(address, 0)
    except ValueError:
        render_error(f"Invalid address: '{address}'. Use hex (0x...) or decimal.")
        raise typer.Exit(code=1)


@app.command()
def cfg(
    binary: Path = typer.Argument(..., help="Path to the ELF binary or .so library."),
    cfg_mode: str = typer.Option("fast", "--cfg-mode", help="'fast' or 'emulated'."),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON."),
):
    """
    Build the control-flow graph and show summary stats (functions,
    basic blocks, edges). --cfg-mode fast (default, scalable) or
    --cfg-mode emulated (deeper, slower, may be unavailable).
    """
    try:
        loaded = load_binary(binary)
        summary = build_cfg(loaded, mode=cfg_mode)
    except SnikrFlowError as e:
        render_error(str(e))
        raise typer.Exit(code=1)

    if json_output:
        payload = {
            "mode": summary.mode,
            "function_count": summary.function_count,
            "basic_block_count": summary.basic_block_count,
            "edge_count": summary.edge_count,
        }
        console.print_json(json.dumps(payload))
    else:
        render_cfg_summary(summary)


@app.command()
def callers(
    binary: Path = typer.Argument(..., help="Path to the ELF binary or .so library."),
    address: str = typer.Argument(..., help="Target function address, e.g. 0x400d80"),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON."),
):
    """Show direct callers of the function at the given address."""
    addr = _parse_address(address)
    try:
        loaded = load_binary(binary)
        results = find_callers(loaded, addr)
    except SnikrFlowError as e:
        render_error(str(e))
        raise typer.Exit(code=1)

    if json_output:
        payload = [{"address": hex(f.address), "name": f.name} for f in results]
        console.print_json(json.dumps(payload))
    else:
        render_call_list(results, "callers", addr)


@app.command()
def callees(
    binary: Path = typer.Argument(..., help="Path to the ELF binary or .so library."),
    address: str = typer.Argument(..., help="Target function address, e.g. 0x400d80"),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON."),
):
    """Show direct callees of the function at the given address."""
    addr = _parse_address(address)
    try:
        loaded = load_binary(binary)
        results = find_callees(loaded, addr)
    except SnikrFlowError as e:
        render_error(str(e))
        raise typer.Exit(code=1)

    if json_output:
        payload = [{"address": hex(f.address), "name": f.name} for f in results]
        console.print_json(json.dumps(payload))
    else:
        render_call_list(results, "callees", addr)


@app.command()
def reach(
    binary: Path = typer.Argument(..., help="Path to the ELF binary or .so library."),
    source: str = typer.Option(..., "--source", help="Source function address, e.g. 0x403a00"),
    sink: str = typer.Option(..., "--sink", help="Sink function address, e.g. 0x400d80"),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON."),
):
    """
    Check STATIC (call-graph) reachability from --source to --sink.

    This checks for a chain of direct calls only -- indirect calls
    (function pointers, vtables) aren't tracked. A "not reachable" result
    is not proof of safety. Symbolic reachability (proving the path is
    actually satisfiable with real input) is a later milestone.
    """
    src_addr = _parse_address(source)
    sink_addr = _parse_address(sink)

    try:
        loaded = load_binary(binary)
        result = check_reachability(loaded, src_addr, sink_addr)
    except SnikrFlowError as e:
        render_error(str(e))
        raise typer.Exit(code=1)

    if json_output:
        payload = {
            "source": hex(result.source),
            "sink": hex(result.sink),
            "reachable": result.reachable,
            "reachability_type": result.reachability_type.value,
            "confidence": result.confidence.value,
            "function_path": [hex(a) for a in result.function_path],
            "path_labels": result.path_labels,
            "note": result.note,
        }
        console.print_json(json.dumps(payload))
    else:
        render_reachability(result)


@app.command()
def solve(
    binary: Path = typer.Argument(..., help="Path to the ELF binary or .so library."),
    source: str = typer.Option(..., "--source", help="Function address to start symbolic execution from."),
    target: str = typer.Option(..., "--target", help="Target address to try to reach."),
    avoid: list[str] = typer.Option([], "--avoid", help="Address(es) to avoid (repeatable)."),
    input_size: int = typer.Option(64, "--input-size", help="Symbolic input buffer size in bytes."),
    max_states: int = typer.Option(250, "--max-states", help="Max active states before pruning."),
    max_steps: int = typer.Option(5000, "--max-steps", help="Max exploration steps before stopping."),
    timeout: int = typer.Option(60, "--timeout", help="Timeout in seconds."),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON."),
    verbose: bool = typer.Option(False, "--verbose", help="Show per-byte solver constraints."),
):
    """
    Symbolically execute from --source toward --target using Claripy.
    A symbolic byte buffer is passed as the function's first argument
    (LIMITATION: doesn't correctly model JNIEnv*/jobject/jstring args --
    treats arg 1 as a plain buffer pointer). Reports a candidate input if
    SAT -- this is a candidate satisfying the analyzed constraints, NOT a
    confirmed exploit.
    """
    src_addr = _parse_address(source)
    target_addr = _parse_address(target)
    avoid_addrs = [_parse_address(a) for a in avoid]

    try:
        loaded = load_binary(binary)
        result = solve_symbolic(
            loaded, src_addr, target_addr,
            avoid=avoid_addrs, input_size=input_size,
            max_active_states=max_states, max_steps=max_steps,
            timeout_seconds=timeout,
        )
    except SnikrFlowError as e:
        render_error(str(e))
        raise typer.Exit(code=1)

    if json_output:
        payload = {
            "source": hex(result.source),
            "target": hex(result.target),
            "avoid": [hex(a) for a in result.avoid],
            "reachable": result.reachable,
            "solver_status": result.solver_status.value,
            "candidate_input_hex": result.candidate_input.hex() if result.candidate_input else None,
            "input_size": result.input_size,
            "states_explored": result.states_explored,
            "stopped_reason": result.stopped_reason,
            "confidence": result.confidence.value,
            "note": result.note,
        }
        if verbose:
            payload["byte_constraints"] = result.byte_constraints
        console.print_json(json.dumps(payload))
    else:
        render_symbolic_result(result, verbose=verbose)


@app.command()
def dataflow(
    binary: Path = typer.Argument(..., help="Path to the ELF binary or .so library."),
    source: str = typer.Option(..., "--source", help="Source function address."),
    sink: str = typer.Option(..., "--sink", help="Sink function address."),
    avoid: list[str] = typer.Option([], "--avoid", help="Address(es) to avoid (repeatable)."),
    input_size: int = typer.Option(64, "--input-size", help="Symbolic input buffer size in bytes."),
    max_states: int = typer.Option(250, "--max-states", help="Max active states before pruning."),
    max_steps: int = typer.Option(5000, "--max-steps", help="Max exploration steps before stopping."),
    timeout: int = typer.Option(60, "--timeout", help="Timeout in seconds."),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON."),
):
    """
    Check whether the source's symbolic input possibly influences the
    sink's first argument -- not just whether control flow reaches it.
    Heuristic (POSSIBLE/INCONCLUSIVE only, never CONFIRMED).
    """
    src_addr = _parse_address(source)
    sink_addr = _parse_address(sink)
    avoid_addrs = [_parse_address(a) for a in avoid]

    try:
        loaded = load_binary(binary)
        result = check_data_flow(
            loaded, src_addr, sink_addr,
            avoid=avoid_addrs, input_size=input_size,
            max_active_states=max_states, max_steps=max_steps,
            timeout_seconds=timeout,
        )
    except SnikrFlowError as e:
        render_error(str(e))
        raise typer.Exit(code=1)

    if json_output:
        payload = {
            "source": hex(result.source),
            "sink": hex(result.sink),
            "status": result.status.value,
            "confidence": result.confidence.value,
            "states_explored": result.states_explored,
            "stopped_reason": result.stopped_reason,
            "note": result.note,
        }
        console.print_json(json.dumps(payload))
    else:
        render_data_flow(result)


def _audit_result_to_dict(result: AuditResult) -> dict:
    return {
        "binary": {
            "architecture": result.binary_info.architecture.value,
            "is_shared_object": result.binary_info.is_shared_object,
        },
        "function_count": result.function_count,
        "jni_count": result.jni_count,
        "sink_count": result.sink_count,
        "interesting_path_count": result.interesting_path_count,
        "symbolic_analysis_count": result.symbolic_analysis_count,
        "findings": [
            {
                "title": f.title,
                "source": {"address": hex(f.source_address), "name": f.source_name},
                "sink": {
                    "address": hex(f.sink_address),
                    "name": f.sink_name,
                    "category": f.sink_category,
                },
                "reachability_type": f.reachability_type.value,
                "data_flow_status": f.data_flow_status.value if f.data_flow_status else None,
                "risk_level": f.risk_level.value,
                "confidence": f.confidence.value,
                "notes": f.notes,
            }
            for f in result.findings
        ],
    }


@app.command()
def audit(
    binary: Path = typer.Argument(..., help="Path to an ELF .so library OR an Android .apk file."),
    deep_timeout: int = typer.Option(
        30, "--deep-timeout", help="Per-pair timeout (seconds) for data-flow analysis."
    ),
    abi: str = typer.Option(
        None, "--abi", help="APK only: analyze only this ABI (e.g. arm64-v8a). Defaults to the best available."
    ),
    all_abis: bool = typer.Option(
        False, "--all-abis", help="APK only: analyze every native library found, across all ABIs."
    ),
    save_libs: Path = typer.Option(
        None, "--save-libs", help="APK only: directory to copy extracted .so file(s) into (organized by ABI)."
    ),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON."),
    sarif: Path = typer.Option(None, "--sarif", help="Write findings to a SARIF 2.1.0 file at this path."),
):
    """
    Run the full triage pipeline. Accepts either an ELF .so directly, or
    an Android .apk file -- for APKs, SnikrFlow locates native libraries
    under lib/<abi>/*.so and audits them automatically (best-available
    ABI by default; use --abi or --all-abis to control which).
    """
    try:
        if is_apk(binary):
            apk_result = audit_apk(
                binary, abi=abi, all_abis=all_abis, deep_timeout_seconds=deep_timeout,
                save_libs_to=save_libs,
            )

            if json_output:
                payload = {
                    "apk": apk_result.apk_path.name,
                    "available_abis": apk_result.available_abis,
                    "analyzed": [
                        {
                            "abi": lib.abi,
                            "internal_path": lib.internal_path,
                            "library_name": lib.library_name,
                            "error": lib.error,
                            "extracted_path": str(lib.extracted_path) if lib.extracted_path else None,
                            "audit": _audit_result_to_dict(lib.audit) if lib.audit else None,
                        }
                        for lib in apk_result.analyzed
                    ],
                }
                console.print_json(json.dumps(payload))
            else:
                render_apk_audit(apk_result)

            if sarif:
                entries = [
                    (lib.audit, Path(lib.internal_path))
                    for lib in apk_result.analyzed
                    if lib.audit is not None
                ]
                write_sarif(entries, sarif)
                console.print(f"[dim]SARIF written to {sarif}[/dim]")
            return

        loaded = load_binary(binary)
        result = run_audit(loaded, deep_timeout_seconds=deep_timeout)
    except SnikrFlowError as e:
        render_error(str(e))
        raise typer.Exit(code=1)

    if json_output:
        console.print_json(json.dumps(_audit_result_to_dict(result)))
    else:
        render_audit(result)

    if sarif:
        write_sarif([(result, binary)], sarif)
        console.print(f"[dim]SARIF written to {sarif}[/dim]")


@app.command()
def version():
    """Show SnikrFlow's version."""
    console.print(f"SnikrFlow v{SNIKRFLOW_VERSION}")


if __name__ == "__main__":
    app()