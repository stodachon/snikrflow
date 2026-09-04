"""
SnikrFlow terminal reporting.

All human-readable Rich output lives here. This module consumes SnikrFlow
models only (BinaryInfo, and later Function, AnalysisFinding, etc.) -- it
never touches angr or the loader directly. Keeping reporting decoupled
from analysis is what will let the future GUI reuse the same underlying
data without duplicating any logic.
"""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from snikrflow.core.models import (
    AnalysisFinding,
    AnalysisPath,
    ApkAuditResult,
    AuditResult,
    BinaryInfo,
    CFGSummary,
    DataFlowResult,
    DataFlowStatus,
    Function,
    RiskLevel,
    SecuritySink,
    SolverStatus,
    SymbolicResult,
)

console = Console()


def render_binary_info(info: BinaryInfo) -> None:
    table = Table.grid(padding=(0, 2))
    table.add_column(style="bold cyan", justify="right")
    table.add_column()

    table.add_row("File:", info.path.name)
    table.add_row("Format:", f"ELF{info.bitness}")
    table.add_row("Architecture:", info.architecture.value)
    table.add_row("Endianness:", info.endianness.value)
    table.add_row("Type:", _describe_elf_type(info))
    table.add_row("Entry:", hex(info.entry_point))
    table.add_row("Stripped:", "yes" if info.is_stripped else "no")
    table.add_row("", "")
    table.add_row("Sections:", str(info.section_count))
    table.add_row("Segments:", str(info.segment_count))
    table.add_row("Symbols:", str(info.symbol_count))
    table.add_row("Functions (symbol-based):", str(info.function_count))
    table.add_row("Exports:", str(info.export_count))
    table.add_row("Imports:", str(info.import_count))
    table.add_row("JNI candidates:", str(info.jni_candidate_count))

    if info.shared_deps:
        table.add_row("Dependencies:", ", ".join(info.shared_deps))

    console.print(
        Panel(
            table,
            title="[bold orange3]SnikrFlow[/bold orange3] :: info",
            border_style="orange3",
            expand=False,
        )
    )


def _describe_elf_type(info: BinaryInfo) -> str:
    if info.is_shared_object:
        return f"Shared Object ({info.elf_type})"
    return info.elf_type


def render_functions(functions: list[Function]) -> None:
    table = Table(
        title=f"SnikrFlow :: functions  ({len(functions)} discovered)",
        title_style="bold orange3",
        border_style="orange3",
        header_style="bold cyan",
    )
    table.add_column("Address", no_wrap=True)
    table.add_column("Name", overflow="fold")
    table.add_column("Size", justify="right")
    table.add_column("Symbol", justify="center")
    table.add_column("Imp", justify="center")
    table.add_column("Exp", justify="center")
    table.add_column("PLT", justify="center")
    table.add_column("JNI", justify="center")
    table.add_column("Source")

    for f in functions:
        table.add_row(
            hex(f.address),
            f.name,
            str(f.size) if f.size is not None else "-",
            "✓" if f.has_symbol else "",
            "✓" if f.is_imported else "",
            "✓" if f.is_exported else "",
            "✓" if f.is_plt_stub else "",
            "[bold yellow]✓[/bold yellow]" if f.is_jni_candidate else "",
            f.source.value,
        )

    console.print(table)


def render_jni_functions(functions: list[Function]) -> None:
    if not functions:
        console.print(
            "[yellow]No statically-exported JNI candidates found.[/yellow] "
            "(Dynamically registered JNI methods aren't detectable via static analysis.)"
        )
        return

    table = Table(
        title=f"SnikrFlow :: jni  ({len(functions)} candidates)",
        title_style="bold orange3",
        border_style="orange3",
        header_style="bold cyan",
    )
    table.add_column("Address", no_wrap=True)
    table.add_column("Export Name", overflow="fold")
    table.add_column("Likely Class", overflow="fold")
    table.add_column("Likely Method")
    table.add_column("Callers", justify="right")
    table.add_column("Callees", justify="right")

    for f in functions:
        table.add_row(
            hex(f.address),
            f.name,
            f.likely_java_class or "[dim]?[/dim]",
            f.likely_java_method or "[dim]?[/dim]",
            str(len(f.callers)),
            str(len(f.callees)),
        )

    console.print(table)
    console.print(
        "[dim]Class/method names are heuristic (best-effort demangling), "
        "not guaranteed accurate.[/dim]"
    )


def render_sinks(sinks: list[SecuritySink]) -> None:
    if not sinks:
        console.print("[yellow]No known security-sensitive sinks found.[/yellow]")
        return

    table = Table(
        title=f"SnikrFlow :: sinks  ({len(sinks)} security-sensitive operations)",
        title_style="bold orange3",
        border_style="orange3",
        header_style="bold cyan",
    )
    table.add_column("Address", no_wrap=True)
    table.add_column("Sink")
    table.add_column("Category")
    table.add_column("Callers", justify="right")
    table.add_column("Call Sites", justify="right")
    table.add_column("Called From (sample)", overflow="fold")

    for s in sinks:
        sample_callers = ", ".join(cs.caller_name for cs in s.call_sites[:3])
        if s.caller_count > 3:
            sample_callers += f", +{s.caller_count - 3} more"

        table.add_row(
            hex(s.address),
            s.name,
            s.category,
            str(s.caller_count),
            str(s.total_call_site_count),
            sample_callers or "[dim]none found[/dim]",
        )

    console.print(table)
    console.print(
        "[dim]These are security-sensitive operations, not confirmed "
        "vulnerabilities. Reachability and data-flow analysis (later "
        "milestones) determine whether attacker input can actually reach them.[/dim]"
    )


def render_cfg_summary(summary: CFGSummary) -> None:
    table = Table.grid(padding=(0, 2))
    table.add_column(style="bold cyan", justify="right")
    table.add_column()
    table.add_row("Mode:", summary.mode)
    table.add_row("Functions:", str(summary.function_count))
    table.add_row("Basic blocks:", str(summary.basic_block_count))
    table.add_row("Edges:", str(summary.edge_count))

    console.print(
        Panel(
            table,
            title="[bold orange3]SnikrFlow[/bold orange3] :: cfg",
            border_style="orange3",
            expand=False,
        )
    )


def render_call_list(functions: list[Function], direction: str, target_addr: int) -> None:
    label = "Callers of" if direction == "callers" else "Callees of"
    if not functions:
        console.print(
            f"[yellow]No direct {direction} found for {hex(target_addr)}.[/yellow] "
            "(Indirect/unresolved calls aren't included.)"
        )
        return

    table = Table(
        title=f"SnikrFlow :: {direction}  -- {label} {hex(target_addr)}",
        title_style="bold orange3",
        border_style="orange3",
        header_style="bold cyan",
    )
    table.add_column("Address", no_wrap=True)
    table.add_column("Name", overflow="fold")
    table.add_column("Source")

    for f in functions:
        table.add_row(hex(f.address), f.name, f.source.value)

    console.print(table)


def render_reachability(path: AnalysisPath) -> None:
    console.print()

    if path.path_labels:
        for i, label in enumerate(path.path_labels):
            if i == 0:
                console.print("[bold orange3]SOURCE[/bold orange3]")
            elif i == len(path.path_labels) - 1:
                console.print("  [dim]↓[/dim]")
                console.print("[bold orange3]SINK[/bold orange3]")
            else:
                console.print("  [dim]↓[/dim]")
            console.print(f"  {label}")
    else:
        console.print(f"Source: {hex(path.source)}")
        console.print(f"Sink:   {hex(path.sink)}")

    console.print()

    if path.reachability_type == path.reachability_type.STATICALLY_REACHABLE:
        result_style = "bold green"
        result_text = "REACHABLE"
    else:
        # NOT_REACHABLE and INCONCLUSIVE both get a cautious (non-green)
        # treatment -- absence of a found path is never presented as "safe".
        result_style = "bold yellow"
        result_text = path.reachability_type.value.upper().replace("_", " ")

    console.print(f"Result:     [{result_style}]{result_text}[/{result_style}]")
    console.print(f"Type:       {path.reachability_type.value}")
    console.print(f"Confidence: {path.confidence.value}")
    if path.note:
        console.print(f"[dim]{path.note}[/dim]")


def render_symbolic_result(result: SymbolicResult, verbose: bool = False) -> None:
    console.print()
    console.print(f"Source: {hex(result.source)}")
    console.print(f"Target: {hex(result.target)}")
    if result.avoid:
        console.print(f"Avoid:  {', '.join(hex(a) for a in result.avoid)}")
    console.print(f"Symbolic input size: {result.input_size} bytes")
    console.print(f"States explored: {result.states_explored}  (stopped: {result.stopped_reason})")
    console.print()

    status_styles = {
        SolverStatus.SAT: "bold green",
        SolverStatus.UNSAT: "bold red",
        SolverStatus.UNKNOWN: "bold yellow",
    }
    style = status_styles.get(result.solver_status, "bold yellow")
    console.print(f"Solver result: [{style}]{result.solver_status.value.upper()}[/{style}]")
    console.print(f"Confidence:    {result.confidence.value}")

    if result.candidate_input:
        console.print()
        console.print("Candidate input:")
        chunk = 16
        raw = result.candidate_input
        for i in range(0, len(raw), chunk):
            row = raw[i:i + chunk]
            hex_row = " ".join(f"{b:02x}" for b in row)
            ascii_row = "".join(chr(b) if 32 <= b < 127 else "." for b in row)
            console.print(f"  {hex_row:<48}  {ascii_row}")

    if verbose and result.byte_constraints:
        console.print()
        console.print("[dim]Per-byte constraints (--verbose):[/dim]")
        for c in result.byte_constraints:
            console.print(f"  {c}")

    if result.note:
        console.print()
        console.print(f"[dim]{result.note}[/dim]")


def render_data_flow(result: DataFlowResult) -> None:
    console.print()
    console.print(f"Source: {hex(result.source)}")
    console.print(f"Sink:   {hex(result.sink)}")
    console.print(f"States explored: {result.states_explored}  (stopped: {result.stopped_reason})")
    console.print()

    status_styles = {
        DataFlowStatus.CONFIRMED: "bold green",
        DataFlowStatus.POSSIBLE: "bold yellow",
        DataFlowStatus.INCONCLUSIVE: "dim",
    }
    style = status_styles.get(result.status, "dim")
    console.print(f"Result:     [{style}]{result.status.value.upper()}[/{style}]")
    console.print(f"Confidence: {result.confidence.value}")

    if result.note:
        console.print()
        console.print(f"[dim]{result.note}[/dim]")


def render_audit(result: AuditResult) -> None:
    info = result.binary_info

    console.print()
    console.print("[bold orange3]SnikrFlow Security Audit[/bold orange3]")
    console.print("[orange3]" + "\u2550" * 27 + "[/orange3]")

    console.print()
    console.print("[bold cyan]Binary[/bold cyan]")
    console.print(f"  Architecture: {info.architecture.value}")
    console.print(f"  Type:         {'Shared Object' if info.is_shared_object else info.elf_type}")

    console.print()
    console.print("[bold cyan]Functions[/bold cyan]")
    console.print(f"  {result.function_count} discovered")
    console.print(f"  {result.jni_count} JNI candidates")
    console.print(f"  {info.export_count} exported")

    console.print()
    console.print("[bold cyan]Security-sensitive operations[/bold cyan]")
    console.print(f"  {result.sink_count} identified")

    console.print()
    console.print("[bold cyan]Interesting paths[/bold cyan]")
    console.print(f"  {result.interesting_path_count} statically reachable")
    console.print(f"  {result.symbolic_analysis_count} selected for data-flow analysis")

    console.print()
    console.print("[bold cyan]Findings[/bold cyan]")

    if not result.findings:
        console.print("  [dim]None -- no statically-reachable JNI-to-sink paths found.[/dim]")
        console.print()
        return

    risk_styles = {
        RiskLevel.CRITICAL: "bold red",
        RiskLevel.HIGH: "bold orange3",
        RiskLevel.MEDIUM: "bold yellow",
        RiskLevel.LOW: "dim",
    }

    for f in result.findings:
        style = risk_styles.get(f.risk_level, "dim")
        console.print()
        console.print(f"  [{style}][{f.risk_level.value.upper()}][/{style}] {f.title}")
        console.print(f"    Source:     {f.source_name} @ {hex(f.source_address)}")
        console.print(f"    Sink:       {f.sink_name} @ {hex(f.sink_address)}  ({f.sink_category})")
        console.print(f"    Status:     {f.reachability_type.value}"
                       + (f", data flow: {f.data_flow_status.value}" if f.data_flow_status else ""))
        console.print(f"    Confidence: {f.confidence.value}")
        for note in f.notes:
            console.print(f"    [dim]- {note}[/dim]")

    console.print()
    console.print(
        "[dim]Risk levels are a prioritization aid, not confirmed "
        "vulnerabilities. Manual verification in Ghidra/GDB is still required.[/dim]"
    )
    console.print()


def render_apk_audit(result: ApkAuditResult) -> None:
    console.print()
    console.print(f"[bold orange3]SnikrFlow APK Audit[/bold orange3] :: {result.apk_path.name}")
    abis_str = ", ".join(result.available_abis) if result.available_abis else "[dim]none[/dim]"
    console.print(f"Available ABIs: {abis_str}")

    if not result.analyzed:
        console.print("[yellow]No native libraries (lib/<abi>/*.so) found in this APK.[/yellow]")
        return

    for lib in result.analyzed:
        console.print()
        console.print(f"[bold cyan]\u2500\u2500 {lib.library_name} ({lib.abi}) \u2500\u2500[/bold cyan]  {lib.internal_path}")
        if lib.error:
            console.print(f"  [bold red][!] Analysis failed:[/bold red] {lib.error}")
            continue
        if lib.extracted_path:
            console.print(f"  [dim]Saved to: {lib.extracted_path}[/dim]")
        render_audit(lib.audit)


def render_error(message: str) -> None:
    console.print(f"[bold red][!][/bold red] {message}")