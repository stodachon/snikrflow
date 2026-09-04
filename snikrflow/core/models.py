"""
SnikrFlow core models.

These are SnikrFlow-owned concepts. Nothing outside analysis/backends/angr/
should ever import angr or claripy types directly -- everything flows
through these dataclasses instead. This is what lets us swap or add
backends (Unicorn, Pin, Dyninst) later without touching the CLI, the
reporting layer, or the audit workflow.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class Architecture(str, Enum):
    X86 = "x86"
    X86_64 = "x86_64"
    ARM = "arm"
    ARM64 = "arm64"
    MIPS = "mips"
    MIPS64 = "mips64"
    UNKNOWN = "unknown"


class Endianness(str, Enum):
    LITTLE = "little"
    BIG = "big"
    UNKNOWN = "unknown"


class FunctionSource(str, Enum):
    """How SnikrFlow learned this function exists."""
    SYMBOL_TABLE = "symbol_table"
    ANGR_DISCOVERED = "angr_discovered"
    IMPORT = "import"
    PLT_STUB = "plt_stub"
    THUNK = "thunk"
    JNI_EXPORT = "jni_export"


class Confidence(str, Enum):
    """
    Required on every automated finding. This is the single most important
    field in SnikrFlow -- it's what stops a researcher from treating a
    heuristic guess as ground truth.
    """
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INCONCLUSIVE = "inconclusive"


# ---------------------------------------------------------------------------
# Binary-level metadata
# ---------------------------------------------------------------------------

@dataclass
class BinaryInfo:
    """Top-level facts about the loaded binary. Backs `snikrflow info`."""
    path: Path
    architecture: Architecture
    endianness: Endianness
    bitness: int                     # 32 or 64
    elf_type: str                    # e.g. "ET_DYN", "ET_EXEC"
    entry_point: int
    is_shared_object: bool
    is_stripped: bool

    section_count: int = 0
    segment_count: int = 0
    symbol_count: int = 0
    import_count: int = 0
    export_count: int = 0
    shared_deps: list[str] = field(default_factory=list)

    function_count: int = 0
    jni_candidate_count: int = 0


# ---------------------------------------------------------------------------
# Function-level model
# ---------------------------------------------------------------------------

@dataclass
class Function:
    """
    A SnikrFlow-owned representation of a function. This is NOT an angr
    Function object -- it's what we translate angr's (or a future backend's)
    notion of a function into, so the rest of the app never has to know
    which backend produced it.
    """
    address: int
    name: str
    size: Optional[int] = None

    source: FunctionSource = FunctionSource.ANGR_DISCOVERED
    has_symbol: bool = False
    is_imported: bool = False
    is_exported: bool = False
    is_plt_stub: bool = False
    is_thunk: bool = False

    is_jni_candidate: bool = False
    likely_java_class: Optional[str] = None
    likely_java_method: Optional[str] = None

    calling_convention: Optional[str] = None

    callers: list[int] = field(default_factory=list)
    callees: list[int] = field(default_factory=list)

    def short_label(self) -> str:
        return f"{self.name} @ {hex(self.address)}"


# ---------------------------------------------------------------------------
# Security sink model
# ---------------------------------------------------------------------------

@dataclass
class SinkCallSite:
    """A specific call to a sink, from a specific caller, at a specific address."""
    caller_address: int
    caller_name: str
    call_site_addresses: list[int] = field(default_factory=list)


@dataclass
class SecuritySink:
    """
    A security-sensitive function call site. Per the doc's terminology
    rules: this represents a "security-sensitive operation" or "possible
    attacker-controlled data" -- NEVER an automatic vulnerability
    classification.
    """
    address: int
    name: str
    category: str  # e.g. "memory", "process_execution", "filesystem", ...
    is_imported: bool
    call_sites: list[SinkCallSite] = field(default_factory=list)

    @property
    def caller_count(self) -> int:
        return len(self.call_sites)

    @property
    def total_call_site_count(self) -> int:
        return sum(len(cs.call_site_addresses) for cs in self.call_sites)


# ---------------------------------------------------------------------------
# CFG summary model
# ---------------------------------------------------------------------------

@dataclass
class CFGSummary:
    """Summary stats for `snikrflow cfg`. Full-graph export comes later."""
    function_count: int
    basic_block_count: int
    edge_count: int
    mode: str  # "fast" or "emulated"


# ---------------------------------------------------------------------------
# Reachability model
# ---------------------------------------------------------------------------

class ReachabilityType(str, Enum):
    """
    Per the doc's semantics rules: these are NOT interchangeable.
    STATICALLY_REACHABLE means "a direct call chain exists in the call
    graph" -- it says nothing about whether the data flowing through it
    is attacker-controlled, or whether the path is satisfiable at runtime.
    """
    STATICALLY_REACHABLE = "statically_reachable"
    SYMBOLICALLY_REACHABLE = "symbolically_reachable"
    RUNTIME_VERIFIED = "runtime_verified"
    NOT_REACHABLE = "not_reachable"
    INCONCLUSIVE = "inconclusive"


@dataclass
class AnalysisPath:
    """A (possible) path from a source function to a sink function."""
    source: int
    sink: int
    reachable: bool
    reachability_type: ReachabilityType
    function_path: list[int] = field(default_factory=list)
    path_labels: list[str] = field(default_factory=list)  # human-readable "name @ addr"
    confidence: Confidence = Confidence.MEDIUM
    note: Optional[str] = None


# ---------------------------------------------------------------------------
# Symbolic execution model
# ---------------------------------------------------------------------------

class SolverStatus(str, Enum):
    SAT = "sat"
    UNSAT = "unsat"
    UNKNOWN = "unknown"


@dataclass
class SymbolicResult:
    """
    Result of `snikrflow solve`. A candidate_input, if present, is a
    CANDIDATE satisfying the path's constraints -- never call this a
    confirmed exploit.
    """
    source: int
    target: int
    avoid: list[int] = field(default_factory=list)
    reachable: bool = False
    solver_status: SolverStatus = SolverStatus.UNKNOWN
    candidate_input: Optional[bytes] = None
    input_size: int = 0
    byte_constraints: list[str] = field(default_factory=list)
    states_explored: int = 0
    stopped_reason: Optional[str] = None
    confidence: Confidence = Confidence.INCONCLUSIVE
    note: Optional[str] = None


# ---------------------------------------------------------------------------
# Data flow model
# ---------------------------------------------------------------------------

class DataFlowStatus(str, Enum):
    """
    Per the doc: never collapse these. CONFIRMED is reserved for stronger
    evidence than a heuristic symbolic check alone can provide (e.g.
    future runtime verification) -- this milestone's analysis can only
    ever produce POSSIBLE or INCONCLUSIVE.
    """
    CONFIRMED = "confirmed"
    POSSIBLE = "possible"
    INCONCLUSIVE = "inconclusive"


@dataclass
class DataFlowResult:
    """
    Result of `snikrflow dataflow`: does the source's symbolic input
    appear to influence the value passed into the sink? Heuristic, not a
    sound full taint analysis.
    """
    source: int
    sink: int
    status: DataFlowStatus
    confidence: Confidence
    states_explored: int = 0
    stopped_reason: Optional[str] = None
    note: Optional[str] = None


# ---------------------------------------------------------------------------
# Audit models
# ---------------------------------------------------------------------------

class RiskLevel(str, Enum):
    """A transparent PRIORITIZATION signal, not proof of a vulnerability."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class AnalysisFinding:
    """One row of `snikrflow audit` output: a JNI-entry-to-sink path with its risk/confidence."""
    title: str
    source_address: int
    source_name: str
    sink_address: int
    sink_name: str
    sink_category: str
    reachability_type: ReachabilityType
    data_flow_status: Optional[DataFlowStatus] = None
    risk_level: RiskLevel = RiskLevel.LOW
    confidence: Confidence = Confidence.INCONCLUSIVE
    notes: list[str] = field(default_factory=list)


@dataclass
class AuditResult:
    """Full `snikrflow audit` output: binary summary + ranked findings."""
    binary_info: BinaryInfo
    function_count: int
    jni_count: int
    sink_count: int
    interesting_path_count: int      # statically-reachable JNI->sink pairs
    symbolic_analysis_count: int     # how many got deep (data-flow) analysis
    findings: list[AnalysisFinding] = field(default_factory=list)


# ---------------------------------------------------------------------------
# APK audit models
# ---------------------------------------------------------------------------

@dataclass
class ApkLibraryAudit:
    """Audit result for one native library extracted from an APK."""
    abi: str
    internal_path: str  # e.g. "lib/arm64-v8a/libfoo.so"
    library_name: str
    audit: Optional[AuditResult] = None
    error: Optional[str] = None
    extracted_path: Optional[Path] = None  # set only if --save-libs was used


@dataclass
class ApkAuditResult:
    """Full `snikrflow audit app.apk` output: one AuditResult per analyzed library."""
    apk_path: Path
    available_abis: list[str] = field(default_factory=list)
    analyzed: list[ApkLibraryAudit] = field(default_factory=list)