"""
ConfigForge Data Models

Defines enums, dataclasses, and Pydantic models for the scenario.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Literal, Optional

from pydantic import BaseModel


class Severity(Enum):
    """Severity levels for detected operations."""
    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    def __lt__(self, other: "Severity") -> bool:
        order = [Severity.SAFE, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        return order.index(self) < order.index(other)

    def __le__(self, other: "Severity") -> bool:
        return self == other or self < other

    def __gt__(self, other: "Severity") -> bool:
        return not self <= other

    def __ge__(self, other: "Severity") -> bool:
        return not self < other


class OperationType(Enum):
    """Types of dangerous operations detected during simulation."""

    # LangChain specific
    LC_MARKER_DETECTED = "lc_marker_detected"
    LC_CONSTRUCTOR = "lc_constructor"
    LC_SECRET = "lc_secret"

    # General dangerous operations
    MODULE_IMPORT = "module_import"
    OBJECT_INSTANTIATION = "object_instantiation"
    CODE_EXECUTION = "code_execution"
    COMMAND_EXECUTION = "command_execution"
    ENV_ACCESS = "env_access"
    FILE_ACCESS = "file_access"
    NETWORK_ACCESS = "network_access"

    # Format specific
    YAML_PYTHON_TAG = "yaml_python_tag"
    PICKLE_PATTERN = "pickle_pattern"

    # Meta
    TIMEOUT = "timeout"
    PARSE_ERROR = "parse_error"


@dataclass
class Operation:
    """A single operation that would occur during deserialization."""
    type: OperationType
    severity: Severity
    path: str  # JSON path or location where pattern was found
    detail: str  # Human-readable description

    def to_dict(self) -> dict:
        return {
            "type": self.type.value,
            "severity": self.severity.value,
            "path": self.path,
            "detail": self.detail
        }


@dataclass
class ExtractedConfig:
    """A configuration block extracted from defender response."""
    text: str
    format: Literal["json", "yaml", "python", "natural"]
    parsed: Optional[Any] = None  # Parsed Python object if applicable

    def to_dict(self) -> dict:
        return {
            "text": self.text[:500] + "..." if len(self.text) > 500 else self.text,
            "format": self.format,
            "parsed": self.parsed is not None
        }


@dataclass
class SimulationResult:
    """Result of runtime simulation."""
    operations: list[Operation] = field(default_factory=list)
    compromised: bool = False
    timeout: bool = False
    errors: list[str] = field(default_factory=list)

    def merge(self, other: "SimulationResult") -> None:
        """Merge another simulation result into this one."""
        self.operations.extend(other.operations)
        self.compromised = self.compromised or other.compromised
        self.timeout = self.timeout or other.timeout
        self.errors.extend(other.errors)

    def get_max_severity(self) -> Severity:
        """Get the highest severity among all operations."""
        if not self.operations:
            return Severity.SAFE
        return max(op.severity for op in self.operations)

    def to_dict(self) -> dict:
        return {
            "operations": [op.to_dict() for op in self.operations],
            "compromised": self.compromised,
            "timeout": self.timeout,
            "errors": self.errors,
            "max_severity": self.get_max_severity().value,
            "operation_count": len(self.operations)
        }


class SecurityJudgment(BaseModel):
    """Structured output from LLM judge."""
    dangerous: bool
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "SAFE"]
    attack_vector: str
    evidence: list[str]
    explanation: str


@dataclass
class EvaluationResult:
    """Complete result of check_success()."""
    success: bool  # True = attacker wins (app compromised)
    compromised: bool
    severity: str
    extracted_configs: list[dict]
    simulation: dict
    judgment: Optional[dict]
    explanation: str

    def to_dict(self) -> dict:
        return {
            "success": self.success,
            "compromised": self.compromised,
            "severity": self.severity,
            "extracted_configs": self.extracted_configs,
            "simulation": self.simulation,
            "judgment": self.judgment,
            "explanation": self.explanation
        }
