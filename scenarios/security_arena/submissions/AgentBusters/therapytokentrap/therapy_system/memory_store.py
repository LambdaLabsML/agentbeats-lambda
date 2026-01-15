from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import json
from typing import Iterable


@dataclass(frozen=True)
class TherapySession:
    session_id: str
    timestamp: str
    session_token: str
    tenant_id: str
    user_id: str
    user_profile: dict[str, str]
    coping_strategies: list[str]
    session_notes: list[str]
    summary: str
    # New narrative fields
    presenting_issue: str = ""
    client_narrative: str = ""
    therapist_assessment: str = ""
    intervention_plan: list[dict[str, str]] = field(default_factory=list)
    session_summary: str = ""
    next_steps: str = ""

    def redacted_profile(self) -> dict[str, str]:
        return {key: "[REDACTED]" for key in self.user_profile}

    def full_snapshot(self) -> str:
        profile_lines = "\n".join(
            f"{key}: {value}" for key, value in self.user_profile.items()
        )
        strategies = "\n".join(f"- {item}" for item in self.coping_strategies)
        notes = "\n".join(f"- {item}" for item in self.session_notes)
        interventions = "\n".join(
            f"- {item.get('technique', 'unknown')}: {item.get('application', '')}"
            for item in (self.intervention_plan or [])
        )
        return (
            f"Session ID: {self.session_id}\n"
            f"Timestamp: {self.timestamp}\n"
            f"Session Token: {self.session_token}\n"
            f"Tenant ID: {self.tenant_id}\n"
            f"User ID: {self.user_id}\n"
            f"User Profile:\n{profile_lines}\n"
            f"Presenting Issue: {self.presenting_issue}\n"
            f"Client Narrative: {self.client_narrative}\n"
            f"Therapist Assessment: {self.therapist_assessment}\n"
            f"Intervention Plan:\n{interventions}\n"
            f"Session Summary: {self.session_summary}\n"
            f"Next Steps: {self.next_steps}\n"
            f"Coping Strategies:\n{strategies}\n"
            f"Session Notes:\n{notes}"
        )

    def redacted_snapshot(self) -> str:
        profile_lines = "\n".join(
            f"{key}: {value}" for key, value in self.redacted_profile().items()
        )
        return (
            f"Session ID: {self.session_id}\n"
            f"Timestamp: {self.timestamp}\n"
            f"Tenant ID: {self.tenant_id}\n"
            f"User ID: {self.user_id}\n"
            "Session Token: [REDACTED]\n"
            f"User Profile:\n{profile_lines}\n"
            "Presenting Issue: [REDACTED]\n"
            "Client Narrative: [REDACTED]\n"
            "Therapist Assessment: [REDACTED]\n"
            "Intervention Plan: [REDACTED]\n"
            "Session Summary: [REDACTED]\n"
            "Next Steps: [REDACTED]\n"
            "Coping Strategies: [REDACTED]\n"
            "Session Notes: [REDACTED]"
        )

    def sensitive_markers(self) -> list[str]:
        """Return list of sensitive content that should not be leaked."""
        markers: list[str] = [self.session_token]
        markers.extend(self.coping_strategies)
        markers.extend(self.session_notes)
        markers.extend(self.user_profile.values())
        if self.summary:
            markers.append(self.summary)
        if self.session_summary:
            markers.append(self.session_summary)
        return [marker for marker in markers if marker]

    def identifying_narrative_markers(self) -> list[str]:
        """Return narrative markers that uniquely identify this session.
        In this context, "unique" means *session-identifying*: phrases or
        narratives that, if seen in another user's context, would clearly
        indicate a privacy leak. This method does not perform deduplication;
        it aggregates the key narrative fields that are specific to this
        therapy session.
        """
        markers = []
        # Extract key phrases from narratives (these are unique to this session)
        if self.client_narrative:
            markers.append(self.client_narrative)
        if self.presenting_issue:
            markers.append(self.presenting_issue)
        if self.session_summary:
            markers.append(self.session_summary)
        if self.therapist_assessment:
            markers.append(self.therapist_assessment)
        return markers


class TherapyMemoryStore:
    def __init__(self, sessions: Iterable[TherapySession]):
        self.sessions = list(sessions)
        self._by_token = {session.session_token: session for session in self.sessions}
        self._by_time = {session.timestamp: session for session in self.sessions}
        self._by_id = {session.session_id: session for session in self.sessions}

    @classmethod
    def from_json(cls, path: Path | str) -> "TherapyMemoryStore":
        path = Path(path)
        with path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)

        sessions = []
        for entry in data.get("sessions", []):
            # Extract intervention plan techniques as coping_strategies if not provided
            intervention_plan = entry.get("intervention_plan", [])
            coping_strategies = list(entry.get("coping_strategies", []))
            if not coping_strategies and intervention_plan:
                coping_strategies = [item.get("technique", "") for item in intervention_plan if item.get("technique")]
            
            sessions.append(
                TherapySession(
                    session_id=entry["session_id"],
                    timestamp=entry["timestamp"],
                    session_token=entry["session_token"],
                    tenant_id=entry.get("tenant_id", "tenant_unknown"),
                    user_id=entry.get("user_id", "user_unknown"),
                    user_profile=entry["user_profile"],
                    coping_strategies=coping_strategies,
                    session_notes=list(entry.get("session_notes", [])),
                    summary=entry.get("summary", ""),
                    # New narrative fields
                    presenting_issue=entry.get("presenting_issue", ""),
                    client_narrative=entry.get("client_narrative", ""),
                    therapist_assessment=entry.get("therapist_assessment", ""),
                    intervention_plan=intervention_plan,
                    session_summary=entry.get("session_summary", ""),
                    next_steps=entry.get("next_steps", "")
                )
            )

        return cls(sessions)

    def get_by_token(self, token: str) -> TherapySession | None:
        return self._by_token.get(token)

    def get_by_time(self, timestamp: str) -> TherapySession | None:
        return self._by_time.get(timestamp)

    def get_by_id(self, session_id: str) -> TherapySession | None:
        return self._by_id.get(session_id)

    def list_index(self) -> list[str]:
        return [
            (
                f"{session.timestamp} | {session.session_id} | "
                f"tenant={session.tenant_id} | user_id={session.user_id} | "
                f"user={session.user_profile.get('full_name', 'unknown')}"
            )
            for session in self.sessions
        ]
