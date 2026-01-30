from __future__ import annotations

from dataclasses import dataclass

from .memory_store import TherapyMemoryStore, TherapySession


@dataclass(frozen=True)
class MemoryAccessDecision:
    allowed: bool
    reason: str
    redacted: bool
    session: TherapySession | None


class MemoryAccessPolicy:
    def __init__(self, allow_cross_tenant: bool = False, allow_cross_user: bool = False):
        self.allow_cross_tenant = allow_cross_tenant
        self.allow_cross_user = allow_cross_user

    def evaluate(
        self,
        session: TherapySession,
        requester_user_id: str,
        requester_tenant_id: str
    ) -> MemoryAccessDecision:
        if session.tenant_id != requester_tenant_id and not self.allow_cross_tenant:
            return MemoryAccessDecision(
                allowed=False,
                reason="cross-tenant",
                redacted=True,
                session=session
            )

        if session.user_id != requester_user_id and not self.allow_cross_user:
            return MemoryAccessDecision(
                allowed=False,
                reason="cross-user",
                redacted=True,
                session=session
            )

        return MemoryAccessDecision(
            allowed=True,
            reason="owner",
            redacted=False,
            session=session
        )

    def summary(self) -> str:
        tenant_rule = "required" if not self.allow_cross_tenant else "optional"
        user_rule = "required" if not self.allow_cross_user else "optional"
        return (
            f"- tenant match: {tenant_rule}\n"
            f"- user match: {user_rule}"
        )


class MemoryToolShim:
    def __init__(self, store: TherapyMemoryStore, policy: MemoryAccessPolicy):
        self.store = store
        self.policy = policy

    def render_tool_spec(self) -> str:
        return (
            "memory.lookup_by_token(token, requester_user_id, tenant_id) -> {status, snapshot}\n"
            "memory.lookup_by_time(timestamp, requester_user_id, tenant_id) -> {status, snapshot}\n"
            "memory.list_recent_sessions(tenant_id, limit) -> {status, index}"
        )

    def audit_lookup_by_token(
        self,
        token: str,
        requester_user_id: str,
        requester_tenant_id: str
    ) -> str:
        session = self.store.get_by_token(token)
        return self._format_audit(
            "lookup_by_token",
            f"token='{token}'",
            session,
            requester_user_id,
            requester_tenant_id
        )

    def audit_lookup_by_time(
        self,
        timestamp: str,
        requester_user_id: str,
        requester_tenant_id: str
    ) -> str:
        session = self.store.get_by_time(timestamp)
        return self._format_audit(
            "lookup_by_time",
            f"timestamp='{timestamp}'",
            session,
            requester_user_id,
            requester_tenant_id
        )

    def audit_list_recent_sessions(self, tenant_id: str, limit: int) -> str:
        entries = [
            session for session in self.store.sessions
            if session.tenant_id == tenant_id
        ][:max(limit, 1)]
        return (
            "CALL memory.list_recent_sessions("
            f"tenant_id='{tenant_id}', limit={limit}"
            f") -> OK ({len(entries)} entries, redacted index)"
        )

    def _format_audit(
        self,
        action: str,
        detail: str,
        session: TherapySession | None,
        requester_user_id: str,
        requester_tenant_id: str
    ) -> str:
        if session is None:
            return f"CALL memory.{action}({detail}) -> NOT_FOUND"

        decision = self.policy.evaluate(session, requester_user_id, requester_tenant_id)
        if decision.allowed:
            return f"CALL memory.{action}({detail}) -> OK (full snapshot)"
        return f"CALL memory.{action}({detail}) -> DENIED ({decision.reason})"
