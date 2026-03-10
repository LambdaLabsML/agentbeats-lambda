#!/usr/bin/env python3

"""V1"""
"""Defender Agent - baseline security gateway for the Security Arena.

This agent wraps the baseline security gateway implemented in the
`defender` package and exposes it via the A2A HTTP interface expected
by the orchestrator.

High-level behaviour:

- Receives filtered scenario context as JSON (no attack info).
- Extracts the user-facing prompt (formatted_input plus basic context).
- Passes that prompt through rule-based security filters.
- Uses the policy decision engine to ALLOW or BLOCK.
- If allowed, makes a single LLM call to generate a response.
- Sanitizes the output and returns it.

All attack detection is rule-based. The only LLM call is for generating
the final response when allowed by policy. Robust error handling ensures
the defender never crashes under adversarial inputs.
"""




import argparse
import json
import logging
import sys
from dataclasses import dataclass
from pathlib import Path

import uvicorn
from dotenv import load_dotenv

CURRENT_DIR = Path(__file__).resolve().parent
if str(CURRENT_DIR) not in sys.path:
    sys.path.insert(0, str(CURRENT_DIR))

from a2a.server.apps import A2AStarletteApplication
from a2a.server.request_handlers import DefaultRequestHandler
from a2a.server.tasks import InMemoryTaskStore, TaskUpdater
from a2a.server.agent_execution import AgentExecutor, RequestContext
from a2a.server.events import EventQueue
from a2a.types import (
    AgentCard,
    AgentCapabilities,
    TaskState,
    InvalidParamsError,
    UnsupportedOperationError,
    Task,
)
from a2a.utils import new_agent_text_message, new_task
from a2a.utils.errors import ServerError

from defender_engine.main import SecurityGateway
from defender_engine.config import SAFE_REFUSAL_MESSAGE


load_dotenv()
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("defender")


@dataclass
class ScenarioContext:
    """Filtered scenario context from orchestrator (no attack info)."""
    domain_description: str   # Domain/system description
    defender_role: str        # Defender's role description
    defender_task: str        # What defender should do
    output_format: str        # Expected output format
    formatted_input: str      # Input to process (may contain attacker content)
    security_guidelines: str = ""  # Optional, scenario-specific security hints

    @classmethod
    def from_dict(cls, d: dict) -> "ScenarioContext":
        return cls(
            domain_description=d.get("domain_description", ""),
            defender_role=d.get("defender_role", ""),
            defender_task=d.get("defender_task", ""),
            output_format=d.get("output_format", ""),
            formatted_input=d.get("formatted_input", ""),
            security_guidelines=d.get("security_guidelines", ""),
        )

    def build_user_prompt(self) -> str:
        """
        Build a concise, single-string prompt for the gateway.

        This keeps the gateway API simple while still giving the model
        enough context to be helpful for normal users.
        """
        sections: list[str] = []

        if self.defender_role:
            sections.append(f"Role: {self.defender_role}")
        if self.defender_task:
            sections.append(f"Task: {self.defender_task}")
        if self.output_format:
            sections.append(f"Output format: {self.output_format}")
        if self.domain_description:
            sections.append(f"Domain: {self.domain_description}")
        if self.security_guidelines:
            sections.append(f"Security guidelines: {self.security_guidelines}")

        sections.append("User input:")
        sections.append(self.formatted_input or "")

        return "\n\n".join(sections)


class Defender(AgentExecutor):
    """Defender that delegates to the SecurityGateway."""

    def __init__(self, model: str = "gpt-oss-20b"):
        # The gateway encapsulates all security logic and the single LLM call.
        self._gateway = SecurityGateway(model=model)
        self._model = model

    async def execute(self, context: RequestContext, event_queue: EventQueue):
        """Process input based on scenario context via the gateway."""
        if not context.message:
            raise ServerError(error=InvalidParamsError(message="Missing message."))

        task = new_task(context.message)
        await event_queue.enqueue_event(task)
        updater = TaskUpdater(event_queue, task.id, task.context_id)

        try:
            # Parse JSON context from orchestrator into dataclass.
            message_text = context.get_user_input()
            try:
                payload = json.loads(message_text)
            except json.JSONDecodeError:
                # Fall back to treating the raw message text as the user prompt.
                logger.warning("Failed to parse scenario JSON; using raw message as prompt.")
                user_prompt = message_text or ""
            else:
                ctx = ScenarioContext.from_dict(payload)
                logger.info("Processing defender request for role=%s", ctx.defender_role[:80])
                user_prompt = ctx.build_user_prompt()

            # Pass the constructed prompt through the security gateway.
            output = await self._gateway.handle_prompt(user_prompt)
            logger.info("Defender generated response (%d chars)", len(output))
            await updater.update_status(TaskState.completed, new_agent_text_message(output))
        except Exception as e:
            # Defensive: never let unexpected errors crash the agent.
            logger.error("Defender error: %s", e, exc_info=True)
            await updater.update_status(
                TaskState.failed,
                new_agent_text_message(SAFE_REFUSAL_MESSAGE),
            )

    async def cancel(self, _request: RequestContext, _event_queue: EventQueue) -> Task | None:
        raise ServerError(error=UnsupportedOperationError())


def main():
    parser = argparse.ArgumentParser(description="Security Arena - Defender Agent")
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind to")
    parser.add_argument("--port", type=int, default=9020, help="Port to bind to")
    parser.add_argument("--model", default="gpt-oss-20b", help="Model to use for the defender")
    args = parser.parse_args()

    agent_card = AgentCard(
        name="defender",
        description="Defender agent that processes inputs according to role",
        url=f"http://{args.host}:{args.port}/",
        version="1.0.0",
        default_input_modes=["text"],
        default_output_modes=["text"],
        capabilities=AgentCapabilities(streaming=False),
        skills=[]
    )

    executor = Defender(model=args.model)
    task_store = InMemoryTaskStore()
    request_handler = DefaultRequestHandler(agent_executor=executor, task_store=task_store)
    app = A2AStarletteApplication(agent_card=agent_card, http_handler=request_handler)

    print(f"Starting Defender on http://{args.host}:{args.port} (model: {args.model})")
    uvicorn.run(app.build(), host=args.host, port=args.port)


if __name__ == "__main__":
    main()
