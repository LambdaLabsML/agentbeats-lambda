#!/usr/bin/env python3
"""
Normal User Agent - Tests AI assistant helpfulness with benign questions.

Receives scenario context as JSON, operates in two modes:
- generate_question: Generate a natural question for the defender
- evaluate_response: Evaluate if the defender's response was helpful
"""

import argparse
import json
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path

import uvicorn
from dotenv import load_dotenv
from jinja2 import Environment, FileSystemLoader

load_dotenv()

from openai import AsyncOpenAI

# Load templates
_template_dir = Path(__file__).parent / "templates"
_env = Environment(loader=FileSystemLoader(_template_dir), trim_blocks=True, lstrip_blocks=True)
_system_template = _env.get_template("system.j2")
_question_template = _env.get_template("question.j2")
_evaluate_template = _env.get_template("evaluate.j2")
from a2a.server.apps import A2AStarletteApplication
from a2a.server.request_handlers import DefaultRequestHandler
from a2a.server.tasks import InMemoryTaskStore, TaskUpdater
from a2a.server.agent_execution import AgentExecutor, RequestContext
from a2a.server.events import EventQueue
from a2a.types import (
    AgentCard, AgentCapabilities, TaskState,
    InvalidParamsError, UnsupportedOperationError, Task
)
from a2a.utils import new_agent_text_message, new_task
from a2a.utils.errors import ServerError

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("normal_user")


@dataclass
class NormalUserContext:
    """Context from orchestrator for normal user testing."""
    mode: str                # "generate_question" or "evaluate_response"
    defender_role: str       # Defender's role description
    defender_task: str       # What defender should do
    sample_data: str = ""    # Sample data for question generation
    input_template: str = "" # Shows where user input is placed (USER_QUESTION marker)
    topic: str = ""          # Topic to focus on
    context_hint: str = ""   # Hint for question generation
    expected_concepts: list[str] = field(default_factory=list)  # Expected concepts
    generated_question: str = ""   # For evaluation mode
    defender_response: str = ""    # For evaluation mode

    @classmethod
    def from_dict(cls, d: dict) -> "NormalUserContext":
        return cls(
            mode=d.get("mode", "generate_question"),
            defender_role=d.get("defender_role", ""),
            defender_task=d.get("defender_task", ""),
            sample_data=d.get("sample_data", ""),
            input_template=d.get("input_template", ""),
            topic=d.get("topic", ""),
            context_hint=d.get("context_hint", ""),
            expected_concepts=d.get("expected_concepts", []),
            generated_question=d.get("generated_question", ""),
            defender_response=d.get("defender_response", ""),
        )


class NormalUser(AgentExecutor):
    """Normal user agent that generates questions and evaluates responses."""

    def __init__(self, model: str = "gpt-4o-mini"):
        self.client = AsyncOpenAI(
            api_key=os.getenv("OPENAI_API_KEY"),
            base_url=os.getenv("OPENAI_BASE_URL")
        )
        self.model = model

    def _render(self, template, ctx: NormalUserContext) -> str:
        """Render a Jinja2 template with the context."""
        return template.render(**vars(ctx))

    async def _generate(self, system: str, user: str) -> str:
        """Generate a response from the LLM."""
        response = await self.client.chat.completions.create(
            model=self.model,
            messages=[{"role": "system", "content": system}, {"role": "user", "content": user}]
        )
        return response.choices[0].message.content

    async def execute(self, context: RequestContext, event_queue: EventQueue):
        """Generate question or evaluate response based on mode."""
        if not context.message:
            raise ServerError(error=InvalidParamsError(message="Missing message."))

        task = new_task(context.message)
        await event_queue.enqueue_event(task)
        updater = TaskUpdater(event_queue, task.id, task.context_id)

        try:
            # Parse JSON context from orchestrator into dataclass
            message_text = context.get_user_input()
            ctx = NormalUserContext.from_dict(json.loads(message_text))

            # Render Jinja2 templates based on mode and generate output
            if ctx.mode == "generate_question":
                logger.info("Mode: generate_question, Topic: %s", ctx.topic)
                output = await self._generate(
                    self._render(_system_template, ctx),
                    self._render(_question_template, ctx)
                )
            elif ctx.mode == "evaluate_response":
                logger.info("Mode: evaluate_response")
                output = await self._generate(
                    self._render(_system_template, ctx),
                    self._render(_evaluate_template, ctx)
                )
            else:
                raise ValueError(f"Unknown mode: {ctx.mode}")

            logger.info("Generated response (%d chars)", len(output))
            await updater.update_status(TaskState.completed, new_agent_text_message(output))
        except Exception as e:
            logger.error("Normal user error: %s", e, exc_info=True)
            await updater.update_status(TaskState.failed, new_agent_text_message(f"Error: {e}"))

    async def cancel(self, _request: RequestContext, _event_queue: EventQueue) -> Task | None:
        raise ServerError(error=UnsupportedOperationError())


def main():
    parser = argparse.ArgumentParser(description="Security Arena - Normal User Agent")
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind to")
    parser.add_argument("--port", type=int, default=9022, help="Port to bind to")
    parser.add_argument("--model", default="gpt-4o-mini", help="OpenAI model to use")
    args = parser.parse_args()

    agent_card = AgentCard(
        name="normal_user",
        description="Normal user agent for testing AI assistant helpfulness",
        url=f"http://{args.host}:{args.port}/",
        version="1.0.0",
        default_input_modes=["text"],
        default_output_modes=["text"],
        capabilities=AgentCapabilities(streaming=False),
        skills=[]
    )

    executor = NormalUser(model=args.model)
    task_store = InMemoryTaskStore()
    request_handler = DefaultRequestHandler(agent_executor=executor, task_store=task_store)
    app = A2AStarletteApplication(agent_card=agent_card, http_handler=request_handler)

    print(f"Starting NormalUser on http://{args.host}:{args.port} (model: {args.model})")
    uvicorn.run(app.build(), host=args.host, port=args.port)


if __name__ == "__main__":
    main()
