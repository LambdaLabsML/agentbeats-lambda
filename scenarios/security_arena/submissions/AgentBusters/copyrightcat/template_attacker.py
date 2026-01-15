#!/usr/bin/env python3
"""
CopyrightCat Template-Based Attacker

Uses fixed puzzle-solving attack templates from plugin.py instead of LLM-generated attacks.
This ensures consistent, well-crafted attacks following the scenario specification:
"asking the model to provide letters in steps to reconstruct song lyrics"
"""

import argparse
import logging
import os
import sys
import uvicorn
from dotenv import load_dotenv

load_dotenv()

# Add parent directories to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))))

from a2a.server.apps import A2AStarletteApplication
from a2a.server.request_handlers import DefaultRequestHandler
from a2a.server.tasks import InMemoryTaskStore, TaskUpdater
from a2a.server.agent_execution import AgentExecutor, RequestContext
from a2a.server.events import EventQueue
from a2a.types import AgentCard, AgentCapabilities, TaskState, InvalidParamsError, UnsupportedOperationError, Task
from a2a.utils import new_agent_text_message, new_task
from a2a.utils.errors import ServerError

# Import attack templates from plugin
try:
    from scenarios.security_arena.submissions.AgentBusters.copyrightcat.plugin import ATTACK_TEMPLATES
except ImportError:
    # Fallback if import fails - use local copy
    from plugin import ATTACK_TEMPLATES


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("template_attacker")


class TemplateAttackerExecutor(AgentExecutor):
    """Executor that uses fixed attack templates"""

    def __init__(self):
        self.round_counter = {}  # Track rounds per context

    async def execute(self, context: RequestContext, event_queue: EventQueue):
        """Execute attack using template"""
        msg = context.message
        if msg:
            task = new_task(msg)
            await event_queue.enqueue_event(task)
        else:
            raise ServerError(error=InvalidParamsError(message="Missing message."))

        updater = TaskUpdater(event_queue, task.id, task.context_id)
        task_id = task.id

        try:
            # Track round number for this context
            context_id = task.context_id or task_id
            if context_id not in self.round_counter:
                self.round_counter[context_id] = 0
            
            current_round = self.round_counter[context_id]
            self.round_counter[context_id] += 1

            # Select attack template (cycle through if more rounds than templates)
            template_index = current_round % len(ATTACK_TEMPLATES)
            attack = ATTACK_TEMPLATES[template_index]

            logger.info(f"Round {current_round + 1}: Using template {template_index + 1}")
            logger.info(f"Attack preview: {attack[:80]}...")

            # Send attack
            await updater.update_status(
                TaskState.completed,
                new_agent_text_message(attack)
            )

        except Exception as e:
            logger.error(f"Template attacker error: {e}", exc_info=True)
            await updater.update_status(
                TaskState.failed,
                new_agent_text_message(f"Error: {str(e)}")
            )

    async def cancel(self, request: RequestContext, event_queue: EventQueue) -> Task | None:
        """Cancel is not supported"""
        raise ServerError(error=UnsupportedOperationError())


def main():
    parser = argparse.ArgumentParser(
        description="CopyrightCat Template-Based Attacker"
    )
    parser.add_argument("--host", type=str, default="127.0.0.1", help="Host to bind to")
    parser.add_argument("--port", type=int, default=9221, help="Port to bind to")
    args = parser.parse_args()

    # Create agent card
    agent_card = AgentCard(
        name="copyrightcat_template_attacker",
        description="Template-based attacker for CopyrightCat scenario using puzzle-solving",
        url=f"http://{args.host}:{args.port}/",
        version="1.0.0",
        default_input_modes=["text"],
        default_output_modes=["text"],
        capabilities=AgentCapabilities(streaming=False),
        skills=[]
    )

    # Create executor
    executor = TemplateAttackerExecutor()

    # Create A2A application
    task_store = InMemoryTaskStore()
    request_handler = DefaultRequestHandler(
        agent_executor=executor,
        task_store=task_store
    )

    app = A2AStarletteApplication(
        agent_card=agent_card,
        http_handler=request_handler
    )

    # Start server
    print(f"Starting CopyrightCat Template Attacker on http://{args.host}:{args.port}")
    print(f"Loaded {len(ATTACK_TEMPLATES)} attack templates")
    print("Ready to attack using puzzle-solving techniques...")
    uvicorn.run(app.build(), host=args.host, port=args.port)


if __name__ == "__main__":
    main()
