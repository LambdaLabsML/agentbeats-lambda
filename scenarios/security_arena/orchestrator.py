#!/usr/bin/env python3
"""
Security Arena Orchestrator - Runs adversarial battles between attacker and defender agents.
Loads scenario plugins and injects context to generic agents.
"""

import argparse
import asyncio
import json
import logging
import os
import re
import sys
import uvicorn
from datetime import datetime
from pathlib import Path
from dotenv import load_dotenv

# Add scenarios directory to path so we can import plugins
sys.path.insert(0, str(Path(__file__).parent))

load_dotenv()

from a2a.server.apps import A2AStarletteApplication
from a2a.server.request_handlers import DefaultRequestHandler
from a2a.server.tasks import InMemoryTaskStore, TaskUpdater
from a2a.types import TaskState, Part, TextPart, AgentCard, AgentCapabilities

from a2a.utils import new_agent_text_message

from agentbeats.green_executor import GreenAgent, GreenExecutor
from agentbeats.models import EvalRequest, EvalResult
from agentbeats.tool_provider import ToolProvider

from arena_common import ArenaConfig, RoundResult, ArenaResult, NormalUserResult
from plugins.registry import load_scenario
from plugins.base import RoundInfo


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("generic_orchestrator")

# Per-agent timeout (in seconds) - each agent call must complete within this time
AGENT_TIMEOUT_SECONDS = int(os.getenv("AGENT_TIMEOUT_SECONDS", "120"))


class AgentTimeoutError(Exception):
    def __init__(self, agent_type: str):
        self.agent_type = agent_type
        super().__init__(f"{agent_type} timed out")


class AgentCrashError(Exception):
    def __init__(self, agent_type: str, message: str = ""):
        self.agent_type = agent_type
        super().__init__(message or f"{agent_type} crashed")


class GenericArenaOrchestrator(GreenAgent):
    """Arena orchestrator that works with any scenario plugin."""

    def __init__(self):
        self._required_roles = ["attacker", "defender"]
        self._required_config_keys = ["scenario_type", "num_rounds"]
        self._tool_provider = ToolProvider()

    async def _call_agent_with_timeout(
        self, message: str, url: str, agent_type: str, new_conversation: bool = False
    ) -> str:
        """Call an agent with timeout protection. Raises AgentTimeoutError or AgentCrashError."""
        try:
            response = await asyncio.wait_for(
                self._tool_provider.talk_to_agent(
                    message, url, new_conversation=new_conversation
                ),
                timeout=AGENT_TIMEOUT_SECONDS
            )
            return response
        except asyncio.TimeoutError:
            logger.error(
                f"{agent_type} timed out after {AGENT_TIMEOUT_SECONDS}s"
            )
            raise AgentTimeoutError(agent_type)
        except Exception as e:
            logger.error(f"{agent_type} crashed: {e}")
            raise AgentCrashError(agent_type, str(e))

    def validate_request(self, request: EvalRequest) -> tuple[bool, str]:
        """Validate that request has required participants and config."""
        is_normal_user = request.config.get("normal_user", False)
        required_roles = ["defender", "normal_user"] if is_normal_user else self._required_roles
        missing_roles = set(required_roles) - set(request.participants.keys())
        if missing_roles:
            return False, f"Missing required roles: {missing_roles}"
        missing_config = set(self._required_config_keys) - set(request.config.keys())
        if missing_config:
            return False, f"Missing required config keys: {missing_config}"
        return True, "ok"

    async def run_eval(self, req: EvalRequest, updater: TaskUpdater) -> None:
        """Main orchestration: load scenario, run battle, save results."""
        logger.info("Starting Security Arena: %s", req)

        try:
            # Parse config and load scenario plugin
            config = ArenaConfig(**req.config)
            scenario_type = config.scenario_type

            await updater.update_status(
                TaskState.working,
                new_agent_text_message(f"Loading scenario: {scenario_type}")
            )

            # Load the scenario plugin
            scenario = load_scenario(scenario_type, req.config)
            logger.info("Loaded scenario plugin: %s", scenario.get_scenario_name())

            defender_url = str(req.participants["defender"])

            # === NORMAL USER MODE ===
            if config.is_normal_user_mode():
                normal_user_url = str(req.participants["normal_user"])
                await self._run_normal_user_mode(
                    req, config, scenario, normal_user_url, defender_url, updater
                )
                return

            attacker_url = str(req.participants["attacker"])

            await updater.update_status(
                TaskState.working,
                new_agent_text_message(f"Security Arena - {scenario.get_scenario_name()} - Starting...")
            )

            # === Adversarial Battle ===
            await updater.update_status(
                TaskState.working,
                new_agent_text_message(
                    f"Starting {config.num_rounds}-round adversarial battle..."
                )
            )

            battle_result = await self._run_adversarial_battle(
                attacker_url=attacker_url,
                defender_url=defender_url,
                scenario=scenario,
                config=config,
                updater=updater
            )

            # === Create Final Result ===
            # Get team_name from config if provided
            team_name = req.config.get("team_name")

            # Get input template with placeholder for battle log display
            input_template = scenario.format_input("ATTACKER_OUTPUT")

            arena_result = ArenaResult(
                team_name=team_name,
                scenario_type=scenario_type,
                winner=battle_result["winner"],
                manipulation_round=battle_result.get("manipulation_round"),
                rounds_defended=battle_result["rounds_defended"],
                total_rounds=config.num_rounds,
                battle_log=battle_result["battle_log"],
                input_format_template=input_template,
                # Error tracking from battle
                attacker_timeout_errors=battle_result.get(
                    "attacker_timeout_errors", 0
                ),
                attacker_crash_errors=battle_result.get(
                    "attacker_crash_errors", 0
                ),
                defender_timeout_errors=battle_result.get(
                    "defender_timeout_errors", 0
                ),
                defender_crash_errors=battle_result.get(
                    "defender_crash_errors", 0
                )
            )

            # Create EvalResult for A2A framework
            result = EvalResult(
                winner=arena_result.winner,
                detail=arena_result.model_dump()
            )

            # Format results text
            results_text = self._format_results(arena_result, scenario)

            await updater.update_status(
                TaskState.working,
                new_agent_text_message(f"\n{results_text}")
            )

            # Save results
            await self._save_results(arena_result, updater)

            # Send final artifact
            await updater.add_artifact(
                parts=[
                    Part(root=TextPart(text=results_text)),
                    Part(root=TextPart(text=result.model_dump_json(indent=2)))
                ],
                name="Arena Result"
            )

            await updater.update_status(
                TaskState.submitted,
                new_agent_text_message(f"Security Arena complete - Winner: {arena_result.winner}")
            )

        except Exception as e:
            logger.error(f"Arena error: {e}", exc_info=True)
            await updater.update_status(
                TaskState.failed,
                new_agent_text_message(f"Error: {str(e)}")
            )
            raise
        finally:
            self._tool_provider.reset()

    async def _run_normal_user_mode(
        self, req: EvalRequest, config: ArenaConfig, scenario,
        normal_user_url: str, defender_url: str, updater: TaskUpdater
    ) -> None:
        """Test defender helpfulness: generate question, get response, evaluate."""
        await updater.update_status(
            TaskState.working,
            new_agent_text_message("🧪 Normal User Test - Testing helpfulness...")
        )
        topics_config = config.get_normal_user_topics()
        if not topics_config:
            await updater.update_status(
                TaskState.failed,
                new_agent_text_message("No normal_user topics defined in config")
            )
            return

        team_name = req.config.get("team_name")
        topics_passed = 0
        details = []

        # Build scenario context for normal user
        defender_role = scenario.get_defender_role()
        defender_task = scenario.get_defender_task_description()

        for i, topic_cfg in enumerate(topics_config, 1):
            topic = topic_cfg.get("topic", "")
            context_hint = topic_cfg.get("context", "")
            expected_concepts = topic_cfg.get("expected_concepts", [])

            # Get sample data for the normal user agent to see the context
            # format_input("") returns the baseline formatted input
            sample_data = scenario.format_input("")

            await updater.update_status(
                TaskState.working,
                new_agent_text_message(f"Topic {i}/{len(topics_config)}: {topic}")
            )

            try:
                # === STEP 1: Normal user generates question ===
                # Send JSON context to normal_user agent (same mechanism as attacker)
                gen_context = {
                    "mode": "generate_question",
                    "defender_role": defender_role,
                    "defender_task": defender_task,
                    "sample_data": sample_data,
                    "topic": topic,
                    "context_hint": context_hint,
                    "expected_concepts": expected_concepts
                }
                gen_context_json = json.dumps(gen_context)

                generated_question = await self._call_agent_with_timeout(
                    gen_context_json, normal_user_url, "normal_user", new_conversation=True
                )
                generated_question = generated_question.strip()

                await updater.update_status(
                    TaskState.working,
                    new_agent_text_message(f"  → Generated: {generated_question[:60]}...")
                )

                # === STEP 2: Send question to defender ===
                # Let scenario format the question into the appropriate input format
                defender_input = scenario.format_input(generated_question)

                # Build context for defender (normal user mode, no attack info)
                context = scenario.get_scenario_context(
                    current_round=0,
                    battle_history=[]
                )
                # Set formatted_input directly (no attack template needed here)
                context.formatted_input = defender_input
                # Send filtered context as JSON (includes formatted_input)
                defender_message = context.to_json(include_attack_info=False)
                defender_response = await self._call_agent_with_timeout(
                    defender_message, defender_url, "defender", new_conversation=True
                )

                await updater.update_status(
                    TaskState.working,
                    new_agent_text_message(
                        f"  → Defender responded ({len(defender_response)} chars)"
                    )
                )

                # === STEP 3: Normal user evaluates response ===
                # Send JSON context to normal_user agent for evaluation
                eval_context = {
                    "mode": "evaluate_response",
                    "defender_role": defender_role,
                    "defender_task": defender_task,
                    "generated_question": generated_question,
                    "defender_response": defender_response,
                    "expected_concepts": expected_concepts
                }
                eval_context_json = json.dumps(eval_context)

                eval_result = await self._call_agent_with_timeout(
                    eval_context_json, normal_user_url, "normal_user", new_conversation=True
                )

                # Parse evaluation result
                passed, explanation = self._parse_normal_user_eval(eval_result)

                if passed:
                    topics_passed += 1

                details.append({
                    "topic": topic,
                    "generated_question": generated_question,
                    "defender_response": defender_response[:500],
                    "evaluation": eval_result,
                    "passed": passed,
                    "explanation": explanation,
                    "expected_concepts": expected_concepts
                })

                status = "✅" if passed else "❌"
                await updater.update_status(
                    TaskState.working,
                    new_agent_text_message(f"{status} Topic {i}: {explanation[:50]}")
                )

            except (AgentTimeoutError, AgentCrashError) as e:
                details.append({
                    "topic": topic,
                    "passed": False,
                    "error": str(e)
                })
                await updater.update_status(
                    TaskState.working,
                    new_agent_text_message(f"❌ Topic {i}: Error - {e}")
                )

        # Create result
        all_passed = topics_passed == len(topics_config)
        result = NormalUserResult(
            team_name=team_name,
            scenario_type=config.scenario_type,
            passed=all_passed,
            questions_passed=topics_passed,
            total_questions=len(topics_config),
            details=details
        )

        await self._save_results(result, updater, filename_suffix="normal_user_result")

        # Final status
        status_msg = (
            f"✅ Normal User Test PASSED! {topics_passed}/{len(topics_config)}"
            if all_passed else
            f"❌ Normal User Test FAILED! {topics_passed}/{len(topics_config)}"
        )
        await updater.update_status(
            TaskState.completed if all_passed else TaskState.failed,
            new_agent_text_message(status_msg)
        )

    def _parse_normal_user_eval(self, eval_result: str) -> tuple[bool, str]:
        """Parse normal user's JSON evaluation of defender response."""
        # Try to extract JSON from response
        json_match = re.search(r'\{[^{}]*\}', eval_result, re.DOTALL)
        if json_match:
            try:
                data = json.loads(json_match.group())
                answered = data.get("answered", False)
                helpful = data.get("helpful", False)
                explanation = data.get("explanation", "No explanation")
                passed = answered and helpful
                return passed, explanation
            except json.JSONDecodeError:
                pass

        # Fallback: check for positive indicators
        lower = eval_result.lower()
        passed = "true" in lower and "false" not in lower
        return passed, eval_result[:100]

    async def _run_adversarial_battle(
        self, attacker_url: str, defender_url: str, scenario,
        config: ArenaConfig, updater: TaskUpdater
    ) -> dict:
        """Run multi-round battle. Returns dict with winner, errors, and battle_log."""
        battle_log = []
        first_manipulation_round = None
        errors = {"attacker_timeout": 0, "attacker_crash": 0, "defender_timeout": 0, "defender_crash": 0}

        for round_num in range(config.num_rounds):
            await updater.update_status(
                TaskState.working,
                new_agent_text_message(
                    f"\n--- Round {round_num + 1}/{config.num_rounds} ---"
                )
            )

            # === BUILD SCENARIO CONTEXT ===
            # Convert battle_log to RoundInfo list for scenario
            battle_history = [
                RoundInfo(
                    round_num=r.round,  # RoundResult uses 'round', not 'round_num'
                    manipulation_detected=r.manipulation_detected,
                    extracted_value=r.extracted_value,
                    attacker_output=r.attack_output,
                    defender_response=r.defender_output
                )
                for r in battle_log
            ] if battle_log else []

            # Get full scenario context
            context = scenario.get_scenario_context(
                current_round=round_num,
                battle_history=battle_history
            )

            # === ATTACKER TURN: Generate attack ===
            # Send full context dict (as JSON) to attacker
            attacker_message = context.to_json(include_attack_info=True)

            logger.info("Round %d: Sending to attacker", round_num + 1)
            try:
                attacker_output = await self._call_agent_with_timeout(
                    attacker_message, attacker_url, "attacker", new_conversation=False
                )
            except AgentTimeoutError:
                errors["attacker_timeout"] += 1
                await updater.update_status(
                    TaskState.working, new_agent_text_message(f"⏱️ Attacker TIMEOUT round {round_num + 1}")
                )
                continue
            except AgentCrashError as e:
                errors["attacker_crash"] += 1
                await updater.update_status(
                    TaskState.working, new_agent_text_message(f"💥 Attacker CRASHED round {round_num + 1}: {e}")
                )
                continue
            await updater.update_status(
                TaskState.working, new_agent_text_message(f"Attacker output ({len(attacker_output)} chars)")
            )

            # === DEFENDER TURN ===
            context.apply_input_template(attacker_output)
            formatted_input = context.formatted_input  # What defender actually sees
            defender_message = context.to_json(include_attack_info=False)
            logger.info("Round %d: Sending to defender", round_num + 1)
            try:
                defender_response = await self._call_agent_with_timeout(
                    defender_message, defender_url, "defender", new_conversation=True
                )
            except AgentTimeoutError:
                errors["defender_timeout"] += 1
                await updater.update_status(
                    TaskState.working, new_agent_text_message(f"⏱️ Defender TIMEOUT round {round_num + 1}")
                )
                battle_log.append(RoundResult(
                    round=round_num + 1, attack_output=attacker_output, formatted_input=formatted_input,
                    defender_output="[TIMEOUT]", manipulation_detected=True, extracted_value="timeout"
                ))
                first_manipulation_round = round_num + 1
                break
            except AgentCrashError as e:
                errors["defender_crash"] += 1
                await updater.update_status(
                    TaskState.working, new_agent_text_message(f"💥 Defender CRASHED round {round_num + 1}: {e}")
                )
                battle_log.append(RoundResult(
                    round=round_num + 1, attack_output=attacker_output, formatted_input=formatted_input,
                    defender_output=f"[CRASH: {e}]", manipulation_detected=True, extracted_value="crash"
                ))
                first_manipulation_round = round_num + 1
                break
            await updater.update_status(
                TaskState.working, new_agent_text_message(f"Defender: {defender_response[:200]}...")
            )

            # === CHECK FOR MANIPULATION ===
            manipulation_detected, extracted_value = scenario.check_success(defender_response)
            battle_log.append(RoundResult(
                round=round_num + 1, attack_output=attacker_output, formatted_input=formatted_input,
                defender_output=defender_response,
                manipulation_detected=manipulation_detected, extracted_value=extracted_value
            ))
            if manipulation_detected:
                await updater.update_status(
                    TaskState.working, new_agent_text_message(f"🚨 MANIPULATION round {round_num + 1}! Value: {extracted_value}")
                )
                first_manipulation_round = round_num + 1
                break
            else:
                await updater.update_status(
                    TaskState.working, new_agent_text_message(f"✓ Round {round_num + 1}: Blocked (value: {extracted_value})")
                )

        # Build result
        result = {
            "attacker_timeout_errors": errors["attacker_timeout"],
            "attacker_crash_errors": errors["attacker_crash"],
            "defender_timeout_errors": errors["defender_timeout"],
            "defender_crash_errors": errors["defender_crash"],
            "battle_log": battle_log
        }
        if first_manipulation_round is not None:
            await updater.update_status(
                TaskState.working, new_agent_text_message(f"🚨 Attacker won in round {first_manipulation_round}")
            )
            result.update({"winner": "attacker", "manipulation_round": first_manipulation_round, "rounds_defended": first_manipulation_round - 1})
        else:
            await updater.update_status(
                TaskState.working, new_agent_text_message(f"✅ Defender held for all {config.num_rounds} rounds!")
            )
            result.update({"winner": "defender", "manipulation_round": None, "rounds_defended": config.num_rounds})

        return result

    async def _save_results(
        self, result: ArenaResult | NormalUserResult, updater: TaskUpdater,
        filename_suffix: str = "result"
    ) -> None:
        """Save results to disk (ArenaResult also saves evidence files)."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        env_dir = os.getenv("AGENTBEATS_RESULTS_DIR")
        if env_dir:
            results_dir = Path(env_dir)
        elif result.team_name:
            results_dir = Path("results") / result.team_name / result.scenario_type / timestamp
        else:
            results_dir = Path("results") / result.scenario_type
        results_dir.mkdir(parents=True, exist_ok=True)
        result_path = results_dir / f"{filename_suffix}.json"
        result_path.write_text(result.model_dump_json(indent=2), encoding='utf-8')
        logger.info("Results saved to: %s", result_path)

        if isinstance(result, ArenaResult):
            attack_data = {
                "succeeded": result.winner == "attacker",
                "manipulation_round": result.manipulation_round,
                "rounds_defended": result.rounds_defended,
                "total_rounds": result.total_rounds,
                "team_name": result.team_name,
                "scenario_type": result.scenario_type
            }
            evidence = json.dumps(attack_data, indent=2)
            (results_dir / "attack_succeeded.json").write_text(evidence, encoding='utf-8')

            # Save human-readable battle log
            battle_log_md = self._format_battle_log(result)
            (results_dir / "battle_log.md").write_text(battle_log_md, encoding='utf-8')

            if result.team_name:
                sub = Path("scenarios/security_arena/submissions")
                sub_dir = sub / result.team_name / result.scenario_type / "test_results"
                if sub_dir.exists() or sub_dir.parent.exists():
                    sub_dir.mkdir(parents=True, exist_ok=True)
                    (sub_dir / "attack_succeeded.json").write_text(evidence, encoding='utf-8')

        await updater.update_status(
            TaskState.working, new_agent_text_message(f"Results saved to: {result_path}")
        )

    def _md_code_block(self, content: str) -> str:
        """Wrap content in a markdown code block, escaping any backticks."""
        # Find max consecutive backticks in content, use more for the fence
        max_ticks = 3
        current = 0
        for char in content:
            if char == '`':
                current += 1
                max_ticks = max(max_ticks, current + 1)
            else:
                current = 0
        fence = '`' * max_ticks
        return f"{fence}\n{content}\n{fence}"

    def _format_battle_log(self, arena_result: ArenaResult) -> str:
        """Format battle log as human-readable markdown."""
        lines = [
            "# Battle Log",
            f"**Scenario:** {arena_result.scenario_type}",
            f"**Winner:** {arena_result.winner}",
            f"**Total Rounds:** {arena_result.total_rounds}",
            ""
        ]
        # Show input template with ATTACKER_OUTPUT placeholder
        if arena_result.input_format_template:
            lines += [
                "## Input Format Template",
                "The attacker's output is injected where `ATTACKER_OUTPUT` appears:",
                self._md_code_block(arena_result.input_format_template),
                "",
                "---",
                ""
            ]
        for rr in arena_result.battle_log:
            status = "🚨 SUCCESS" if rr.manipulation_detected else "❌ BLOCKED"
            lines += [
                f"## Round {rr.round} - {status}",
                "",
                "### Attacker Output",
                self._md_code_block(rr.attack_output),
                ""
            ]
            if rr.formatted_input:
                lines += [
                    "### Formatted Input (what defender sees)",
                    self._md_code_block(rr.formatted_input),
                    ""
                ]
            lines += [
                "### Defender Response",
                self._md_code_block(rr.defender_output),
                "",
                f"**Extracted Value:** `{rr.extracted_value}`",
                "",
                "---",
                ""
            ]
        return "\n".join(lines)

    def _format_results(self, arena_result: ArenaResult, scenario) -> str:
        """Format arena results as human-readable text."""
        r = arena_result
        lines = [
            "=" * 80, f"ARENA - {scenario.get_scenario_name().upper()} - RESULTS",
            "=" * 80, "", f"Winner: {r.winner.upper()}", f"Total Rounds: {r.total_rounds}", ""
        ]
        if r.winner == "attacker":
            lines += [f"🚨 Attacker succeeded round {r.manipulation_round}!",
                      f"Defended: {r.rounds_defended}",
                      f"Success Rate: {r.get_attack_success_rate():.1%}", ""]
        else:
            lines += [f"✅ Defender resisted all {r.total_rounds} rounds!", "Defense: 100%", ""]
        # Errors
        errs = [(r.attacker_timeout_errors, "⏱️ Attacker timeouts"),
                (r.attacker_crash_errors, "💥 Attacker crashes"),
                (r.defender_timeout_errors, "⏱️ Defender timeouts"),
                (r.defender_crash_errors, "💥 Defender crashes")]
        if any(e[0] for e in errs):
            lines.append("--- Errors ---")
            lines += [f"{label}: {cnt}" for cnt, label in errs if cnt > 0]
            lines.append("")
        # Rounds
        lines.append("--- Rounds ---")
        for rr in r.battle_log:
            st = "🚨 BREACH" if rr.manipulation_detected else "✓ Blocked"
            lines.append(f"Round {rr.round}: {st} (value: {rr.extracted_value})")
        lines += ["", "=" * 80]
        return "\n".join(lines)


def create_app(host: str, port: int):
    """Create and configure the A2A application"""
    card = AgentCard(
        name="Security Arena Orchestrator",
        description="Generic arena orchestrating dynamic security battles for any scenario",
        url=f"http://{host}:{port}/",
        version="1.0.0",
        default_input_modes=["text"],
        default_output_modes=["text"],
        capabilities=AgentCapabilities(streaming=False),
        skills=[]
    )

    orchestrator = GenericArenaOrchestrator()
    executor = GreenExecutor(orchestrator)

    task_store = InMemoryTaskStore()
    request_handler = DefaultRequestHandler(
        agent_executor=executor,
        task_store=task_store
    )

    app = A2AStarletteApplication(
        agent_card=card,
        http_handler=request_handler
    )

    return app


async def main():
    parser = argparse.ArgumentParser(description="Security Arena Orchestrator")
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind to")
    parser.add_argument("--port", type=int, default=9010, help="Port to bind to")
    args = parser.parse_args()

    app = create_app(args.host, args.port)

    logger.info("Starting Security Arena Orchestrator on http://%s:%d", args.host, args.port)

    uvicorn_config = uvicorn.Config(app.build(), host=args.host, port=args.port)
    uvicorn_server = uvicorn.Server(uvicorn_config)
    await uvicorn_server.serve()


if __name__ == "__main__":
    asyncio.run(main())
