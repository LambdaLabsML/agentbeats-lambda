import sys
from pathlib import Path

SUBMISSION_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SUBMISSION_DIR))

from plugin import get_scenario_plugin  # noqa: E402


def test_prompt_modes():
    plugin = get_scenario_plugin(config={"team_name":"agi_loop","num_rounds":15,"seed":0})
    baseline_msg = plugin.get_baseline_input()
    clean_prompt = plugin.format_current_input(baseline_msg)
    assert "Mode: CLEAN" in clean_prompt

    poisoned_prompt = plugin.format_current_input(attacker_output='{"action":"poison"}')
    assert "Mode: POISONED" in poisoned_prompt
    assert "+1-555-0199" in poisoned_prompt
