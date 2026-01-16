import sys
from pathlib import Path

SUBMISSION_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SUBMISSION_DIR))

from plugin import get_scenario_plugin  # noqa: E402


def test_format_current_input_switches_mode_clean_vs_poisoned():
    plugin = get_scenario_plugin(config={"team_name": "agi_loop", "num_rounds": 15, "seed": 0})
    baseline_msg = plugin.get_baseline_input()

    clean_prompt = plugin.format_current_input(baseline_msg)
    assert "=== OFFLINE REQUEST (CLEAN) ===" in clean_prompt

    poisoned_prompt = plugin.format_current_input('{"action":"poison"}')
    assert "=== OFFLINE REQUEST (POISONED) ===" in poisoned_prompt

    # Ensure noop keeps CLEAN mode
    noop_prompt = plugin.format_current_input('{"action":"noop"}')
    assert "=== OFFLINE REQUEST (CLEAN) ===" in noop_prompt

    assert clean_prompt != poisoned_prompt
