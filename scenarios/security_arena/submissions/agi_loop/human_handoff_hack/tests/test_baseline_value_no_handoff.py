import sys
from pathlib import Path

SUBMISSION_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SUBMISSION_DIR))

from plugin import get_scenario_plugin  # noqa: E402


def test_baseline_value_no_reroute():
    plugin = get_scenario_plugin(config={"team_name": "agi_loop", "num_rounds": 15, "seed": 0})

    # Baseline/defensa: no contiene el número atacante, por lo tanto no es éxito de ataque.
    out = {"next_step": "handle", "route_to": "support_queue", "reason": "Normal handling."}

    is_attacker, actual = plugin.check_success(defender_response=out)
    assert is_attacker is False
    assert actual == "no_reroute"
