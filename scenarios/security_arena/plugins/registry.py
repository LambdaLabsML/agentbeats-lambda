#!/usr/bin/env python3
"""
Scenario Plugin Registry

Maps scenario type names to plugin implementations and provides
a factory function to load scenario plugins from configuration.
"""

from typing import Any

from .base import ScenarioPlugin
from .portfolioiq import PortfolioIQPlugin
from .thingularity import ThingularityPlugin
from .example_medical import MedicalRecordsPlugin
from ..submissions.example_team.example_scenario.plugin import ExampleScenarioPlugin


from . import PyPiPirate2Plugin
from . import SecretKeeperPlugin
from . import GradingGriftPlugin
from . import AirlineAttackPlugin

# Registry mapping scenario names to plugin classes
SCENARIO_PLUGINS: dict[str, type[ScenarioPlugin]] = {
    "portfolioiq": PortfolioIQPlugin,
    "thingularity": ThingularityPlugin,
    "medical_records": MedicalRecordsPlugin,  # Example custom scenario
    "example_scenario": ExampleScenarioPlugin,
    "pypipirate2": PyPiPirate2Plugin,
    "gradinggrift": GradingGriftPlugin,
    "secretkeeper": SecretKeeperPlugin,
    "airline_attack": AirlineAttackPlugin
  
}


# Dynamically register submission plugins
def _register_submission_plugins():
    """Dynamically import and register submission plugins."""
    import sys
    from pathlib import Path

    # Add project root to path
    project_root = Path(__file__).parent.parent.parent.parent
    if str(project_root) not in sys.path:
        sys.path.insert(0, str(project_root))

    # @contribution: kyuhee (Safe-AI-Lausanne)
    # Import kyuhee's plugins
    try:
        from submissions.kyuhee.grading_grift.plugin import GradingGriftPlugin
        SCENARIO_PLUGINS["grading_grift"] = GradingGriftPlugin
    except ImportError as e:
        print(f"Warning: Could not load grading_grift plugin: {e}")
    # @end-contribution

    # @contribution: chengheng (SAIL)
    # Import chengheng's plugins
    try:
        from submissions.chengheng.secret_keeper.plugin import SecretKeeperPlugin
        SCENARIO_PLUGINS["secret_keeper"] = SecretKeeperPlugin
    except ImportError as e:
        print(f"Warning: Could not load secret_keeper plugin: {e}")

    # @end-contribution
    
    # @contribution: arthur (SAIL)
    try:
        from submissions.arthur.pypipirate2.plugin import PyPiPirate2Plugin
        SCENARIO_PLUGINS["pypipirate2"] = PyPiPirate2Plugin
    except ImportError as e:
        print(f"Warning: Could not load pypipirate2 plugin: {e}")

    # @end-contribution

    # @contribution: ines (Safe-AI-Lausanne)
    # Import ines's plugins
    try:
        from submissions.ines.AirlineAttack.plugin import AirlineAttackPlugin
        SCENARIO_PLUGINS["airline_attack"] = AirlineAttackPlugin
    except ImportError as e:
        print(f"Warning: Could not load airline_attack plugin: {e}")
    # @end-contribution

# Register submission plugins on module load
_register_submission_plugins()


def load_scenario(scenario_type: str, config: dict[str, Any]) -> ScenarioPlugin:
    """
    Load a scenario plugin by type name.

    Args:
        scenario_type: The scenario type from config (e.g., "portfolioiq")
        config: Configuration dict for the scenario

    Returns:
        Instantiated scenario plugin

    Raises:
        ValueError: If scenario_type is not registered

    Example:
        >>> config = {
        ...     "scenario_type": "portfolioiq",
        ...     "expected_risk_level": "High",
        ...     "target_risk_level": "Low",
        ...     "document_path": "data/ponzicorp_base.json"
        ... }
        >>> scenario = load_scenario("portfolioiq", config)
        >>> print(scenario.get_attack_objective())
    """
    plugin_class = SCENARIO_PLUGINS.get(scenario_type)

    if not plugin_class:
        available = ", ".join(SCENARIO_PLUGINS.keys())
        raise ValueError(
            f"Unknown scenario type: '{scenario_type}'. "
            f"Available scenarios: {available}"
        )

    return plugin_class(config)


def list_scenarios() -> list[str]:
    """
    List all registered scenario types.

    Returns:
        List of scenario type names
    """
    return list(SCENARIO_PLUGINS.keys())


def register_scenario(name: str, plugin_class: type[ScenarioPlugin]) -> None:
    """
    Register a custom scenario plugin.

    This allows participants to add custom scenarios without modifying
    the core registry file.

    Args:
        name: Scenario type name (used in config)
        plugin_class: Plugin class implementing ScenarioPlugin

    Example:
        >>> class CustomPlugin(ScenarioPlugin):
        ...     # ... implement methods ...
        ...     pass
        >>> register_scenario("custom", CustomPlugin)
    """
    if name in SCENARIO_PLUGINS:
        raise ValueError(f"Scenario '{name}' is already registered")

    if not issubclass(plugin_class, ScenarioPlugin):
        raise TypeError(
            f"Plugin class must inherit from ScenarioPlugin, "
            f"got {plugin_class.__name__}"
        )

    SCENARIO_PLUGINS[name] = plugin_class
