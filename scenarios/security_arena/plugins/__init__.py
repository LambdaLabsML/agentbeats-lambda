"""Scenario plugin system for Security Arena"""

from .base import ScenarioPlugin
from .registry import load_scenario, list_scenarios, register_scenario
from .portfolioiq import PortfolioIQPlugin
from .thingularity import ThingularityPlugin
from .example_medical import MedicalRecordsPlugin
from submissions.lambda_example.glitchinthematrix.plugin import GlitchInTheMatrixPlugin

__all__ = [
    "ScenarioPlugin",
    "load_scenario",
    "list_scenarios",
    "register_scenario",
    "PortfolioIQPlugin",
    "ThingularityPlugin",
    "MedicalRecordsPlugin",
    "GlitchInTheMatrixPlugin",
]
