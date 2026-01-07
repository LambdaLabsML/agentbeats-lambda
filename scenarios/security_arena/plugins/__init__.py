"""Scenario plugin system for Security Arena"""

from .base import ScenarioPlugin
from .registry import load_scenario, list_scenarios, register_scenario
from .portfolioiq import PortfolioIQPlugin
from .thingularity import ThingularityPlugin
from .example_medical import MedicalRecordsPlugin
from ....submissions.arthur.pypipirate2.plugin import PyPiPirate2Plugin
from ....submissions.kyuhee.grading_grift.plugin import GradingGriftPlugin
from ....submissions.chengheng.secret_keeper.plugin import SecretKeeperPlugin

__all__ = [
    "ScenarioPlugin",
    "load_scenario",
    "list_scenarios",
    "register_scenario",
    "PortfolioIQPlugin",
    "ThingularityPlugin",
    "MedicalRecordsPlugin",
    "PyPiPirate2Plugin",
    "SecretKeeperPlugin",
]
