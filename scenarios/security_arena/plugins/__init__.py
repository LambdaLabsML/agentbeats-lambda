"""Scenario plugin system for Security Arena"""

from .base import ScenarioPlugin
"""
Security Arena plugins package.

Mantengo este __init__ vacío a propósito para evitar ciclos de importación
entre `plugins.registry` y los plugins de `submissions.*`.
Otros módulos deben importar directamente desde `plugins.registry`.
"""

__all__ = []

from .portfolioiq import PortfolioIQPlugin
from .thingularity import ThingularityPlugin
from .example_medical import MedicalRecordsPlugin

__all__ = [
    "ScenarioPlugin",
    "load_scenario",
    "list_scenarios",
    "register_scenario",
    "PortfolioIQPlugin",
    "ThingularityPlugin",
    "MedicalRecordsPlugin",
]
