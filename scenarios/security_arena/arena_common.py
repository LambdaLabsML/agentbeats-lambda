#!/usr/bin/env python3
"""
Common types and utilities for Security Arena
"""

from pydantic import BaseModel, Field, field_validator
from typing import Any, Union


class NormalUserConfig(BaseModel):
    """Configuration for normal user helpfulness testing"""
    enabled: bool = Field(default=True, description="Whether normal user test is enabled")
    topics: list[dict] = Field(default=[], description="Topics for question generation")


class ArenaConfig(BaseModel):
    """
    Generic configuration for arena battles.

    This is the base configuration that works for all scenarios.
    Scenario-specific config parameters are passed through as additional fields.
    """
    scenario_type: str = Field(description="Scenario plugin to use")
    num_rounds: int = Field(default=5, ge=1, le=20, description="Battle rounds")
    normal_user: Union[bool, NormalUserConfig] = Field(
        default=False, description="Run helpfulness test (bool or config dict)"
    )

    # Scenario-specific config is passed through dynamically
    # For PortfolioIQ: expected_risk_level, target_risk_level, document_path
    # For Thingularity: hidden_tools, public_tools
    # etc.

    class Config:
        extra = "allow"  # Allow additional fields for scenario-specific config

    @field_validator("normal_user", mode="before")
    @classmethod
    def parse_normal_user(cls, v):
        """Accept bool, dict, or NormalUserConfig"""
        if isinstance(v, bool):
            return v
        if isinstance(v, dict):
            return NormalUserConfig(**v)
        return v

    def is_normal_user_mode(self) -> bool:
        """Check if normal user mode is enabled"""
        if isinstance(self.normal_user, bool):
            return self.normal_user
        return self.normal_user.enabled

    def get_normal_user_topics(self) -> list[dict]:
        """Get topics for normal user question generation"""
        if isinstance(self.normal_user, NormalUserConfig):
            return self.normal_user.topics
        return []


class NormalUserQuestion(BaseModel):
    """A normal user question for helpfulness testing"""
    question: str = Field(description="The question to ask")
    expected_keywords: list[str] = Field(description="Keywords expected")
    description: str = Field(default="", description="Question description")


class NormalUserResult(BaseModel):
    """Result from normal user helpfulness test"""
    team_name: str | None = Field(default=None, description="Team that submitted")
    scenario_type: str = Field(description="Which scenario was tested")
    passed: bool = Field(description="Whether all questions were answered helpfully")
    questions_passed: int = Field(description="Number of questions answered correctly")
    total_questions: int = Field(description="Total number of questions")
    details: list[dict] = Field(default=[], description="Per-question details")


class RoundResult(BaseModel):
    """Result from a single battle round"""
    round: int = Field(description="Round number (1-indexed)")
    attack_output: str = Field(description="What the attacker generated (truncated for display)")
    defender_output: str = Field(description="What the defender responded")
    manipulation_detected: bool = Field(description="Whether the attack succeeded")
    extracted_value: Any = Field(description="Value extracted by success checker (e.g., risk_level, revealed_tools)")


class ArenaResult(BaseModel):
    """Complete result from arena evaluation"""
    team_name: str | None = Field(default=None, description="Team that submitted the scenario")
    scenario_type: str = Field(description="Which scenario was tested")
    winner: str = Field(description="'attacker', 'defender', or 'none'")
    baseline_passed: bool = Field(description="Whether defender passed baseline test")
    manipulation_round: int | None = Field(description="Round where manipulation succeeded (if any)")
    rounds_defended: int = Field(description="How many rounds defender successfully blocked")
    total_rounds: int = Field(description="Total number of rounds")
    battle_log: list[RoundResult] = Field(description="Detailed log of each round")
    baseline_value: Any | None = Field(default=None, description="Defender's baseline output value")

    # Error tracking per agent type
    attacker_timeout_errors: int = Field(default=0, description="Number of attacker timeouts")
    attacker_crash_errors: int = Field(default=0, description="Number of attacker crashes")
    defender_timeout_errors: int = Field(default=0, description="Number of defender timeouts")
    defender_crash_errors: int = Field(default=0, description="Number of defender crashes")

    def get_attack_success_rate(self) -> float:
        """Calculate attack success rate (0.0 to 1.0)"""
        if not self.battle_log:
            return 0.0
        successes = sum(1 for r in self.battle_log if r.manipulation_detected)
        return successes / len(self.battle_log)

    def get_defense_success_rate(self) -> float:
        """Calculate defense success rate (0.0 to 1.0)"""
        return self.rounds_defended / self.total_rounds
