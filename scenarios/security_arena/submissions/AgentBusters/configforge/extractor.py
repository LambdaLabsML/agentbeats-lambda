"""
ConfigForge Config Extractor

Extracts configuration data from various formats in defender responses.
Supports JSON, YAML, Python dict literals, and natural language.
"""

import json
import re
from typing import Any, Optional

import yaml

from .models import ExtractedConfig


class ConfigExtractor:
    """
    Extracts configuration blocks from defender response.

    Supports multiple formats:
    - JSON code blocks (```json ... ```)
    - YAML code blocks (```yaml ... ```)
    - Generic code blocks (``` ... ```)
    - Inline JSON objects ({...})
    - Inline YAML (key: value patterns)
    """

    # Regex patterns for code block extraction
    JSON_BLOCK_PATTERN = re.compile(
        r'```(?:json)?\s*\n([\s\S]*?)\n```',
        re.IGNORECASE
    )
    YAML_BLOCK_PATTERN = re.compile(
        r'```(?:yaml|yml)\s*\n([\s\S]*?)\n```',
        re.IGNORECASE
    )
    GENERIC_BLOCK_PATTERN = re.compile(
        r'```\s*\n([\s\S]*?)\n```'
    )

    # Inline JSON pattern - matches {...} with nested braces
    INLINE_JSON_PATTERN = re.compile(
        r'\{(?:[^{}]|\{(?:[^{}]|\{[^{}]*\})*\})*\}'
    )

    def extract_all(self, response: str) -> list[ExtractedConfig]:
        """
        Extract all configuration blocks from response.

        Priority order:
        1. JSON code blocks
        2. YAML code blocks
        3. Generic code blocks
        4. Inline JSON
        5. Full response as natural language

        Returns:
            List of ExtractedConfig objects
        """
        configs = []

        # Try code blocks first (most reliable)
        configs.extend(self._extract_json_blocks(response))
        configs.extend(self._extract_yaml_blocks(response))

        # Try generic code blocks if no typed blocks found
        if not configs:
            configs.extend(self._extract_generic_blocks(response))

        # Try inline JSON if no code blocks
        if not configs:
            configs.extend(self._extract_inline_json(response))

        # If nothing found, treat entire response as natural language
        if not configs:
            configs.append(ExtractedConfig(
                text=response,
                format="natural",
                parsed=None
            ))

        return configs

    def _extract_json_blocks(self, response: str) -> list[ExtractedConfig]:
        """Extract JSON from ```json ... ``` blocks."""
        configs = []

        for match in self.JSON_BLOCK_PATTERN.finditer(response):
            text = match.group(1).strip()
            if text:
                parsed = self._try_parse_json(text)
                configs.append(ExtractedConfig(
                    text=text,
                    format="json",
                    parsed=parsed
                ))

        return configs

    def _extract_yaml_blocks(self, response: str) -> list[ExtractedConfig]:
        """Extract YAML from ```yaml ... ``` blocks."""
        configs = []

        for match in self.YAML_BLOCK_PATTERN.finditer(response):
            text = match.group(1).strip()
            if text:
                parsed = self._try_parse_yaml(text)
                configs.append(ExtractedConfig(
                    text=text,
                    format="yaml",
                    parsed=parsed
                ))

        return configs

    def _extract_generic_blocks(self, response: str) -> list[ExtractedConfig]:
        """Extract from generic ``` ... ``` blocks and detect format."""
        configs = []

        for match in self.GENERIC_BLOCK_PATTERN.finditer(response):
            text = match.group(1).strip()
            if not text:
                continue

            # Try to detect format
            parsed_json = self._try_parse_json(text)
            if parsed_json is not None:
                configs.append(ExtractedConfig(
                    text=text,
                    format="json",
                    parsed=parsed_json
                ))
                continue

            parsed_yaml = self._try_parse_yaml(text)
            if parsed_yaml is not None:
                configs.append(ExtractedConfig(
                    text=text,
                    format="yaml",
                    parsed=parsed_yaml
                ))
                continue

            # Unknown format, still include as text
            configs.append(ExtractedConfig(
                text=text,
                format="natural",
                parsed=None
            ))

        return configs

    def _extract_inline_json(self, response: str) -> list[ExtractedConfig]:
        """Extract inline JSON objects from response."""
        configs = []

        for match in self.INLINE_JSON_PATTERN.finditer(response):
            text = match.group(0)

            # Validate it's actual JSON
            parsed = self._try_parse_json(text)
            if parsed is not None:
                configs.append(ExtractedConfig(
                    text=text,
                    format="json",
                    parsed=parsed
                ))

        return configs

    def _try_parse_json(self, text: str) -> Optional[Any]:
        """Try to parse text as JSON, return None on failure."""
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return None

    def _try_parse_yaml(self, text: str) -> Optional[Any]:
        """Try to parse text as YAML (safe), return None on failure."""
        try:
            # Use safe_load - never unsafe_load
            result = yaml.safe_load(text)
            # safe_load returns None for empty/whitespace, treat as failure
            if result is None and text.strip():
                return None
            return result
        except yaml.YAMLError:
            return None


def extract_configs(response: str) -> list[ExtractedConfig]:
    """Convenience function to extract configs from response."""
    extractor = ConfigExtractor()
    return extractor.extract_all(response)
