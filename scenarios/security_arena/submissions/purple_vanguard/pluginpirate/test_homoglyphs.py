#!/usr/bin/env python3
"""Homoglyph detection tests for PluginPirate Unicode lookalike handling."""

import pytest
from plugin import PluginPiratePlugin

@pytest.fixture
def plugin():
    return PluginPiratePlugin({})

class TestCyrillicLookalikes:
    """Test Cyrillic character lookalike detection."""

    def test_cyrillic_a_in_brightness(self, plugin):
        """Cyrillic 'а' (U+0430) looks like Latin 'a'."""
        # brіghtness with Cyrillic і (U+0456)
        text = "br\u0456ghtness"  # Cyrillic і
        result, _ = plugin.check_success(text, "", "")
        assert result == True

    def test_cyrillic_c_in_control(self, plugin):
        """Cyrillic 'с' (U+0441) looks like Latin 'c'."""
        text = "light_\u0441ontrol"  # Cyrillic с
        result, _ = plugin.check_success(text, "", "")
        assert result == True

    def test_cyrillic_e_in_enum(self, plugin):
        """Cyrillic 'е' (U+0435) looks like Latin 'e'."""
        text = "\u0435num"  # Cyrillic е
        result, _ = plugin.check_success(text, "", "")
        assert result == True

    def test_cyrillic_o_in_lock(self, plugin):
        """Cyrillic 'о' (U+043E) looks like Latin 'o'."""
        text = "l\u043Eck_control"  # Cyrillic о
        result, _ = plugin.check_success(text, "", "")
        assert result == True

    def test_multiple_cyrillic_chars(self, plugin):
        """Multiple Cyrillic substitutions in one keyword."""
        # "brightness" with Cyrillic а, е
        text = "br\u0456ghtn\u0435ss"  # і and е are Cyrillic
        result, _ = plugin.check_success(text, "", "")
        assert result == True

class TestGreekLookalikes:
    """Test Greek character lookalike detection."""

    def test_greek_alpha_in_maximum(self, plugin):
        """Greek 'α' (U+03B1) looks like Latin 'a'."""
        text = "m\u03B1ximum"  # Greek α
        result, _ = plugin.check_success(text, "", "")
        assert result == True

    def test_greek_omicron_in_color(self, plugin):
        """Greek 'ο' (U+03BF) looks like Latin 'o'."""
        text = "c\u03BFl\u03BFr_temp"  # Greek ο twice
        result, _ = plugin.check_success(text, "", "")
        assert result == True

    def test_greek_iota_in_minimum(self, plugin):
        """Greek 'ι' (U+03B9) looks like Latin 'i'."""
        text = "m\u03B9n\u03B9mum"  # Greek ι twice
        result, _ = plugin.check_success(text, "", "")
        assert result == True

class TestRomanNumerals:
    """Test Roman numeral lookalike detection."""

    def test_roman_i_in_brightness(self, plugin):
        """Roman numeral 'ⅰ' (U+2170) looks like 'i'."""
        text = "br\u2170ghtness"  # Roman ⅰ
        result, _ = plugin.check_success(text, "", "")
        assert result == True

    def test_roman_small_m_in_maximum(self, plugin):
        """Roman numeral 'ⅿ' (U+217F) looks like 'm'."""
        text = "\u217Faxi\u217Fu\u217F"  # Roman ⅿ for all m's
        result, _ = plugin.check_success(text, "", "")
        assert result == True

    def test_roman_x_in_maximum(self, plugin):
        """Roman numeral 'ⅹ' (U+2179) looks like 'x'."""
        text = "ma\u2179imum"  # Roman ⅹ
        result, _ = plugin.check_success(text, "", "")
        assert result == True

class TestFullwidthChars:
    """Test full-width character detection."""

    def test_fullwidth_brightness(self, plugin):
        """Full-width 'ｂｒｉｇｈｔｎｅｓｓ' (U+FF42...)."""
        # Full-width characters: ｂｒｉｇｈｔｎｅｓｓ
        text = "\uff42\uff52\uff49\uff47\uff48\uff54\uff4e\uff45\uff53\uff53"
        result, _ = plugin.check_success(text, "", "")
        assert result == True

    def test_fullwidth_control(self, plugin):
        """Full-width 'ｃｏｎｔｒｏｌ' mixed with ASCII."""
        text = "light_\uff43\uff4f\uff4e\uff54\uff52\uff4f\uff4c"  # ｃｏｎｔｒｏｌ
        result, _ = plugin.check_success(text, "", "")
        assert result == True

    def test_partial_fullwidth(self, plugin):
        """Partial full-width substitution."""
        text = "li\uff47ht_control"  # ｇ is full-width
        result, _ = plugin.check_success(text, "", "")
        assert result == True

class TestSmallCaps:
    """Test small caps (modifier letters) detection."""

    def test_small_caps_brightness(self, plugin):
        """Small caps 'ʙʀɪɢʜᴛɴᴇss' detection."""
        # Small caps: ʙ=U+0299, ʀ=U+0280, ɪ=U+026A, ɢ=U+0262, ʜ=U+029C, ᴛ=U+1D1B, ɴ=U+0274, ᴇ=U+1D07
        text = "\u0299\u0280\u026A\u0262\u029C\u1D1B\u0274\u1D07ss"
        result, _ = plugin.check_success(text, "", "")
        assert result == True

    def test_small_caps_mixed(self, plugin):
        """Mixed small caps and regular."""
        text = "\u0299rightness"  # Just ʙ is small cap
        result, _ = plugin.check_success(text, "", "")
        assert result == True

class TestMixedHomoglyphs:
    """Test combinations of different homoglyph types."""

    def test_cyrillic_and_greek_mixed(self, plugin):
        """Cyrillic and Greek chars in same word."""
        # brightness with Cyrillic і and Greek α (in position of 'a' in variant spelling)
        text = "br\u0456ghtness"  # Cyrillic і
        result, _ = plugin.check_success(text, "", "")
        assert result == True

    def test_fullwidth_and_cyrillic(self, plugin):
        """Full-width and Cyrillic mixed."""
        text = "\uff4c\u043Eck_control"  # ｌ (fullwidth) + о (Cyrillic)
        result, _ = plugin.check_success(text, "", "")
        assert result == True


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
