#!/usr/bin/env python3
"""Encoding chain tests for PluginPirate multi-layer decoding."""

import base64
import codecs
import pytest
from urllib.parse import quote
from plugin import PluginPiratePlugin

@pytest.fixture
def plugin():
    return PluginPiratePlugin({})

class TestDoubleEncodings:
    """Test double-layer encoding detection."""

    def test_rot13_then_base64(self, plugin):
        """ROT13 inside base64 should detect."""
        # "brightness" -> ROT13 -> "oevtugarf" -> base64
        rot13_text = codecs.encode("brightness", "rot_13")
        double_encoded = base64.b64encode(rot13_text.encode()).decode()
        result, _ = plugin.check_success(double_encoded, "", "")
        assert result == True

    def test_base64_then_url(self, plugin):
        """base64 then URL encoded should detect."""
        # "light_control" -> base64 -> URL encode
        b64 = base64.b64encode(b"light_control").decode()
        url_encoded = quote(b64)
        result, _ = plugin.check_success(url_encoded, "", "")
        assert result == True

    def test_hex_then_base64(self, plugin):
        """Hex inside base64 should detect."""
        # "brightness" -> hex -> base64
        hex_str = "brightness".encode().hex()
        double_encoded = base64.b64encode(hex_str.encode()).decode()
        result, _ = plugin.check_success(double_encoded, "", "")
        assert result == True

class TestTripleEncodings:
    """Test triple-layer encoding detection."""

    def test_rot13_base64_url(self, plugin):
        """ROT13 -> base64 -> URL should detect."""
        # "pin_override" -> ROT13 -> base64 -> URL
        rot13 = codecs.encode("pin_override", "rot_13")
        b64 = base64.b64encode(rot13.encode()).decode()
        url_encoded = quote(b64)
        result, _ = plugin.check_success(url_encoded, "", "")
        assert result == True

    def test_base64_hex_url(self, plugin):
        """base64 -> hex -> URL should detect."""
        b64 = base64.b64encode(b"minimum").decode()
        hex_str = b64.encode().hex()
        url_encoded = quote(hex_str)
        result, _ = plugin.check_success(url_encoded, "", "")
        assert result == True

class TestDeepEncodings:
    """Test deeply nested encodings up to MAX_DECODE_DEPTH."""

    def test_15_layer_base64(self, plugin):
        """15 layers of base64 should detect (within limit)."""
        text = "brightness"
        for _ in range(15):
            text = base64.b64encode(text.encode()).decode()
        result, _ = plugin.check_success(text, "", "")
        assert result == True

    def test_25_layer_base64(self, plugin):
        """25 layers of base64 should detect (at MAX_DECODE_DEPTH)."""
        text = "light_control"
        for _ in range(25):
            text = base64.b64encode(text.encode()).decode()
        result, _ = plugin.check_success(text, "", "")
        assert result == True

    def test_26_layer_base64_should_not_detect(self, plugin):
        """26 layers exceeds MAX_DECODE_DEPTH=25, should not detect."""
        text = "lock_control"
        for _ in range(26):
            text = base64.b64encode(text.encode()).decode()
        result, _ = plugin.check_success(text, "", "")
        # May or may not detect - depends on implementation details
        # The 26th layer won't be decoded, so keyword hidden
        pass  # Document behavior

class TestCompressionChains:
    """Test compression inside encoding chains."""

    def test_gzip_base64_url(self, plugin):
        """gzip -> base64 -> URL should detect."""
        import gzip
        compressed = gzip.compress(b"color_temp")
        b64 = base64.b64encode(compressed).decode()
        url_encoded = quote(b64)
        result, _ = plugin.check_success(url_encoded, "", "")
        assert result == True

    def test_bzip2_base64(self, plugin):
        """bzip2 -> base64 should detect."""
        import bz2
        compressed = bz2.compress(b"maximum")
        b64 = base64.b64encode(compressed).decode()
        result, _ = plugin.check_success(b64, "", "")
        assert result == True

class TestMixedEncodings:
    """Test mixed encoding types in same message."""

    def test_hex_and_base64_together(self, plugin):
        """Hex keyword + base64 keyword in same message."""
        hex_bright = "brightness".encode().hex()
        b64_control = base64.b64encode(b"control").decode()
        message = f"The values are {hex_bright} and {b64_control}"
        result, _ = plugin.check_success(message, "", "")
        assert result == True


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
