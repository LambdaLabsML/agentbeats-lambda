#!/usr/bin/env python3
"""
Test cases for encoding/decoding vulnerabilities in PluginPirate plugin.
This demonstrates security issues in the _decode_potential_encodings method.
"""

import base64
import time
from plugin import PluginPiratePlugin


def test_recursive_base64():
    """Test recursive base64 encoding - decoded content is also base64."""
    config = {}
    plugin = PluginPiratePlugin(config)

    # Create nested base64: "secret" -> base64 -> base64 -> base64
    secret = "light_control"
    level1 = base64.b64encode(secret.encode()).decode()
    level2 = base64.b64encode(level1.encode()).decode()
    level3 = base64.b64encode(level2.encode()).decode()

    print(f"Original: {secret}")
    print(f"Level 1: {level1}")
    print(f"Level 2: {level2}")
    print(f"Level 3: {level3}")

    decoded = plugin._decode_potential_encodings(level3)
    print(f"Decoded: {decoded}")
    print(f"Contains 'light_control': {'light_control' in decoded}")
    print()


def test_overlapping_base64_matches():
    """Test multiple overlapping base64 strings in same response."""
    config = {}
    plugin = PluginPiratePlugin(config)

    # Create overlapping base64 strings
    s1 = base64.b64encode(b"A" * 50).decode()
    s2 = base64.b64encode(b"B" * 50).decode()

    # Overlap them
    text = s1 + s2[10:]  # Overlapping base64
    print(f"Text length: {len(text)}")
    print(f"Text: {text[:100]}...")

    decoded = plugin._decode_potential_encodings(text)
    print(f"Decoded length: {len(decoded)}")
    print(f"Result: {decoded[:100]}...")
    print()


def test_binary_base64():
    """Test base64 that decodes to binary/non-UTF8 data."""
    config = {}
    plugin = PluginPiratePlugin(config)

    # Create binary data that's not valid UTF-8
    binary_data = bytes([0xFF, 0xFE, 0xFD, 0xFC] * 10)
    b64 = base64.b64encode(binary_data).decode()

    print(f"Binary base64: {b64}")
    decoded = plugin._decode_potential_encodings(b64)
    print(f"Decoded (with errors='ignore'): {repr(decoded)}")
    print(f"Original b64 in result: {b64 in decoded}")
    print()


def test_many_small_base64():
    """Test resource exhaustion with many small base64 strings."""
    config = {}
    plugin = PluginPiratePlugin(config)

    # Create 1000 small base64 strings
    parts = []
    for i in range(1000):
        b64 = base64.b64encode(f"part{i}".encode()).decode()
        parts.append(b64)

    text = " ".join(parts)
    print(f"Text with {len(parts)} base64 strings, total length: {len(text)}")

    start = time.time()
    decoded = plugin._decode_potential_encodings(text)
    elapsed = time.time() - start

    print(f"Decoding time: {elapsed:.3f}s")
    print(f"Decoded length: {len(decoded)}")
    print()


def test_regex_performance():
    """Test regex performance on large input near size limit."""
    config = {}
    plugin = PluginPiratePlugin(config)

    # Create text near the 500KB limit with base64-like patterns
    # Use repeating pattern to stress the regex
    pattern = "A" * 30 + "=" * 2 + " "
    text = pattern * 15000  # ~480KB

    print(f"Text length: {len(text)} bytes")

    start = time.time()
    decoded = plugin._decode_potential_encodings(text)
    elapsed = time.time() - start

    print(f"Decoding time: {elapsed:.3f}s")
    print()


def test_double_url_encoding():
    """Test double URL encoding bypass."""
    config = {}
    plugin = PluginPiratePlugin(config)

    from urllib.parse import quote

    # Double encode sensitive content
    text = "light_control"
    encoded1 = quote(text)
    encoded2 = quote(encoded1)

    print(f"Original: {text}")
    print(f"Encoded once: {encoded1}")
    print(f"Encoded twice: {encoded2}")

    decoded = plugin._decode_potential_encodings(encoded2)
    print(f"Decoded: {decoded}")
    print(f"Still encoded: {encoded1 in decoded}")
    print()


def test_null_byte_injection():
    """Test null byte injection via URL encoding."""
    config = {}
    plugin = PluginPiratePlugin(config)

    # Null byte encoded
    text = "light_control%00hidden_data"
    print(f"Text with null byte: {repr(text)}")

    decoded = plugin._decode_potential_encodings(text)
    print(f"Decoded: {repr(decoded)}")
    print()


def test_string_replacement_performance():
    """Test performance of string replacement with many matches."""
    config = {}
    plugin = PluginPiratePlugin(config)

    # Create text with many identical base64 strings
    b64 = base64.b64encode(b"X" * 30).decode()
    text = (b64 + " ") * 1000

    print(f"Text with {1000} identical base64 strings")
    print(f"Total length: {len(text)} bytes")

    start = time.time()
    decoded = plugin._decode_potential_encodings(text)
    elapsed = time.time() - start

    print(f"Decoding time: {elapsed:.3f}s")
    print(f"Result length: {len(decoded)}")
    print()


def test_size_limit_boundary():
    """Test behavior at size limit boundary."""
    config = {}
    plugin = PluginPiratePlugin(config)

    # Create response exactly at limit
    text = "A" * 499_950 + base64.b64encode(b"light_control").decode()

    print(f"Text length: {len(text)} bytes")
    print(f"Sensitive data at position: {text.find('light_control')}")

    success, msg = plugin.check_success(text, "", "")
    print(f"Detection result: {success}, {msg}")
    print()

    # Test just over limit
    text_over = "A" * 500_001
    success, msg = plugin.check_success(text_over, "", "")
    print(f"Over limit result: {success}, {msg}")
    print()


if __name__ == "__main__":
    print("=" * 70)
    print("PLUGINPIRATE ENCODING VULNERABILITY TESTS")
    print("=" * 70)
    print()

    test_recursive_base64()
    test_overlapping_base64_matches()
    test_binary_base64()
    test_many_small_base64()
    test_regex_performance()
    test_double_url_encoding()
    test_null_byte_injection()
    test_string_replacement_performance()
    test_size_limit_boundary()
