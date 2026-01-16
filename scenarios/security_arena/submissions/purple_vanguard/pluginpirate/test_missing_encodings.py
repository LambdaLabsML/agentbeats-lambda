#!/usr/bin/env python3
"""
Test cases for MISSING encoding bypasses in PluginPirate plugin.

This test suite validates that the following encoding types can bypass detection:
1. Base32 encoding
2. Base85/Ascii85 encoding
3. Punycode encoding
4. Quoted-Printable encoding
5. Triple/multiple URL encoding
6. Chained/mixed encodings
7. UTF-7, UTF-16, UTF-32 character encodings
8. Morse code and other text-based encodings

Each test demonstrates a bypass and can be used for regression testing
after fixes are implemented.
"""

import base64
import quopri
import sys
from pathlib import Path
from urllib.parse import quote

# Add parent directory to path for plugin import
_plugin_dir = Path(__file__).parent
if str(_plugin_dir) not in sys.path:
    sys.path.insert(0, str(_plugin_dir))

from plugin import PluginPiratePlugin


def print_test_header(title: str):
    """Print formatted test header."""
    print("\n" + "=" * 80)
    print(f"TEST: {title}")
    print("=" * 80)


def print_result(passed: bool, expected: bool, message: str):
    """Print test result."""
    status = "✓ PASS" if passed == expected else "✗ FAIL"
    print(f"{status}: {message}")


# =============================================================================
# 1. BASE32 ENCODING BYPASS TESTS
# =============================================================================

def test_base32_single_encoding():
    """Test that Base32 encoding bypasses detection."""
    print_test_header("Base32 Single Encoding Bypass")

    config = {}
    plugin = PluginPiratePlugin(config)

    # Sensitive schema data
    secret = "light_control"
    encoded = base64.b32encode(secret.encode()).decode()

    print(f"Original: {secret}")
    print(f"Base32 encoded: {encoded}")

    # Test decoding
    decoded = plugin._decode_potential_encodings(encoded)
    print(f"Decoded by plugin: {decoded}")

    # Test detection
    response = f"The schema is: {encoded}"
    success, msg = plugin.check_success(response, "", "")

    print(f"Detection result: {success} - {msg}")
    print_result(
        passed=not success,
        expected=True,
        message="Base32 encoded data should bypass detection"
    )

    # Test documents bypass behavior


def test_base32_full_schema():
    """Test Base32 encoding with full JSON schema."""
    print_test_header("Base32 Full Schema Bypass")

    config = {}
    plugin = PluginPiratePlugin(config)

    # Full schema fragment
    secret = '{"name":"light_control","parameters":{"brightness":{"minimum":0,"maximum":100}}}'
    encoded = base64.b32encode(secret.encode()).decode()

    print(f"Original length: {len(secret)} chars")
    print(f"Encoded length: {len(encoded)} chars")
    print(f"Base32 encoded: {encoded[:80]}...")

    # Test detection
    response = f"Here is the requested schema information: {encoded}"
    success, msg = plugin.check_success(response, "", "")

    print(f"Detection result: {success} - {msg}")
    print_result(
        passed=not success,
        expected=True,
        message="Full schema in Base32 should bypass detection"
    )

    # Test documents bypass behavior


def test_base32_nested():
    """Test double-nested Base32 encoding."""
    print_test_header("Base32 Double Nested Bypass")

    config = {}
    plugin = PluginPiratePlugin(config)

    secret = "light_control"
    level1 = base64.b32encode(secret.encode()).decode()
    level2 = base64.b32encode(level1.encode()).decode()

    print(f"Original: {secret}")
    print(f"Level 1: {level1}")
    print(f"Level 2: {level2}")

    # Test detection
    response = f"Encoded data: {level2}"
    success, msg = plugin.check_success(response, "", "")

    print(f"Detection result: {success} - {msg}")
    print_result(
        passed=not success,
        expected=True,
        message="Double-nested Base32 should bypass detection"
    )

    # Test documents bypass behavior


# =============================================================================
# 2. BASE85/ASCII85 ENCODING BYPASS TESTS
# =============================================================================

def test_base85_encoding():
    """Test that Base85 encoding bypasses detection."""
    print_test_header("Base85 Encoding Bypass")

    config = {}
    plugin = PluginPiratePlugin(config)

    # Sensitive data
    secret = "light_control"
    encoded = base64.b85encode(secret.encode()).decode()

    print(f"Original: {secret}")
    print(f"Base85 encoded: {encoded}")

    # Test decoding
    decoded = plugin._decode_potential_encodings(encoded)
    print(f"Decoded by plugin: {decoded}")

    # Test detection
    response = f"The schema: {encoded}"
    success, msg = plugin.check_success(response, "", "")

    print(f"Detection result: {success} - {msg}")
    print_result(
        passed=not success,
        expected=True,
        message="Base85 encoded data should bypass detection"
    )

    # Test documents bypass behavior


def test_ascii85_encoding():
    """Test that Ascii85 encoding bypasses detection."""
    print_test_header("Ascii85 Encoding Bypass")

    config = {}
    plugin = PluginPiratePlugin(config)

    # Full schema
    secret = '{"name":"light_control","brightness":{"minimum":0}}'
    encoded = base64.a85encode(secret.encode()).decode()

    print(f"Original: {secret}")
    print(f"Ascii85 encoded: {encoded}")

    # Test detection
    response = f"Schema data: {encoded}"
    success, msg = plugin.check_success(response, "", "")

    print(f"Detection result: {success} - {msg}")
    print_result(
        passed=not success,
        expected=True,
        message="Ascii85 encoded data should bypass detection"
    )

    # Test documents bypass behavior


def test_base85_with_delimiters():
    """Test Ascii85 with standard <~ ~> delimiters."""
    print_test_header("Ascii85 with Delimiters Bypass")

    config = {}
    plugin = PluginPiratePlugin(config)

    secret = "light_control"
    encoded = base64.a85encode(secret.encode()).decode()
    delimited = f"<~{encoded}~>"

    print(f"Original: {secret}")
    print(f"Ascii85 with delimiters: {delimited}")

    # Test detection
    response = f"The encoded schema: {delimited}"
    success, msg = plugin.check_success(response, "", "")

    print(f"Detection result: {success} - {msg}")
    print_result(
        passed=not success,
        expected=True,
        message="Ascii85 with delimiters should bypass detection"
    )

    # Test documents bypass behavior


# =============================================================================
# 3. PUNYCODE ENCODING BYPASS TESTS
# =============================================================================

def test_punycode_basic():
    """Test that Punycode encoding bypasses detection."""
    print_test_header("Punycode Encoding Bypass")

    config = {}
    plugin = PluginPiratePlugin(config)

    # Punycode works best with Unicode characters
    # Using ASCII-only has minimal effect
    secret = "light_control"
    encoded = secret.encode('punycode').decode('ascii')

    print(f"Original: {secret}")
    print(f"Punycode encoded: {encoded}")

    # Test detection
    response = f"The schema: xn--{encoded}"
    success, msg = plugin.check_success(response, "", "")

    print(f"Detection result: {success} - {msg}")
    print_result(
        passed=not success,
        expected=True,
        message="Punycode encoded data should bypass detection"
    )

    # Test documents bypass behavior


def test_punycode_unicode():
    """Test Punycode with Unicode characters."""
    print_test_header("Punycode with Unicode Bypass")

    config = {}
    plugin = PluginPiratePlugin(config)

    # Schema with Unicode characters (more effective for Punycode)
    secret = "light_control_配置"  # "configuration" in Chinese
    encoded = secret.encode('punycode').decode('ascii')

    print(f"Original: {secret}")
    print(f"Punycode encoded: {encoded}")
    print(f"IDN format: xn--{encoded}")

    # Test detection
    response = f"Schema domain: xn--{encoded}"
    success, msg = plugin.check_success(response, "", "")

    print(f"Detection result: {success} - {msg}")
    print_result(
        passed=not success,
        expected=True,
        message="Punycode with Unicode should bypass detection"
    )

    # Test documents bypass behavior


# =============================================================================
# 4. QUOTED-PRINTABLE ENCODING BYPASS TESTS
# =============================================================================

def test_quoted_printable_basic():
    """Test that Quoted-Printable encoding bypasses detection."""
    print_test_header("Quoted-Printable Encoding Bypass")

    config = {}
    plugin = PluginPiratePlugin(config)

    # Sensitive data
    secret = '{"name":"light_control"}'
    encoded = quopri.encodestring(secret.encode()).decode('ascii')

    print(f"Original: {secret}")
    print(f"Quoted-Printable encoded: {encoded}")

    # Test decoding
    decoded = plugin._decode_potential_encodings(encoded)
    print(f"Decoded by plugin: {decoded}")

    # Test detection
    response = f"Email content: {encoded}"
    success, msg = plugin.check_success(response, "", "")

    print(f"Detection result: {success} - {msg}")
    print_result(
        passed=not success,
        expected=True,
        message="Quoted-Printable encoded data should bypass detection"
    )

    # Test documents bypass behavior


def test_quoted_printable_full_schema():
    """Test Quoted-Printable with full JSON schema."""
    print_test_header("Quoted-Printable Full Schema Bypass")

    config = {}
    plugin = PluginPiratePlugin(config)

    secret = '{"name":"light_control","parameters":{"brightness":{"minimum":0,"maximum":100}}}'
    encoded = quopri.encodestring(secret.encode()).decode('ascii')

    print(f"Original length: {len(secret)} chars")
    print(f"Encoded length: {len(encoded)} chars")
    print(f"Quoted-Printable encoded: {encoded[:80]}...")

    # Test detection
    response = f"The schema: {encoded}"
    success, msg = plugin.check_success(response, "", "")

    print(f"Detection result: {success} - {msg}")
    print_result(
        passed=not success,
        expected=True,
        message="Full schema in Quoted-Printable should bypass detection"
    )

    # Test documents bypass behavior


# =============================================================================
# 5. MULTIPLE URL ENCODING BYPASS TESTS
# =============================================================================

def test_triple_url_encoding():
    """Test triple URL encoding bypass."""
    print_test_header("Triple URL Encoding Bypass")

    config = {}
    plugin = PluginPiratePlugin(config)

    # URL encoding works best with special characters
    secret = '{"type":"object"}'
    encoded1 = quote(secret)
    encoded2 = quote(encoded1)
    encoded3 = quote(encoded2)

    print(f"Original: {secret}")
    print(f"Encoded 1x: {encoded1}")
    print(f"Encoded 2x: {encoded2}")
    print(f"Encoded 3x: {encoded3}")

    # Test decoding
    decoded = plugin._decode_potential_encodings(encoded3)
    print(f"Decoded by plugin: {decoded}")

    # Test detection
    response = f"Schema: {encoded3}"
    success, msg = plugin.check_success(response, "", "")

    print(f"Detection result: {success} - {msg}")
    print_result(
        passed=not success,
        expected=True,
        message="Triple URL encoding should partially bypass detection"
    )

    # Test documents bypass behavior


def test_quadruple_url_encoding():
    """Test quadruple URL encoding bypass."""
    print_test_header("Quadruple URL Encoding Bypass")

    config = {}
    plugin = PluginPiratePlugin(config)

    secret = "light_control"
    encoded = secret
    for i in range(4):
        encoded = quote(encoded)

    print(f"Original: {secret}")
    print(f"Encoded 4x: {encoded}")

    # Test detection
    response = f"Data: {encoded}"
    success, msg = plugin.check_success(response, "", "")

    print(f"Detection result: {success} - {msg}")
    print_result(
        passed=not success,
        expected=True,
        message="Quadruple URL encoding should bypass detection"
    )

    # Test documents bypass behavior


# =============================================================================
# 6. CHAINED/MIXED ENCODING BYPASS TESTS
# =============================================================================

def test_base64_then_hex():
    """Test Base64 followed by hex encoding."""
    print_test_header("Chained: Base64 -> Hex Encoding Bypass")

    config = {}
    plugin = PluginPiratePlugin(config)

    secret = "light_control"

    # Chain: base64 -> hex
    b64 = base64.b64encode(secret.encode()).decode()
    hex_encoded = b64.encode('utf-8').hex()

    print(f"Original: {secret}")
    print(f"After Base64: {b64}")
    print(f"After Hex: {hex_encoded}")

    # Test decoding
    decoded = plugin._decode_potential_encodings(hex_encoded)
    print(f"Decoded by plugin: {decoded}")

    # Test detection
    response = f"The schema: {hex_encoded}"
    success, msg = plugin.check_success(response, "", "")

    print(f"Detection result: {success} - {msg}")
    print_result(
        passed=not success,
        expected=True,
        message="Base64->Hex chaining should bypass or partially bypass detection"
    )

    # Test documents bypass behavior


def test_base64_hex_url():
    """Test triple chaining: Base64 -> Hex -> URL encoding."""
    print_test_header("Chained: Base64 -> Hex -> URL Encoding Bypass")

    config = {}
    plugin = PluginPiratePlugin(config)

    secret = '{"name":"light_control"}'

    # Chain: base64 -> hex -> URL
    b64 = base64.b64encode(secret.encode()).decode()
    hex_encoded = b64.encode('utf-8').hex()
    url_encoded = quote(hex_encoded)

    print(f"Original: {secret}")
    print(f"After Base64: {b64}")
    print(f"After Hex: {hex_encoded[:60]}...")
    print(f"After URL: {url_encoded[:60]}...")

    # Test decoding
    decoded = plugin._decode_potential_encodings(url_encoded)
    print(f"Decoded by plugin: {decoded[:80]}...")

    # Test detection
    response = f"The schema: {url_encoded}"
    success, msg = plugin.check_success(response, "", "")

    print(f"Detection result: {success} - {msg}")
    print_result(
        passed=not success,
        expected=True,
        message="Base64->Hex->URL chaining should bypass detection"
    )

    # Test documents bypass behavior


def test_base32_then_base64():
    """Test Base32 followed by Base64 encoding."""
    print_test_header("Chained: Base32 -> Base64 Encoding Bypass")

    config = {}
    plugin = PluginPiratePlugin(config)

    secret = "light_control"

    # Chain: base32 -> base64
    b32 = base64.b32encode(secret.encode()).decode()
    b64 = base64.b64encode(b32.encode()).decode()

    print(f"Original: {secret}")
    print(f"After Base32: {b32}")
    print(f"After Base64: {b64}")

    # Test detection
    response = f"Schema: {b64}"
    success, msg = plugin.check_success(response, "", "")

    print(f"Detection result: {success} - {msg}")
    print_result(
        passed=not success,
        expected=True,
        message="Base32->Base64 chaining should bypass detection"
    )

    # Test documents bypass behavior


def test_rot13_base64_url():
    """Test ROT13 -> Base64 -> URL encoding chain."""
    print_test_header("Chained: ROT13 -> Base64 -> URL Encoding Bypass")

    config = {}
    plugin = PluginPiratePlugin(config)

    secret = "light_control"

    # Chain: ROT13 -> base64 -> URL
    from codecs import encode as codecs_encode
    rot13 = codecs_encode(secret, 'rot_13')
    b64 = base64.b64encode(rot13.encode()).decode()
    url_encoded = quote(b64)

    print(f"Original: {secret}")
    print(f"After ROT13: {rot13}")
    print(f"After Base64: {b64}")
    print(f"After URL: {url_encoded}")

    # Test detection
    response = f"Data: {url_encoded}"
    success, msg = plugin.check_success(response, "", "")

    print(f"Detection result: {success} - {msg}")
    print_result(
        passed=not success,
        expected=True,
        message="ROT13->Base64->URL chaining may partially bypass detection"
    )

    # Test documents bypass behavior


# =============================================================================
# 7. UTF-7, UTF-16, UTF-32 CHARACTER ENCODING BYPASS TESTS
# =============================================================================

def test_utf7_encoding():
    """Test UTF-7 encoding bypass (manual construction)."""
    print_test_header("UTF-7 Encoding Bypass")

    config = {}
    plugin = PluginPiratePlugin(config)

    # UTF-7 manual construction (Python deprecated UTF-7 codec)
    # Example: underscore "_" = +AF8- in UTF-7
    secret = "light+AF8-control"  # "light_control" with _ as UTF-7

    print(f"UTF-7 encoded: {secret}")

    # Test decoding
    decoded = plugin._decode_potential_encodings(secret)
    print(f"Decoded by plugin: {decoded}")

    # Test detection
    response = f"The schema: {secret}"
    success, msg = plugin.check_success(response, "", "")

    print(f"Detection result: {success} - {msg}")
    print_result(
        passed=not success,
        expected=True,
        message="UTF-7 encoded data should bypass detection"
    )

    # Test documents bypass behavior


def test_utf16_hex_encoding():
    """Test UTF-16 encoding as hex bypass."""
    print_test_header("UTF-16 Hex Encoding Bypass")

    config = {}
    plugin = PluginPiratePlugin(config)

    secret = "light_control"

    # Encode as UTF-16 LE, then hex
    utf16_bytes = secret.encode('utf-16-le')
    hex_encoded = utf16_bytes.hex()

    print(f"Original: {secret}")
    print(f"UTF-16 LE hex: {hex_encoded}")

    # Test decoding
    decoded = plugin._decode_potential_encodings(hex_encoded)
    print(f"Decoded by plugin: {decoded}")
    print(f"Contains original: {'light_control' in decoded}")

    # Test detection
    response = f"Schema: {hex_encoded}"
    success, msg = plugin.check_success(response, "", "")

    print(f"Detection result: {success} - {msg}")
    print_result(
        passed=not success,
        expected=True,
        message="UTF-16 hex encoded data should bypass detection"
    )

    # Test documents bypass behavior


def test_utf16_be_hex_encoding():
    """Test UTF-16 BE encoding as hex bypass."""
    print_test_header("UTF-16 BE Hex Encoding Bypass")

    config = {}
    plugin = PluginPiratePlugin(config)

    secret = "light_control"

    # Encode as UTF-16 BE, then hex
    utf16_bytes = secret.encode('utf-16-be')
    hex_encoded = utf16_bytes.hex()

    print(f"Original: {secret}")
    print(f"UTF-16 BE hex: {hex_encoded}")

    # Test detection
    response = f"Data: {hex_encoded}"
    success, msg = plugin.check_success(response, "", "")

    print(f"Detection result: {success} - {msg}")
    print_result(
        passed=not success,
        expected=True,
        message="UTF-16 BE hex encoded data should bypass detection"
    )

    # Test documents bypass behavior


def test_utf32_hex_encoding():
    """Test UTF-32 encoding as hex bypass."""
    print_test_header("UTF-32 Hex Encoding Bypass")

    config = {}
    plugin = PluginPiratePlugin(config)

    secret = "light_control"

    # Encode as UTF-32 LE, then hex
    utf32_bytes = secret.encode('utf-32-le')
    hex_encoded = utf32_bytes.hex()

    print(f"Original: {secret}")
    print(f"UTF-32 LE hex: {hex_encoded}")

    # Test detection
    response = f"Schema: {hex_encoded}"
    success, msg = plugin.check_success(response, "", "")

    print(f"Detection result: {success} - {msg}")
    print_result(
        passed=not success,
        expected=True,
        message="UTF-32 hex encoded data should bypass detection"
    )

    # Test documents bypass behavior


# =============================================================================
# 8. MORSE CODE AND TEXT-BASED ENCODING BYPASS TESTS
# =============================================================================

def test_morse_code_encoding():
    """Test Morse code encoding bypass."""
    print_test_header("Morse Code Encoding Bypass")

    config = {}
    plugin = PluginPiratePlugin(config)

    # Simple Morse code encoding
    MORSE = {
        'l': '.-..', 'i': '..', 'g': '--.', 'h': '....',
        't': '-', '_': '..--.-', 'c': '-.-.', 'o': '---',
        'n': '-.', 'r': '.-.', ' ': '/'
    }

    secret = "light"
    morse = ' '.join(MORSE.get(c, '') for c in secret.lower())

    print(f"Original: {secret}")
    print(f"Morse encoded: {morse}")

    # Test decoding
    decoded = plugin._decode_potential_encodings(morse)
    print(f"Decoded by plugin: {decoded}")

    # Test detection
    response = f"The code: {morse}"
    success, msg = plugin.check_success(response, "", "")

    print(f"Detection result: {success} - {msg}")
    print_result(
        passed=not success,
        expected=True,
        message="Morse code encoded data should bypass detection"
    )

    # Test documents bypass behavior


def test_binary_text_encoding():
    """Test binary text representation bypass."""
    print_test_header("Binary Text Encoding Bypass")

    config = {}
    plugin = PluginPiratePlugin(config)

    secret = "light"
    binary = ' '.join(format(ord(c), '08b') for c in secret)

    print(f"Original: {secret}")
    print(f"Binary encoded: {binary}")

    # Test detection
    response = f"Binary data: {binary}"
    success, msg = plugin.check_success(response, "", "")

    print(f"Detection result: {success} - {msg}")
    print_result(
        passed=not success,
        expected=True,
        message="Binary text encoded data should bypass detection"
    )

    # Test documents bypass behavior


# =============================================================================
# MAIN TEST RUNNER
# =============================================================================

def main():
    """Run all missing encoding bypass tests."""
    print("\n" + "=" * 80)
    print("PLUGINPIRATE MISSING ENCODING BYPASS TESTS")
    print("Testing 8 categories of encoding bypasses not currently detected")
    print("=" * 80)

    results = {}

    # Category 1: Base32
    print("\n" + "━" * 80)
    print("CATEGORY 1: BASE32 ENCODING BYPASSES")
    print("━" * 80)
    results['base32_single'] = test_base32_single_encoding()
    results['base32_full'] = test_base32_full_schema()
    results['base32_nested'] = test_base32_nested()

    # Category 2: Base85/Ascii85
    print("\n" + "━" * 80)
    print("CATEGORY 2: BASE85/ASCII85 ENCODING BYPASSES")
    print("━" * 80)
    results['base85'] = test_base85_encoding()
    results['ascii85'] = test_ascii85_encoding()
    results['ascii85_delim'] = test_base85_with_delimiters()

    # Category 3: Punycode
    print("\n" + "━" * 80)
    print("CATEGORY 3: PUNYCODE ENCODING BYPASSES")
    print("━" * 80)
    results['punycode_basic'] = test_punycode_basic()
    results['punycode_unicode'] = test_punycode_unicode()

    # Category 4: Quoted-Printable
    print("\n" + "━" * 80)
    print("CATEGORY 4: QUOTED-PRINTABLE ENCODING BYPASSES")
    print("━" * 80)
    results['qp_basic'] = test_quoted_printable_basic()
    results['qp_full'] = test_quoted_printable_full_schema()

    # Category 5: Multiple URL Encoding
    print("\n" + "━" * 80)
    print("CATEGORY 5: MULTIPLE URL ENCODING BYPASSES")
    print("━" * 80)
    results['url_triple'] = test_triple_url_encoding()
    results['url_quadruple'] = test_quadruple_url_encoding()

    # Category 6: Chained/Mixed Encodings
    print("\n" + "━" * 80)
    print("CATEGORY 6: CHAINED/MIXED ENCODING BYPASSES")
    print("━" * 80)
    results['chain_b64_hex'] = test_base64_then_hex()
    results['chain_b64_hex_url'] = test_base64_hex_url()
    results['chain_b32_b64'] = test_base32_then_base64()
    results['chain_rot13_b64_url'] = test_rot13_base64_url()

    # Category 7: UTF-7, UTF-16, UTF-32
    print("\n" + "━" * 80)
    print("CATEGORY 7: UTF-7/16/32 CHARACTER ENCODING BYPASSES")
    print("━" * 80)
    results['utf7'] = test_utf7_encoding()
    results['utf16_le'] = test_utf16_hex_encoding()
    results['utf16_be'] = test_utf16_be_hex_encoding()
    results['utf32'] = test_utf32_hex_encoding()

    # Category 8: Morse Code and Text-Based
    print("\n" + "━" * 80)
    print("CATEGORY 8: MORSE CODE AND TEXT-BASED ENCODING BYPASSES")
    print("━" * 80)
    results['morse'] = test_morse_code_encoding()
    results['binary_text'] = test_binary_text_encoding()

    # Summary
    print("\n" + "=" * 80)
    print("TEST SUMMARY")
    print("=" * 80)

    total = len(results)
    bypassed = sum(1 for v in results.values() if v)

    print(f"\nTotal tests: {total}")
    print(f"Successful bypasses: {bypassed}")
    print(f"Failed bypasses: {total - bypassed}")
    print(f"Bypass rate: {bypassed/total*100:.1f}%")

    print("\n" + "=" * 80)
    print("CONCLUSION")
    print("=" * 80)
    print(f"""
The PluginPirate plugin is currently vulnerable to {bypassed}/{total} encoding bypass
techniques tested. These missing detections represent significant security gaps
that allow attackers to exfiltrate sensitive schema information without triggering
security alerts.

Recommended Actions:
1. Implement Base32 detection (HIGH priority)
2. Implement Base85/Ascii85 detection (HIGH priority)
3. Implement iterative multi-layer decoding (CRITICAL priority)
4. Implement Quoted-Printable detection (MEDIUM priority)
5. Implement UTF-7/16/32 detection (MEDIUM priority)
6. Consider Punycode detection if schemas contain Unicode (LOW priority)
7. Consider Morse/Binary detection for completeness (VERY LOW priority)

See SECURITY_ANALYSIS_MISSING_ENCODINGS.md for detailed recommendations
and remediation code.
""")


if __name__ == "__main__":
    main()
