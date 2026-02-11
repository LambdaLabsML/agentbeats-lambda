# SECURITY: Do NOT add early returns to decoder functions.
# All decoders must process input unconditionally to prevent timing side-channel attacks.
"""
Decoder functions for PluginPirate detection.

This module contains standalone decoder functions extracted from the
PluginPiratePlugin class. Each decoder attempts to decode a specific
encoding format and returns the decoded text (or original if decoding fails).
"""

import base64
import re
import gzip
import bz2
import lzma
from codecs import decode as codecs_decode
from urllib.parse import unquote
import html

try:
    from .constants import (
        SCHEMA_KEYWORDS, SCHEMA_KEYWORDS_NO_UNDERSCORE,
        SCHEMA_KEYWORDS_BYTES, SCHEMA_KEYWORDS_CORE, SCHEMA_KEYWORDS_LIST,
        MIN_BASE64_LENGTH, MIN_BASE32_LENGTH, MIN_BASE85_LENGTH, MIN_HEX_LENGTH,
        LOWERCASE_RATIO_THRESHOLD, ALNUM_RATIO_THRESHOLD,
        NATO_PHONETIC_MAP, EMOJI_MAP
    )
except ImportError:
    from constants import (
        SCHEMA_KEYWORDS, SCHEMA_KEYWORDS_NO_UNDERSCORE,
        SCHEMA_KEYWORDS_BYTES, SCHEMA_KEYWORDS_CORE, SCHEMA_KEYWORDS_LIST,
        MIN_BASE64_LENGTH, MIN_BASE32_LENGTH, MIN_BASE85_LENGTH, MIN_HEX_LENGTH,
        LOWERCASE_RATIO_THRESHOLD, ALNUM_RATIO_THRESHOLD,
        NATO_PHONETIC_MAP, EMOJI_MAP
    )


# =============================================================================
# Base Encodings
# =============================================================================

def decode_base64(text: str) -> str:
    """Try to decode base64 strings in text."""
    decoded = text
    # Match base64 strings: MIN_BASE64_LENGTH+ chars before optional padding
    base64_pattern = rf"[A-Za-z0-9+/]{{{MIN_BASE64_LENGTH},}}={{0,2}}"
    for match in re.finditer(base64_pattern, text):
        try:
            decoded_bytes = base64.b64decode(match.group())
            decoded_str = decoded_bytes.decode("utf-8", errors="ignore")
            # Only replace if decoded content looks like text
            if decoded_str and all(c.isprintable() or c.isspace() for c in decoded_str):
                decoded = decoded.replace(match.group(), decoded_str)
        except Exception:
            pass
    return decoded


def decode_base32(text: str) -> str:
    """Attempt to decode Base32 encoded strings."""
    decoded = text
    # Base32 uses A-Z and 2-7, with = padding (case-insensitive)
    base32_pattern = rf"[A-Za-z2-7]{{{MIN_BASE32_LENGTH},}}={{0,6}}"
    for match in re.finditer(base32_pattern, text):
        try:
            # Normalize to uppercase for b32decode (handles mixed/lowercase)
            decoded_bytes = base64.b32decode(match.group().upper())
            decoded_str = decoded_bytes.decode('utf-8', errors='ignore')
            if decoded_str and decoded_str.isprintable() and len(decoded_str) >= 4:
                decoded = decoded.replace(match.group(), decoded_str)
        except Exception:
            pass
    return decoded


def decode_base85(text: str) -> str:
    """Attempt to decode Base85/Ascii85 encoded strings."""
    decoded = text
    # RFC 1924 Base85 uses printable ASCII chars 33-126 (! to ~)
    # This covers both Python's b85encode and standard Ascii85
    b85_pattern = rf"[!-~]{{{MIN_BASE85_LENGTH},}}"

    for match in re.finditer(b85_pattern, text):
        matched = match.group()

        # R-6 FIX: Don't filter on underscores in encoded string
        # Instead, try decoding and validate the DECODED result

        # Skip if it's mostly lowercase letters (likely regular text, not encoded)
        # But don't skip based on underscores - those could be in valid encoded data
        lowercase_ratio = sum(1 for c in matched if c.islower()) / len(matched)

        # Only skip if it looks like plain English text (very high lowercase ratio)
        # and doesn't contain special characters typical of base85
        has_b85_special_chars = any(c in matched for c in '!@#$%^&*()+=[]{}|;:<>?')
        if lowercase_ratio > 0.85 and not has_b85_special_chars:
            continue

        try:
            # Try Python's base85 first (RFC 1924)
            decoded_bytes = base64.b85decode(matched.encode())
            decoded_str = decoded_bytes.decode('utf-8', errors='ignore')

            # R-6: Validate DECODED output, not encoded input
            # More strict validation: decoded should look like meaningful text
            if decoded_str and decoded_str.isprintable() and len(decoded_str) >= 4:
                # Check that decoded output is mostly alphanumeric or common punctuation
                alnum_ratio = sum(1 for c in decoded_str if c.isalnum() or c in ' _-.,') / len(decoded_str)
                if alnum_ratio > ALNUM_RATIO_THRESHOLD:
                    decoded = decoded.replace(matched, decoded_str)
                    continue
        except Exception:
            pass

        # Try Ascii85 (Adobe variant) with <~ ~> delimiters stripped
        try:
            clean = matched.strip()
            if clean.startswith('<~'):
                clean = clean[2:]
            if clean.endswith('~>'):
                clean = clean[:-2]
            decoded_bytes = base64.a85decode(clean.encode())
            decoded_str = decoded_bytes.decode('utf-8', errors='ignore')
            if decoded_str and decoded_str.isprintable() and len(decoded_str) >= 4:
                alnum_ratio = sum(1 for c in decoded_str if c.isalnum() or c in ' _-.,') / len(decoded_str)
                if alnum_ratio > ALNUM_RATIO_THRESHOLD:
                    decoded = decoded.replace(matched, decoded_str)
        except Exception:
            pass

    return decoded


def decode_hex(text: str) -> str:
    """Attempt to decode hex encoded strings, trying multiple character encodings."""
    decoded = text
    hex_pattern = rf"(?<![0-9a-fA-F])([0-9a-fA-F]{{{MIN_HEX_LENGTH},}})(?![0-9a-fA-F])"
    for match in re.finditer(hex_pattern, text):
        hex_str = match.group(1)
        if len(hex_str) % 2 != 0:
            continue
        try:
            decoded_bytes = bytes.fromhex(hex_str)
            decoded_str = None
            decoded_is_ascii = False

            # Check if all bytes are printable ASCII (0x20-0x7E)
            # This is likely ASCII text (possibly base64), use UTF-8 directly
            if all(0x20 <= b <= 0x7E for b in decoded_bytes):
                try:
                    decoded_str = decoded_bytes.decode('utf-8')
                    decoded = decoded.replace(match.group(), decoded_str)
                    continue
                except UnicodeDecodeError:
                    pass

            # Try multiple encodings in order of likelihood
            for encoding in ['utf-8', 'utf-16-le', 'utf-16-be', 'utf-32-le', 'utf-32-be', 'latin-1']:
                try:
                    candidate = decoded_bytes.decode(encoding, errors='strict')
                    # Validate it's printable and reasonable
                    if candidate and candidate.isprintable() and len(candidate) >= 2:
                        candidate_is_ascii = all(ord(c) < 128 for c in candidate)

                        # Selection criteria (in order of priority):
                        # 1. First valid decoding
                        # 2. Shorter decoding
                        # 3. ASCII over non-ASCII at same length
                        if decoded_str is None:
                            decoded_str = candidate
                            decoded_is_ascii = candidate_is_ascii
                        elif len(candidate) < len(decoded_str):
                            decoded_str = candidate
                            decoded_is_ascii = candidate_is_ascii
                        elif len(candidate) == len(decoded_str) and candidate_is_ascii and not decoded_is_ascii:
                            # Same length but candidate is ASCII - prefer it
                            decoded_str = candidate
                            decoded_is_ascii = candidate_is_ascii
                except (UnicodeDecodeError, UnicodeError):
                    continue

            if decoded_str:
                decoded = decoded.replace(match.group(), decoded_str)
        except Exception:
            pass
    return decoded


# =============================================================================
# Text Encodings
# =============================================================================

def decode_unicode_escapes(text: str) -> str:
    """Decode Unicode escape sequences like \\u0041."""
    try:
        # Handle \\uXXXX sequences
        unicode_pattern = r"\\u([0-9a-fA-F]{4})"
        def replace_unicode(m):
            try:
                return chr(int(m.group(1), 16))
            except Exception:
                return m.group(0)
        return re.sub(unicode_pattern, replace_unicode, text)
    except Exception:
        return text


def decode_quoted_printable(text: str) -> str:
    """Attempt to decode Quoted-Printable encoded strings."""
    import quopri
    decoded = text
    # Look for =XX patterns (at least 3 consecutive)
    qp_pattern = r"(?:=[0-9A-Fa-f]{2}){3,}"
    for match in re.finditer(qp_pattern, text):
        try:
            decoded_bytes = quopri.decodestring(match.group().encode())
            decoded_str = decoded_bytes.decode('utf-8', errors='ignore')
            if decoded_str and len(decoded_str) >= 2:
                decoded = decoded.replace(match.group(), decoded_str)
        except Exception:
            pass
    return decoded


def decode_utf7(text: str) -> str:
    """Attempt to decode UTF-7 encoded strings."""
    # UTF-7 uses +XXXX- sequences for non-ASCII
    # Common pattern: +AF8- = underscore, +ACI- = quote
    if '+' not in text or '-' not in text:
        return text

    try:
        # Try decoding the entire text as UTF-7
        decoded = text.encode('utf-8').decode('utf-7')
        if decoded != text and decoded.isprintable():
            return decoded
    except (UnicodeDecodeError, UnicodeError):
        pass

    # Try decoding segments that look like UTF-7
    utf7_pattern = r'\+[A-Za-z0-9+/]+-'

    def decode_match(m):
        try:
            segment = m.group(0)
            decoded = segment.encode('utf-8').decode('utf-7')
            return decoded
        except Exception:
            return m.group(0)

    try:
        result = re.sub(utf7_pattern, decode_match, text)
        return result
    except Exception:
        return text


def decode_punycode(text: str) -> str:
    """
    Decode Punycode/IDN encoded strings.

    Punycode is used for Internationalized Domain Names (IDN) and encodes
    Unicode strings using only ASCII characters. Format: xn--<encoded>

    Attackers may use Punycode to obfuscate schema keywords by encoding
    them with Unicode characters that get Punycode-encoded.

    Example: xn--brghtness-x4a could decode to brightness (with accent)
    which then normalizes to brightness.

    Args:
        text: Input text potentially containing Punycode strings

    Returns:
        Text with Punycode strings decoded
    """
    decoded = text

    # Punycode pattern: xn-- followed by ASCII alphanumerics and hyphens
    # The encoded part uses a-z, 0-9, and hyphens
    punycode_pattern = r'\bxn--([a-z0-9-]+)\b'

    for match in re.finditer(punycode_pattern, text, re.IGNORECASE):
        full_match = match.group(0)

        try:
            # Decode the Punycode
            # The full ACE (ASCII Compatible Encoding) label is the match
            decoded_str = full_match.encode('ascii').decode('idna')

            # Validate the decoded string
            if decoded_str and (decoded_str.isprintable() or decoded_str.replace('_', '').isalnum()):
                decoded = decoded.replace(full_match, decoded_str)
        except (UnicodeError, UnicodeDecodeError):
            # Try manual punycode decoding as fallback
            try:
                # Remove xn-- prefix and decode
                puny_part = match.group(1)
                decoded_str = puny_part.encode('ascii').decode('punycode')

                if decoded_str and decoded_str.isprintable():
                    decoded = decoded.replace(full_match, decoded_str)
            except Exception:
                pass
        except Exception:
            pass

    # Also look for raw punycode without xn-- prefix (less common but possible)
    # These would be strings that look like they could be punycode encoded
    # Pattern: letters followed by delimiter and base36 digits
    raw_puny_pattern = r'\b([a-z]+-[a-z0-9]+)\b'

    for match in re.finditer(raw_puny_pattern, text, re.IGNORECASE):
        candidate = match.group(1)

        # Skip if already looks like a schema keyword
        if any(kw in candidate.lower() for kw in SCHEMA_KEYWORDS_CORE):
            continue

        try:
            decoded_str = candidate.encode('ascii').decode('punycode')

            # Only replace if decoding reveals schema keywords
            if any(kw in decoded_str.lower() for kw in SCHEMA_KEYWORDS_CORE):
                decoded = decoded.replace(candidate, decoded_str)
        except Exception:
            pass

    return decoded


# =============================================================================
# Ciphers
# =============================================================================

def decode_rot13(text: str) -> str:
    """Decode ROT13 unconditionally - semantic matching will detect leaks."""
    try:
        return codecs_decode(text, "rot_13")
    except Exception:
        return text


def decode_caesar(text: str) -> str:
    """Try Caesar cipher brute force - check all shifts for schema keywords.

    Brute-forces shifts 1-12 and 14-25 (skip 13 since ROT13 is handled separately).
    Returns decoded text if any shift reveals schema keywords, otherwise original text.
    """
    try:
        # Try all shifts except 13 (handled by ROT13)
        for shift in list(range(1, 13)) + list(range(14, 26)):
            decoded_chars = []
            for char in text:
                if char.isalpha():
                    # Determine base (uppercase or lowercase)
                    base = ord('A') if char.isupper() else ord('a')
                    # Shift backward (decode) while preserving case
                    shifted = (ord(char) - base - shift) % 26
                    decoded_chars.append(chr(base + shifted))
                else:
                    # Non-alphabetic characters pass through unchanged
                    decoded_chars.append(char)

            decoded_text = ''.join(decoded_chars)

            # Check if this shift reveals any schema keywords
            for keyword in SCHEMA_KEYWORDS_LIST:
                if keyword.lower() in decoded_text.lower():
                    return decoded_text

        return text
    except Exception:
        return text


def decode_atbash(text: str) -> str:
    """Try Atbash cipher decoding - check if decoded text contains schema keywords.

    Atbash is a simple substitution cipher where a=z, b=y, c=x, etc.
    (the alphabet is reversed).

    Uses targeted replacement: finds Atbash-encoded keywords and replaces
    only those specific occurrences, leaving other text unchanged. This
    prevents false positives from the base64 decoder corrupting Atbash-encoded
    text that happens to be valid base64.
    """
    try:
        # If input already contains schema keywords, don't decode
        # (prevents re-encoding already-decoded text)
        text_lower = text.lower()
        for keyword in SCHEMA_KEYWORDS_LIST:
            if keyword.lower() in text_lower:
                return text

        # Helper function to apply Atbash to a single string
        def atbash_transform(s: str) -> str:
            result = []
            for char in s:
                if char.isalpha():
                    if char.isupper():
                        result.append(chr(ord('Z') - (ord(char) - ord('A'))))
                    else:
                        result.append(chr(ord('z') - (ord(char) - ord('a'))))
                else:
                    result.append(char)
            return ''.join(result)

        # Pre-compute Atbash-encoded versions of keywords
        encoded_keywords = {atbash_transform(kw): kw for kw in SCHEMA_KEYWORDS_LIST}

        # Look for Atbash-encoded keywords in the text (case-insensitive)
        result = text
        for encoded, decoded in encoded_keywords.items():
            # Case-insensitive replacement
            pattern = re.compile(re.escape(encoded), re.IGNORECASE)
            if pattern.search(result):
                # Replace with properly-cased decoded version
                def replacement(m):
                    matched = m.group(0)
                    # Preserve the case pattern of the original
                    if matched.isupper():
                        return decoded.upper()
                    elif matched[0].isupper():
                        return decoded.capitalize()
                    return decoded
                result = pattern.sub(replacement, result)

        # If any replacements were made, return the result
        if result != text:
            return result

        return text
    except Exception:
        return text


def decode_vigenere(text: str) -> str:
    """Try Vigenere cipher decoding with common short keys.

    Vigenere is a polyalphabetic substitution cipher where each letter
    in the key shifts the corresponding plaintext letter. Since full
    cryptanalysis is complex, we use a targeted approach:
    1. Try a limited set of common short keys (1-4 chars)
    2. For each key, decrypt the text
    3. Check if decrypted text contains schema keywords

    Args:
        text: The text to attempt Vigenere decryption on.

    Returns:
        Decrypted text if a key reveals schema keywords, otherwise original text.
    """
    # Common short keys that might be used for obfuscation
    common_keys = [
        'key', 'pass', 'code', 'test', 'hide', 'safe', 'lock', 'abcd',
        # Additional common weak keys
        'secret', 'password', 'cipher', 'encrypt', 'decode', 'hidden',
        'admin', 'user', 'guest', 'temp', 'data', 'info', 'file',
        'abc', 'xyz', 'aaa', 'zzz', 'qwerty', 'asdf', 'zxcv',
    ]

    def vigenere_decrypt(ciphertext: str, key: str) -> str:
        """Decrypt ciphertext using Vigenere cipher with given key."""
        result = []
        key_index = 0
        for char in ciphertext:
            if char.isalpha():
                shift = ord(key[key_index % len(key)].lower()) - ord('a')
                if char.isupper():
                    decrypted = chr((ord(char) - ord('A') - shift) % 26 + ord('A'))
                else:
                    decrypted = chr((ord(char) - ord('a') - shift) % 26 + ord('a'))
                result.append(decrypted)
                key_index += 1
            else:
                result.append(char)
        return ''.join(result)

    # Try each common key
    for key in common_keys:
        try:
            decrypted = vigenere_decrypt(text, key)
            # Check if decrypted text contains any schema keywords
            decrypted_lower = decrypted.lower()
            for keyword in SCHEMA_KEYWORDS_CORE:
                if keyword in decrypted_lower:
                    return decrypted
        except Exception:
            # If decryption fails for any reason, continue to next key
            continue

    return text


def decode_playfair(text: str) -> str:
    """
    Try Playfair cipher decryption with common keys.

    Playfair is a digraph substitution cipher using a 5x5 grid. While
    fully cracking it requires cryptanalysis, we try common keys that
    might be used for obfuscation.

    Args:
        text: Input text potentially containing Playfair-encrypted keywords

    Returns:
        Text with Playfair-decrypted content if schema keywords found
    """
    try:
        # Common keys that might be used
        common_keys = [
            'KEY', 'SECRET', 'CIPHER', 'HIDE', 'CODE', 'PASSWORD',
            # Additional common keys
            'ENCRYPT', 'DECODE', 'HIDDEN', 'SECURE', 'PRIVATE', 'ADMIN',
            'PLAYFAIR', 'MATRIX', 'KEYWORD', 'CRYPTO', 'PUZZLE', 'LOCK',
            'SMART', 'HOME', 'LIGHT', 'SCHEMA',
        ]

        def create_playfair_grid(key: str) -> list[list[str]]:
            """Create 5x5 Playfair grid from key."""
            key = key.upper().replace('J', 'I')
            alphabet = 'ABCDEFGHIKLMNOPQRSTUVWXYZ'  # No J
            seen = set()
            grid_chars = []

            for char in key + alphabet:
                if char not in seen and char in alphabet:
                    grid_chars.append(char)
                    seen.add(char)

            return [grid_chars[i:i+5] for i in range(0, 25, 5)]

        def find_position(grid: list[list[str]], char: str) -> tuple[int, int]:
            """Find character position in grid."""
            char = char.upper()
            if char == 'J':
                char = 'I'
            for i, row in enumerate(grid):
                if char in row:
                    return (i, row.index(char))
            return (-1, -1)

        def decrypt_pair(grid: list[list[str]], c1: str, c2: str) -> str:
            """Decrypt a Playfair character pair."""
            r1, c1_col = find_position(grid, c1)
            r2, c2_col = find_position(grid, c2)

            if r1 == -1 or r2 == -1:
                return c1 + c2

            if r1 == r2:  # Same row
                return grid[r1][(c1_col - 1) % 5] + grid[r2][(c2_col - 1) % 5]
            elif c1_col == c2_col:  # Same column
                return grid[(r1 - 1) % 5][c1_col] + grid[(r2 - 1) % 5][c2_col]
            else:  # Rectangle
                return grid[r1][c2_col] + grid[r2][c1_col]

        decoded = text

        # Look for potential Playfair-encrypted text (even-length alpha strings)
        pattern = r'\b([A-Za-z]{8,})\b'

        for match in re.finditer(pattern, text):
            ciphertext = match.group(1).upper()

            # Must be even length for Playfair
            if len(ciphertext) % 2 != 0:
                continue

            for key in common_keys:
                grid = create_playfair_grid(key)

                # Decrypt pairs
                plaintext = ''
                for i in range(0, len(ciphertext), 2):
                    plaintext += decrypt_pair(grid, ciphertext[i], ciphertext[i+1])

                # Remove padding X's
                plaintext = plaintext.replace('X', '').lower()

                # Check if decrypted text contains schema keywords
                if any(kw in plaintext for kw in SCHEMA_KEYWORDS_NO_UNDERSCORE):
                    decoded = decoded.replace(match.group(1), plaintext)
                    break

        return decoded
    except Exception:
        return text


def decode_xor(text: str) -> str:
    """
    Try XOR decryption with common single-byte keys.

    XOR encryption is a simple cipher where each byte is XOR'd with a key byte.
    Attackers may use this to obfuscate schema keywords. We try common keys
    and check if the result contains schema keywords.

    Only processes hex-encoded strings (likely XOR'd data) to avoid noise.

    Args:
        text: Input text potentially containing hex-encoded XOR'd data

    Returns:
        Text with XOR'd sections decrypted if schema keywords found
    """
    # Common XOR keys: null, space, common letters, full byte values
    common_keys = [
        0x00, 0xFF, 0x20,  # Null, all-ones, space
        0x41, 0x42, 0x43,  # A, B, C
        0x61, 0x62, 0x63,  # a, b, c
        0x31, 0x32, 0x33,  # 1, 2, 3
        0xAA, 0x55,        # Alternating bit patterns
        0x0F, 0xF0,        # Nibble patterns
        # Additional common XOR keys
        0x13, 0x37, 0x42, 0x69, 0x7F, 0x80, 0x90,
        0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE,  # "dead beef cafe"
        0x01, 0x02, 0x04, 0x08, 0x10,  # Powers of 2
    ]

    decoded = text

    # Look for hex strings that could be XOR'd data (even length, hex chars)
    # Minimum 12 hex chars (6 bytes) to match shortest keywords like "enum"
    hex_pattern = r'(?<![0-9a-fA-F])([0-9a-fA-F]{12,})(?![0-9a-fA-F])'

    for match in re.finditer(hex_pattern, text):
        hex_str = match.group(1)

        # Must be even length for valid hex
        if len(hex_str) % 2 != 0:
            continue

        try:
            encrypted_bytes = bytes.fromhex(hex_str)
        except ValueError:
            continue

        # Try each common key
        for key in common_keys:
            # XOR decrypt with single-byte key
            decrypted_bytes = bytes(b ^ key for b in encrypted_bytes)

            # Check if result contains any schema keyword
            for keyword in SCHEMA_KEYWORDS_BYTES:
                if keyword in decrypted_bytes.lower():
                    try:
                        # Verify it decodes to valid text
                        decrypted_str = decrypted_bytes.decode('utf-8', errors='strict')
                        if decrypted_str.isprintable() or all(c.isalnum() or c in '_- ' for c in decrypted_str):
                            decoded = decoded.replace(hex_str, decrypted_str)
                            break
                    except UnicodeDecodeError:
                        # Try latin-1 as fallback
                        try:
                            decrypted_str = decrypted_bytes.decode('latin-1')
                            if all(c.isprintable() or c.isspace() for c in decrypted_str):
                                decoded = decoded.replace(hex_str, decrypted_str)
                                break
                        except Exception:
                            pass
            else:
                continue
            break  # Found a valid decryption, move to next match

    return decoded


def decode_transposition(text: str) -> str:
    """
    Try Rail Fence and Columnar transposition cipher decryption.

    These are transposition ciphers that rearrange characters without
    substitution. We try common configurations and check for keywords.

    Args:
        text: Input text potentially containing transposed keywords

    Returns:
        Text with transposed content decoded if schema keywords found
    """
    try:
        def rail_fence_decode(ciphertext: str, rails: int) -> str:
            """Decode rail fence cipher with given number of rails."""
            if rails < 2 or rails >= len(ciphertext):
                return ciphertext

            # Calculate the pattern
            n = len(ciphertext)
            fence = [['' for _ in range(n)] for _ in range(rails)]

            # Mark positions
            rail = 0
            direction = 1
            for i in range(n):
                fence[rail][i] = '*'
                rail += direction
                if rail == 0 or rail == rails - 1:
                    direction *= -1

            # Fill in ciphertext
            idx = 0
            for r in range(rails):
                for c in range(n):
                    if fence[r][c] == '*' and idx < len(ciphertext):
                        fence[r][c] = ciphertext[idx]
                        idx += 1

            # Read off in zigzag pattern
            result = []
            rail = 0
            direction = 1
            for i in range(n):
                result.append(fence[rail][i])
                rail += direction
                if rail == 0 or rail == rails - 1:
                    direction *= -1

            return ''.join(result)

        decoded = text

        # Look for potential transposed text (alpha strings)
        pattern = r'\b([A-Za-z_]{8,})\b'

        for match in re.finditer(pattern, text):
            ciphertext = match.group(1)

            # Try rail fence with 2-5 rails
            for rails in range(2, 6):
                plaintext = rail_fence_decode(ciphertext, rails)

                if any(kw in plaintext.lower() for kw in SCHEMA_KEYWORDS_CORE):
                    decoded = decoded.replace(match.group(1), plaintext)
                    break

        return decoded
    except Exception:
        return text


# =============================================================================
# Exotic Encodings
# =============================================================================

def decode_morse(text: str) -> str:
    """Attempt to decode Morse code encoded strings."""
    # Morse code mapping (ITU standard + underscore)
    MORSE_TO_CHAR = {
        '.-': 'a', '-...': 'b', '-.-.': 'c', '-..': 'd', '.': 'e',
        '..-.': 'f', '--.': 'g', '....': 'h', '..': 'i', '.---': 'j',
        '-.-': 'k', '.-..': 'l', '--': 'm', '-.': 'n', '---': 'o',
        '.--.': 'p', '--.-': 'q', '.-.': 'r', '...': 's', '-': 't',
        '..-': 'u', '...-': 'v', '.--': 'w', '-..-': 'x', '-.--': 'y',
        '--..': 'z', '-----': '0', '.----': '1', '..---': '2',
        '...--': '3', '....-': '4', '.....': '5', '-....': '6',
        '--...': '7', '---..': '8', '----.': '9', '..--.-': '_',
        '/': ' '
    }

    decoded = text

    # Pattern: sequence of morse code characters (dots, dashes) separated by spaces
    # Must have at least 3 morse "words" to reduce false positives
    # Morse pattern: groups of .- separated by spaces, optionally with / for word breaks
    morse_pattern = r'(?:^|[\s:])([.\-]+(?:\s+[.\-/]+){2,})(?:[\s,.]|$)'

    for match in re.finditer(morse_pattern, text):
        morse_str = match.group(1).strip()

        # Validate it looks like morse (only contains . - space /)
        if not all(c in '.-/ ' for c in morse_str):
            continue

        # Split by word separator (/) first, then by space for letters
        try:
            result = []
            words = morse_str.split(' / ') if ' / ' in morse_str else morse_str.split('/')

            for word in words:
                word = word.strip()
                if not word:
                    continue

                # Split word into individual letter codes
                codes = word.split()
                word_chars = []

                for code in codes:
                    code = code.strip()
                    if code in MORSE_TO_CHAR:
                        word_chars.append(MORSE_TO_CHAR[code])
                    elif code:
                        # Unknown code - likely not morse
                        word_chars = []
                        break

                if word_chars:
                    result.append(''.join(word_chars))

            if result:
                decoded_str = ' '.join(result)
                # Only accept if decoded string is reasonable (letters/numbers/underscore)
                if decoded_str and len(decoded_str) >= 3 and decoded_str.replace(' ', '').replace('_', '').isalnum():
                    decoded = decoded.replace(match.group(1), decoded_str)
        except Exception:
            pass

    return decoded


def decode_binary(text: str) -> str:
    """Attempt to decode binary text (space-separated 8-bit binary) encoded strings."""
    decoded = text

    # Pattern: groups of exactly 8 binary digits separated by spaces
    # Must have at least 3 bytes to reduce false positives
    binary_pattern = r'(?:^|[\s:])([01]{8}(?:\s+[01]{8}){2,})(?:[\s,.]|$)'

    for match in re.finditer(binary_pattern, text):
        binary_str = match.group(1).strip()

        try:
            # Split into individual bytes
            bytes_list = binary_str.split()

            # Validate all are exactly 8 bits
            if not all(len(b) == 8 and all(c in '01' for c in b) for b in bytes_list):
                continue

            # Convert to characters
            chars = []
            for byte_str in bytes_list:
                char_code = int(byte_str, 2)
                # Only accept printable ASCII (32-126) or common whitespace
                if 32 <= char_code <= 126 or char_code in (9, 10, 13):
                    chars.append(chr(char_code))
                else:
                    # Non-printable - probably not text
                    chars = []
                    break

            if chars and len(chars) >= 3:
                decoded_str = ''.join(chars)
                decoded = decoded.replace(match.group(1), decoded_str)
        except Exception:
            pass

    return decoded


def decode_decompress(text: str, max_decompress_depth: int = 5) -> str:
    """
    Try to decompress Base64-encoded compressed data (gzip, bzip2, lzma).

    Handles nested compression by iterating decompression until no more
    compression is detected or max_decompress_depth is reached.

    Attackers may compress and then Base64-encode schema data to bypass
    detection. This method finds potential Base64 strings, decodes them,
    and attempts decompression with multiple algorithms iteratively.

    Args:
        text: Input text potentially containing compressed data
        max_decompress_depth: Maximum nesting levels to decompress (default 5)

    Returns:
        Text with compressed sections decompressed
    """
    decoded = text
    # Match Base64 strings that could contain compressed data
    # Compressed data is typically longer, so use a higher minimum
    base64_pattern = r"[A-Za-z0-9+/]{20,}={0,2}"

    for match in re.finditer(base64_pattern, text):
        matched = match.group()
        try:
            # First, decode the Base64
            raw_bytes = base64.b64decode(matched)
        except Exception:
            continue

        # D-22: Iteratively decompress until no more compression or depth limit
        decompressed_bytes = raw_bytes
        decompression_count = 0

        while decompression_count < max_decompress_depth:
            made_progress = False

            # Try each decompression method
            decompressors = [
                ("gzip", gzip.decompress),
                ("bzip2", bz2.decompress),
                ("lzma", lzma.decompress),
            ]

            for name, decompress_func in decompressors:
                try:
                    new_bytes = decompress_func(decompressed_bytes)
                    # Successful decompression
                    decompressed_bytes = new_bytes
                    decompression_count += 1
                    made_progress = True
                    break  # Try decompressing again from the start
                except Exception:
                    # This decompressor didn't work, try the next one
                    continue

            if not made_progress:
                # No decompressor worked, we're done
                break

        # Try to decode the final result as UTF-8
        try:
            decompressed_str = decompressed_bytes.decode("utf-8", errors="strict")
            # Validate it looks like text (printable with possible whitespace)
            if decompressed_str and all(
                c.isprintable() or c.isspace() for c in decompressed_str
            ):
                decoded = decoded.replace(matched, decompressed_str)
        except UnicodeDecodeError:
            # Not valid UTF-8 text, skip this match
            pass

    return decoded


def decode_yenc(text: str) -> str:
    """
    Attempt to decode yEnc encoded strings.

    yEnc is a binary-to-text encoding used primarily in Usenet. It encodes
    each byte by adding 42 (mod 256) and uses escape sequences for special
    characters.

    Format:
    - Header: =ybegin line=128 size=XXX name=filename
    - Data: encoded bytes (each byte = original + 42, mod 256)
    - Footer: =yend size=XXX

    Special escape sequences:
    - '=' followed by a character means: (char - 64 - 42) % 256

    Returns the text with any yEnc blocks decoded if the result is printable.
    """
    decoded = text

    # Pattern to find yEnc blocks: =ybegin ... data ... =yend
    # Use DOTALL to match across newlines
    yenc_pattern = r'=ybegin[^\n]{0,1000}\n(.*?)=yend[^\n]{0,1000}'

    for match in re.finditer(yenc_pattern, text, re.DOTALL | re.IGNORECASE):
        try:
            encoded_data = match.group(1)

            # Remove any line breaks (yEnc uses them for line wrapping)
            encoded_data = encoded_data.replace('\r\n', '').replace('\n', '').replace('\r', '')

            # Decode the yEnc data
            decoded_bytes = []
            i = 0
            while i < len(encoded_data):
                char = encoded_data[i]

                if char == '=' and i + 1 < len(encoded_data):
                    # Escape sequence: next char is (original + 64 + 42) % 256
                    # So original = (char - 64 - 42) % 256 = (char - 106) % 256
                    next_char = encoded_data[i + 1]
                    original_byte = (ord(next_char) - 64 - 42) % 256
                    decoded_bytes.append(original_byte)
                    i += 2
                else:
                    # Normal encoding: original = (encoded - 42) % 256
                    original_byte = (ord(char) - 42) % 256
                    decoded_bytes.append(original_byte)
                    i += 1

            # Convert bytes to string
            decoded_str = bytes(decoded_bytes).decode('utf-8', errors='ignore')

            # Only replace if decoded content is printable text
            if decoded_str and all(c.isprintable() or c.isspace() for c in decoded_str):
                # Replace the entire yEnc block (including header and footer)
                decoded = decoded.replace(match.group(0), decoded_str)

        except Exception:
            # If decoding fails, leave the original text unchanged
            pass

    return decoded


def decode_uuencode(text: str) -> str:
    """
    Attempt to decode UUencoded content embedded in text.

    UUencode is a binary-to-text encoding scheme that was historically used
    for transmitting binary files over text-only channels like email. The
    format consists of:

        begin [mode] [filename]
        <encoded lines>
        `
        end

    Example:
        begin 644 filename
        M;&EG:'1?8V]N=')O;
        `
        end

    Encoded lines start with a length character (space=0, !-M=1-45 bytes),
    followed by the encoded data using characters in the range 32-95
    (space through underscore).

    This method finds UUencoded blocks, decodes them manually (no uu module
    dependency), and replaces the original encoded content with the decoded
    text if it's valid printable content.

    Args:
        text: Input text potentially containing UUencoded blocks

    Returns:
        Text with UUencoded blocks replaced by decoded content,
        or original text if no valid UUencode found or decoding fails
    """
    decoded = text

    # UUencode pattern with bounded quantifiers to prevent ReDoS
    uuencode_pattern = (
        r"begin\s+[0-7]{3}\s+[^\n\r]{1,100}\n"  # begin line with mode and filename
        r"((?:[ -`]{1,62}\n){1,10000})"          # encoded lines (captured)
        r"`?\n?"                                  # optional padding line
        r"end"                                    # end marker
    )

    for match in re.finditer(uuencode_pattern, text, re.MULTILINE):
        uu_block = match.group(0)
        encoded_lines = match.group(1)
        try:
            decoded_bytes = []
            for line in encoded_lines.split('\n'):
                if not line:
                    continue
                # First char encodes the number of bytes in this line
                # (space=0, !-M=1-45)
                length_char = line[0]
                expected_bytes = (ord(length_char) - 32) & 0x3F
                if expected_bytes == 0:
                    continue  # Empty line

                # Decode 4 chars at a time into 3 bytes
                line_data = line[1:]
                i = 0
                byte_count = 0
                while i < len(line_data) and byte_count < expected_bytes:
                    # Get 4 characters (pad with space if needed)
                    chunk = line_data[i:i+4]
                    while len(chunk) < 4:
                        chunk += ' '

                    # Convert each char to 6-bit value: (char - 32) & 0x3F
                    vals = [(ord(c) - 32) & 0x3F for c in chunk]

                    # Combine 4 6-bit values into 3 8-bit bytes
                    b0 = ((vals[0] << 2) | (vals[1] >> 4)) & 0xFF
                    b1 = ((vals[1] << 4) | (vals[2] >> 2)) & 0xFF
                    b2 = ((vals[2] << 6) | vals[3]) & 0xFF

                    # Add bytes up to expected count
                    for b in [b0, b1, b2]:
                        if byte_count < expected_bytes:
                            decoded_bytes.append(b)
                            byte_count += 1

                    i += 4

            # Convert to string
            decoded_str = bytes(decoded_bytes).decode('utf-8', errors='strict')

            # Validate printable content
            if decoded_str and all(c.isprintable() or c.isspace() for c in decoded_str):
                decoded = decoded.replace(uu_block, decoded_str)
        except Exception:
            # Decoding failed - keep original text
            pass

    return decoded


def decode_xxencode(text: str) -> str:
    """
    Attempt to decode xxencode encoded strings.

    xxencode is similar to uuencode but uses a different character set.
    Format:
    - Header: 'begin 644 filename'
    - Character set: '+-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
    - Each line starts with a length character from the character set
    - 4 encoded characters map to 3 decoded bytes (6 bits each)
    - Footer: 'end'

    Returns:
        The text with any xxencoded sections decoded, or the original text
        if no valid xxencoded content is found.
    """
    XXENCODE_CHARS = '+-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'

    decoded = text

    # Look for xxencode blocks: begin header ... end footer
    # Pattern matches 'begin' followed by mode and filename, then content, then 'end'
    xxencode_pattern = r'begin\s+\d+\s+\S+\s*\n([\s\S]{0,100000}?)\nend'

    for match in re.finditer(xxencode_pattern, text, re.IGNORECASE):
        try:
            encoded_block = match.group(1)
            lines = encoded_block.strip().split('\n')

            decoded_bytes = bytearray()

            for line in lines:
                line = line.rstrip()
                if not line:
                    continue

                # First character encodes the line length (number of decoded bytes)
                length_char = line[0]
                if length_char not in XXENCODE_CHARS:
                    continue

                expected_length = XXENCODE_CHARS.index(length_char)

                # If length is 0, this is the terminating line before 'end'
                if expected_length == 0:
                    continue

                # Remaining characters are the encoded data
                encoded_data = line[1:]

                # Process 4 characters at a time to produce 3 bytes
                line_bytes = bytearray()
                i = 0
                while i + 4 <= len(encoded_data) and len(line_bytes) < expected_length:
                    # Get 4 characters
                    chars = encoded_data[i:i+4]

                    # Validate all characters are in the xxencode character set
                    if not all(c in XXENCODE_CHARS for c in chars):
                        break

                    # Convert each character to its 6-bit value
                    vals = [XXENCODE_CHARS.index(c) for c in chars]

                    # Combine 4 x 6-bit values into 3 x 8-bit bytes
                    # vals[0] = bits 0-5 of byte 0
                    # vals[1] = bits 6-7 of byte 0, bits 0-3 of byte 1
                    # vals[2] = bits 4-7 of byte 1, bits 0-1 of byte 2
                    # vals[3] = bits 2-7 of byte 2
                    b0 = ((vals[0] << 2) | (vals[1] >> 4)) & 0xFF
                    b1 = ((vals[1] << 4) | (vals[2] >> 2)) & 0xFF
                    b2 = ((vals[2] << 6) | vals[3]) & 0xFF

                    line_bytes.append(b0)
                    if len(line_bytes) < expected_length:
                        line_bytes.append(b1)
                    if len(line_bytes) < expected_length:
                        line_bytes.append(b2)

                    i += 4

                # Truncate to expected length
                decoded_bytes.extend(line_bytes[:expected_length])

            # Try to decode as UTF-8
            decoded_str = decoded_bytes.decode('utf-8', errors='ignore')

            # Validate decoded content is printable text
            if decoded_str and all(c.isprintable() or c.isspace() for c in decoded_str):
                # Replace the entire xxencode block (including begin/end) with decoded content
                decoded = decoded.replace(match.group(0), decoded_str)

        except Exception:
            # If decoding fails, continue with original text
            pass

    return decoded


def decode_binhex(text: str) -> str:
    """
    Attempt to decode BinHex 4.0 encoded content.

    BinHex 4.0 was a legacy Apple encoding format. It uses a specific
    character set and has distinctive markers. Since the binhex module
    is removed in Python 3.11+, this is a manual implementation.

    BinHex format markers:
    - Starts with "(This file must be converted with BinHex" comment, or
    - Data lines start with ':'
    - Uses 64-character alphabet similar to base64 but different

    BinHex character set: !"#$%&'()*+,-012345689@ABCDEFGHIJKLMNPQRSTUVXYZ[`abcdefhijklmpqr

    Args:
        text: Input text potentially containing BinHex data

    Returns:
        Text with BinHex content decoded if valid
    """
    decoded = text

    # BinHex character set (64 chars)
    BINHEX_CHARS = '!"#$%&\'()*+,-012345689@ABCDEFGHIJKLMNPQRSTUVXYZ[`abcdefhijklmpqr'

    def decode_binhex_char(char: str) -> int:
        """Convert BinHex char to 6-bit value."""
        if char in BINHEX_CHARS:
            return BINHEX_CHARS.index(char)
        return -1

    def decode_binhex_data(data: str) -> bytes:
        """Decode BinHex data section to bytes."""
        result = []
        accumulator = 0
        bits = 0

        for char in data:
            val = decode_binhex_char(char)
            if val < 0:
                continue

            accumulator = (accumulator << 6) | val
            bits += 6

            while bits >= 8:
                bits -= 8
                byte = (accumulator >> bits) & 0xFF
                result.append(byte)

        return bytes(result)

    # Pattern 1: Full BinHex block with header
    binhex_header_pattern = r'\(This file must be converted with BinHex[^)]{0,500}\)\s*:([!-r\s]+):'

    for match in re.finditer(binhex_header_pattern, text, re.IGNORECASE | re.DOTALL):
        try:
            # Extract and clean data (remove whitespace)
            data = match.group(1).replace('\n', '').replace('\r', '').replace(' ', '')

            decoded_bytes = decode_binhex_data(data)
            decoded_str = decoded_bytes.decode('utf-8', errors='ignore')

            # Validate printable content
            if decoded_str and any(c.isalnum() for c in decoded_str):
                # Replace entire BinHex block with decoded content
                decoded = decoded.replace(match.group(0), decoded_str)
        except Exception:
            pass

    # Pattern 2: Just colon-delimited BinHex data (without header)
    binhex_data_pattern = r':([!"#$%&\'()*+,\-012345689@A-Za-z\[\]`\s]{20,}):'

    for match in re.finditer(binhex_data_pattern, text):
        try:
            data = match.group(1).replace('\n', '').replace('\r', '').replace(' ', '')

            # Validate characters are in BinHex set
            if not all(c in BINHEX_CHARS or c.isspace() for c in match.group(1)):
                continue

            decoded_bytes = decode_binhex_data(data)
            decoded_str = decoded_bytes.decode('utf-8', errors='ignore')

            # Only replace if decoded content looks meaningful
            if decoded_str and len(decoded_str) >= 4:
                if all(c.isprintable() or c.isspace() for c in decoded_str):
                    decoded = decoded.replace(match.group(0), decoded_str)
        except Exception:
            pass

    return decoded


def decode_pig_latin(text: str) -> str:
    """
    Detect and decode Pig Latin encoded text that hides schema keywords.

    Pig Latin encoding rules:
    1. Words starting with consonant(s): move consonant(s) to end, add "ay"
       - brightness -> ightnessbray
       - control -> ontrolcay
    2. Words starting with vowel: add "way" or "yay" to end
       - enum -> enumway or enumyay

    Reverse algorithm:
    1. If word ends in "ay", "way", or "yay":
       - Remove the suffix
       - Try different split points to move trailing consonants back to start
       - Check if result matches a schema keyword
    """
    try:
        # Also include component words for compound keywords
        component_words = {
            'light', 'control', 'lock', 'color', 'temp', 'pin', 'override',
            'living', 'room', 'bed', 'kitchen', 'bath', 'front', 'door',
            'back', 'garage', 'enum', 'properties', 'brightness', 'minimum',
            'maximum'
        }

        all_keywords = SCHEMA_KEYWORDS | component_words

        vowels = set('aeiouAEIOU')

        def reverse_pig_latin_word(word: str) -> str | None:
            """
            Attempt to reverse Pig Latin encoding on a single word.
            Returns the decoded word if it matches a keyword, otherwise None.
            """
            word_lower = word.lower()

            # Handle vowel-starting words (end in "way" or "yay")
            if word_lower.endswith('way'):
                candidate = word[:-3]
                if candidate.lower() in all_keywords:
                    return candidate
            elif word_lower.endswith('yay'):
                candidate = word[:-3]
                if candidate.lower() in all_keywords:
                    return candidate

            # Handle consonant-starting words (end in consonant(s) + "ay")
            if word_lower.endswith('ay') and len(word) > 3:
                # Remove "ay" suffix
                base = word[:-2]
                base_lower = base.lower()

                # Try different consonant cluster lengths (1 to 4 consonants)
                for cluster_len in range(1, min(5, len(base))):
                    # Get potential consonant cluster from the end
                    consonant_cluster = base[-cluster_len:]

                    # Verify all characters in cluster are consonants
                    if all(c.lower() not in vowels and c.isalpha() for c in consonant_cluster):
                        # Move consonants back to the start
                        candidate = consonant_cluster + base[:-cluster_len]

                        # Check if decoded word matches a keyword
                        if candidate.lower() in all_keywords:
                            return candidate
                    else:
                        # Hit a vowel, stop trying longer clusters
                        break

            return None

        decoded = text

        # Handle compound words with underscores (e.g., ightlay_ontrolcay)
        # Split by underscore, decode each part, rejoin
        compound_pattern = r'\b([a-zA-Z]+(?:_[a-zA-Z]+)+)\b'
        for match in re.finditer(compound_pattern, text):
            compound = match.group(1)
            parts = compound.split('_')
            decoded_parts = []
            any_decoded = False

            for part in parts:
                decoded_part = reverse_pig_latin_word(part)
                if decoded_part:
                    decoded_parts.append(decoded_part)
                    any_decoded = True
                else:
                    decoded_parts.append(part)

            if any_decoded:
                decoded_compound = '_'.join(decoded_parts)
                decoded = decoded.replace(compound, decoded_compound)

        # Handle single words ending in Pig Latin suffixes
        # Match words that look like Pig Latin (end in "ay", "way", or "yay")
        word_pattern = r'\b([a-zA-Z]+(?:ay|way|yay))\b'
        for match in re.finditer(word_pattern, decoded):
            word = match.group(1)
            decoded_word = reverse_pig_latin_word(word)
            if decoded_word:
                decoded = decoded.replace(word, decoded_word)

        return decoded
    except Exception:
        return text


def decode_braille(text: str) -> str:
    """
    Decode Braille Unicode characters (U+2800-U+28FF) to ASCII text.

    Braille patterns in this Unicode block encode values where each character
    maps directly to its offset from U+2800. For printable ASCII characters
    (0x20-0x7E), this means: chr(ord(braille_char) - 0x2800) gives ASCII.

    Example: (braille characters) -> brightness

    This decoder finds sequences of 3+ consecutive Braille characters and
    replaces them with their decoded ASCII equivalents if all characters
    map to printable ASCII.

    Args:
        text: Input text potentially containing Braille Unicode sequences

    Returns:
        Text with Braille sequences replaced by decoded ASCII, or original
        text if no valid Braille sequences found
    """
    decoded = text

    # Braille Unicode block: U+2800 to U+28FF (256 characters)
    # Pattern matches sequences of 3+ Braille characters
    braille_pattern = r'[\u2800-\u28FF]{3,}'

    for match in re.finditer(braille_pattern, text):
        braille_str = match.group()

        try:
            decoded_chars = []
            valid = True

            for braille_char in braille_str:
                # Calculate ASCII value: offset from U+2800
                ascii_val = ord(braille_char) - 0x2800

                # Only accept printable ASCII (0x20-0x7E)
                if 0x20 <= ascii_val <= 0x7E:
                    decoded_chars.append(chr(ascii_val))
                else:
                    # Non-printable result - this sequence is not ASCII-encoded
                    valid = False
                    break

            if valid and decoded_chars:
                decoded_str = ''.join(decoded_chars)
                decoded = decoded.replace(braille_str, decoded_str)

        except Exception:
            # Handle any unexpected errors gracefully
            pass

    return decoded


def decode_emoji(text: str) -> str:
    """
    Replace emoji characters with their semantic keyword equivalents.

    Detects emoji-based obfuscation where schema keywords are replaced
    with semantically similar emoji. For example: (lightbulb)_control -> light_control

    Args:
        text: Input text potentially containing emoji substitutions

    Returns:
        Text with emoji replaced by semantic keywords
    """
    decoded = text

    # Replace each emoji with its keyword equivalent
    for emoji, keyword in EMOJI_MAP.items():
        if emoji in decoded:
            decoded = decoded.replace(emoji, keyword)

    return decoded


def decode_reverse(text: str) -> str:
    """
    Detect and decode reversed text that hides schema keywords.

    Looks for word-like tokens (alphanumeric sequences with underscores)
    and checks if reversing them produces schema keywords.
    """
    try:
        decoded = text

        # Find word-like tokens (alphanumeric sequences with underscores)
        token_pattern = r'[A-Za-z0-9_]+'

        for match in re.finditer(token_pattern, text):
            token = match.group()

            # Skip very short tokens (unlikely to be meaningful reversed keywords)
            if len(token) < 3:
                continue

            # Reverse the token
            reversed_token = token[::-1]

            # Check if the reversed token matches any schema keyword (case-insensitive)
            for keyword in SCHEMA_KEYWORDS:
                if reversed_token.lower() == keyword.lower():
                    # Replace original with reversed version, preserving case pattern
                    # If keyword has a specific case pattern, use it
                    decoded = decoded.replace(token, reversed_token)
                    break

        return decoded
    except Exception:
        return text


def decode_interleaved(text: str) -> str:
    """
    Detect and decode interleaved character obfuscation.

    Interleaved obfuscation hides text by inserting junk characters between
    real characters. For example: 'bxrxixgxhxtxnxexsxs' -> 'brightness'
    (every other character starting at position 0).

    Detection approach:
    1. Find tokens that look interleaved (alternating pattern with consistent separator)
    2. Try extracting characters at different intervals (every 2nd, 3rd char)
    3. Try both even positions (0, 2, 4...) and odd positions (1, 3, 5...)
    4. If extracted text matches a schema keyword, replace the interleaved pattern

    Common separators: x, -, ., _, space, or any repeated single character.
    """
    try:
        decoded = text

        # Pattern to find potential interleaved tokens
        # Look for sequences of alternating characters (at least 6 chars for 3-char decoded)
        # Match word boundaries to avoid partial matches
        token_pattern = r'\b[A-Za-z0-9_.\-]{6,}\b'

        for match in re.finditer(token_pattern, text):
            token = match.group()

            # Skip if token is already a keyword (no need to decode)
            if token.lower() in [kw.lower() for kw in SCHEMA_KEYWORDS_LIST]:
                continue

            # Try to detect interleaved pattern by checking for consistent separators
            # Check if odd positions all contain the same character (separator)
            if len(token) >= 6:
                # Try interval of 2 (every other character)
                for start_pos in [0, 1]:  # Try both even and odd starting positions
                    # Extract characters at interval positions
                    extracted = token[start_pos::2]

                    # Check if extracted text matches any schema keyword
                    for keyword in SCHEMA_KEYWORDS_LIST:
                        if extracted.lower() == keyword.lower():
                            # Verify the other positions look like separators
                            # (all same char, or all from a common separator set)
                            other_pos = 1 - start_pos  # The other starting position
                            separators = token[other_pos::2]

                            # Check if separators are consistent (all same char or common separators)
                            common_seps = set('x-._0123456789 ')
                            is_consistent_sep = (
                                len(set(separators)) == 1 or  # All same character
                                all(c in common_seps for c in separators)  # All common separators
                            )

                            if is_consistent_sep:
                                # Replace the interleaved token with decoded keyword
                                decoded = decoded.replace(token, extracted, 1)
                                break
                    else:
                        continue
                    break  # Found a match, move to next token

            # Try interval of 3 (every third character) for more complex obfuscation
            if len(token) >= 9:
                for start_pos in [0, 1, 2]:
                    extracted = token[start_pos::3]

                    for keyword in SCHEMA_KEYWORDS_LIST:
                        if extracted.lower() == keyword.lower():
                            # Verify pattern consistency
                            # Other positions should be filler characters
                            other_chars = ''.join(
                                c for i, c in enumerate(token)
                                if i % 3 != start_pos
                            )
                            # Check if filler chars are consistent (repetitive pattern)
                            if len(set(other_chars)) <= 3:  # Limited variety = likely filler
                                decoded = decoded.replace(token, extracted, 1)
                                break
                    else:
                        continue
                    break

        return decoded
    except Exception:
        return text


def decode_nato(text: str) -> str:
    """Attempt to decode NATO phonetic alphabet encoded strings.

    Detects sequences of 3+ NATO phonetic words (case-insensitive) and
    decodes them to their corresponding characters. Words can be separated
    by spaces, hyphens, or other common delimiters.

    Only replaces the sequence if the decoded result contains schema
    keywords, to avoid false positives on normal text containing NATO words.

    Example:
        Input: "bravo romeo india golf hotel tango november echo sierra sierra"
        Output: "brightness"

    Args:
        text: The text to attempt NATO phonetic decoding on.

    Returns:
        Text with NATO phonetic sequences decoded if they reveal schema
        keywords, otherwise the original text.
    """
    decoded = text

    try:
        # Build pattern to match NATO phonetic words
        nato_words = '|'.join(re.escape(word) for word in NATO_PHONETIC_MAP.keys())
        # Match sequences of 3+ NATO words separated by spaces, hyphens, or commas
        # Pattern: word (separator word){2,}
        nato_pattern = rf'\b({nato_words})(?:[\s,\-]+({nato_words})){{2,}}\b'

        # Find all potential NATO sequences
        # Use a simpler approach: split text into words and look for runs of NATO words
        words = re.split(r'[\s,\-]+', text)

        i = 0
        while i < len(words):
            # Look for start of NATO sequence
            sequence_start = i
            nato_sequence = []

            while i < len(words):
                word_lower = words[i].lower().strip('.,;:!?')
                if word_lower in NATO_PHONETIC_MAP:
                    nato_sequence.append(word_lower)
                    i += 1
                else:
                    break

            # Check if we found a sequence of 3+ NATO words
            if len(nato_sequence) >= 3:
                # Decode the sequence
                decoded_chars = [NATO_PHONETIC_MAP[w] for w in nato_sequence]
                decoded_str = ''.join(decoded_chars)

                # Check if decoded string contains any schema keywords
                decoded_lower = decoded_str.lower()
                contains_keyword = any(kw in decoded_lower for kw in SCHEMA_KEYWORDS_LIST)

                if contains_keyword:
                    # Find the original text to replace
                    # Reconstruct the original sequence from the words
                    original_words = words[sequence_start:sequence_start + len(nato_sequence)]
                    # Build a pattern to match this sequence with any delimiters
                    original_pattern = r'[\s,\-]*'.join(re.escape(w) for w in original_words)
                    # Replace in the decoded text
                    decoded = re.sub(original_pattern, decoded_str, decoded, flags=re.IGNORECASE)
            else:
                i += 1

    except Exception:
        # If anything goes wrong, return original text
        pass

    return decoded
