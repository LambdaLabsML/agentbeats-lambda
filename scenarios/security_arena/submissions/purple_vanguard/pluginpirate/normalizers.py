"""
Text Normalization Functions for PluginPirate

This module provides standalone text normalization functions for detecting
obfuscated schema keywords. These functions handle various bypass techniques:

- Unicode normalization and invisible character removal
- Leetspeak character substitution (1337sp34k)
- Homoglyph character normalization (lookalike Unicode)
- Abbreviation expansion
- Synonym expansion to canonical forms
- Euphemism expansion to schema terms
- Foreign language translation to English
- Text number word conversion to digits
"""

import re
import unicodedata

try:
    from .constants import (
        LEETSPEAK_MAP, HOMOGLYPH_MAP, ABBREVIATIONS,
        SYNONYM_MAP, WORD_NUMBERS, EUPHEMISM_MAP, TRANSLATION_MAP
    )
except ImportError:
    from constants import (
        LEETSPEAK_MAP, HOMOGLYPH_MAP, ABBREVIATIONS,
        SYNONYM_MAP, WORD_NUMBERS, EUPHEMISM_MAP, TRANSLATION_MAP
    )


def normalize_text(text: str) -> str:
    """Normalize Unicode and strip invisible characters."""
    # Strip null bytes (prevent injection bypass)
    text = text.replace('\x00', '')
    # Normalize CRLF to LF (prevent line-ending injection bypass)
    text = text.replace('\r\n', '\n').replace('\r', '\n')
    # NFKC normalization (converts lookalikes to ASCII)
    text = unicodedata.normalize("NFKC", text)

    # D-14: Zero-width characters that break pattern matching
    # Zero-width space (U+200B), Zero-width non-joiner (U+200C),
    # Zero-width joiner (U+200D), BOM/ZWNBSP (U+FEFF), Word joiner (U+2060)
    # Already covered in pattern below

    # D-15: Additional invisible Unicode characters
    # These chars are invisible but can break keyword detection:
    # - U+034F: Combining grapheme joiner
    # - U+115F: Hangul choseong filler
    # - U+1160: Hangul jungseong filler
    # - U+3164: Hangul filler
    # - U+FFA0: Halfwidth Hangul filler
    # - U+17B4: Khmer vowel inherent AQ
    # - U+17B5: Khmer vowel inherent AA

    # Combined pattern for all invisible characters
    # Original: [\u200b-\u200f\u2028-\u202f\u2060-\u206f\ufeff\u00ad]
    # Extended with D-14 and D-15 additions
    invisible_pattern = (
        r"["
        r"\u200b-\u200f"   # Zero-width chars (space, non-joiner, joiner, LRM, RLM)
        r"\u2028-\u202f"   # Line/paragraph separators, formatting chars
        r"\u2060-\u206f"   # Word joiner, invisible operators
        r"\ufeff"          # BOM / Zero-width no-break space
        r"\u00ad"          # Soft hyphen
        r"\u034f"          # Combining grapheme joiner
        r"\u115f\u1160"    # Hangul choseong/jungseong fillers
        r"\u3164"          # Hangul filler
        r"\uffa0"          # Halfwidth Hangul filler
        r"\u17b4\u17b5"    # Khmer vowel inherent AQ/AA
        r"\u180e"          # Mongolian vowel separator
        r"]"
    )
    text = re.sub(invisible_pattern, "", text)
    return text


def normalize_leetspeak(text: str) -> str:
    """Normalize leetspeak characters to their alphabetic equivalents.

    Handles both single-character substitutions (0->o, 1->i, 3->e, etc.)
    and multi-character sequences (><->x).

    Example: 'br1gh7n355' -> 'brightness'
    """
    result = []
    i = 0
    while i < len(text):
        # Check for multi-character sequences first (longer matches take priority)
        # Currently only '><' -> 'x' is a multi-char sequence
        if i + 1 < len(text) and text[i:i+2] == '><':
            result.append(LEETSPEAK_MAP['><'])
            i += 2
        elif text[i] in LEETSPEAK_MAP:
            result.append(LEETSPEAK_MAP[text[i]])
            i += 1
        else:
            result.append(text[i])
            i += 1
    return ''.join(result)


def normalize_homoglyphs(text: str) -> str:
    """Normalize homoglyph characters to their ASCII equivalents.

    Handles lookalike characters from various Unicode blocks:
    - Cyrillic (a->a, c->c, e->e, etc.)
    - Greek (alpha->a, beta->b, epsilon->e, etc.)
    - Roman numerals (i->i, v->v, x->x, etc.)
    - Full-width (a->a, b->b, etc.)
    - Small caps (A->a, B->b, etc.)

    Example: 'brightness' (with Cyrillic i) -> 'brightness'
    """
    result = []
    for char in text:
        if char in HOMOGLYPH_MAP:
            result.append(HOMOGLYPH_MAP[char])
        else:
            result.append(char)
    return ''.join(result)


def expand_abbreviations(text: str) -> str:
    """Expand common abbreviations to full words for detection."""
    result = text
    for pattern, replacement in ABBREVIATIONS.items():
        result = re.sub(pattern, replacement, result, flags=re.IGNORECASE)
    return result


def expand_synonyms(text: str) -> str:
    """Expand synonyms to their canonical forms for detection.

    Replaces synonym phrases with their canonical equivalents (e.g.,
    'luminosity' -> 'brightness', 'ceiling' -> 'maximum') to catch
    semantic bypasses where attackers use alternative terminology.

    Uses word boundaries for accurate replacement and processes
    multi-word synonyms first (sorted by length, longest first).
    """
    result = text
    # Sort synonyms by length (longest first) to handle multi-word synonyms first
    sorted_synonyms = sorted(SYNONYM_MAP.keys(), key=len, reverse=True)
    for synonym in sorted_synonyms:
        canonical = SYNONYM_MAP[synonym]
        # Use word boundaries for accurate replacement (case-insensitive)
        pattern = rf"\b{re.escape(synonym)}\b"
        result = re.sub(pattern, canonical, result, flags=re.IGNORECASE)
    return result


def expand_euphemisms(text: str) -> str:
    """Expand euphemistic phrases to their canonical schema terms for detection.

    Replaces euphemistic phrases with canonical equivalents (e.g.,
    'upper limit' -> 'maximum', 'allowed values' -> 'enum') to catch
    semantic bypasses where attackers use alternative terminology to
    describe schema constraints and types.

    Uses case-insensitive matching and processes multi-word phrases
    first (sorted by length, longest first) to avoid partial matches.
    """
    result = text
    # Sort euphemisms by length (longest first) to handle multi-word phrases first
    sorted_euphemisms = sorted(EUPHEMISM_MAP.keys(), key=len, reverse=True)
    for euphemism in sorted_euphemisms:
        canonical = EUPHEMISM_MAP[euphemism]
        # Use case-insensitive matching for euphemistic phrases
        pattern = rf"\b{re.escape(euphemism)}\b"
        result = re.sub(pattern, canonical, result, flags=re.IGNORECASE)
    return result


def expand_translations(text: str) -> str:
    """D-30: Expand foreign language translations to English schema equivalents.

    Detects schema keywords expressed in other languages (French, German,
    Spanish, Italian, Portuguese) and replaces them with canonical English
    terms for detection.

    Uses case-insensitive matching and word boundaries for accuracy.
    Processes multi-word phrases first (sorted by length, longest first).
    """
    result = text
    # Sort by length (longest first) to handle multi-word phrases first
    sorted_translations = sorted(TRANSLATION_MAP.keys(), key=len, reverse=True)
    for foreign_word in sorted_translations:
        english = TRANSLATION_MAP[foreign_word]
        # Use word boundaries for accurate replacement (case-insensitive)
        pattern = rf"\b{re.escape(foreign_word)}\b"
        result = re.sub(pattern, english, result, flags=re.IGNORECASE)
    return result


def convert_text_numbers(text: str) -> str:
    """Convert text number words to digits for detection."""
    result = text
    # Sort by length descending to match longer phrases first
    sorted_words = sorted(WORD_NUMBERS.keys(), key=len, reverse=True)
    for word in sorted_words:
        result = re.sub(rf"\b{re.escape(word)}\b", WORD_NUMBERS[word], result, flags=re.IGNORECASE)
    return result
