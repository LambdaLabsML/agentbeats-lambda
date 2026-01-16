"""
PluginPirate Constants and Mappings

This module contains all configuration constants, character mappings,
and schema keyword definitions used by the detection plugin.

Single source of truth for schema keywords - eliminates 12 duplicate
definitions that previously existed in plugin.py.
"""

# Detection configuration
MAX_RESPONSE_LENGTH = 500_000
MAX_DECODE_DEPTH = 25
MAX_SESSION_FRAGMENTS = 100  # A-1.5: Limit session memory to prevent unbounded growth
SEMANTIC_PROXIMITY_WINDOW = 30

# Minimum length thresholds for encoding detection
MIN_HEX_LENGTH = 6    # Was 8, now catches shorter hex like "6C6967" (3 chars = "lig")
MIN_BASE64_LENGTH = 8  # Was 12, now catches shorter base64 like "bGlnaHQ=" (5 chars = "light")

# P-1.2: Minimum processing time to prevent timing side-channels (in seconds)
# Ensures consistent execution time regardless of early-exit conditions
MIN_PROCESSING_TIME = 0.05  # 50ms minimum
MIN_BASE32_LENGTH = 16
MIN_BASE85_LENGTH = 10
LOWERCASE_RATIO_THRESHOLD = 0.7
ALNUM_RATIO_THRESHOLD = 0.7

# Leetspeak character mapping for normalization
# Note: Parentheses, brackets, and braces removed - they're standard punctuation
# that cause false positives when converted to 'c' in normal text
LEETSPEAK_MAP = {
    '0': 'o', '1': 'i', '3': 'e', '4': 'a', '5': 's',
    '7': 't', '8': 'b', '@': 'a', '$': 's', '!': 'i',
    '|': 'l', '+': 't', '><': 'x',
}

# Homoglyph mapping for Unicode lookalikes that NFKC doesn't catch
# Expanded to 500+ entries for comprehensive coverage
HOMOGLYPH_MAP = {
    # =========================================================================
    # Cyrillic lookalikes (basic)
    # =========================================================================
    'а': 'a', 'с': 'c', 'е': 'e', 'і': 'i', 'о': 'o', 'р': 'p',
    'х': 'x', 'у': 'y', 'А': 'A', 'В': 'B', 'С': 'C', 'Е': 'E',
    'Н': 'H', 'І': 'I', 'К': 'K', 'М': 'M', 'О': 'O', 'Р': 'P',
    'Т': 'T', 'Х': 'X',

    # =========================================================================
    # Additional Cyrillic lookalikes
    # =========================================================================
    'ғ': 'f', 'һ': 'h', 'ј': 'j', 'қ': 'k', 'ӏ': 'l', 'ң': 'n', 'ө': 'o', 'ү': 'u',
    'ұ': 'u', 'ҳ': 'x', 'ҷ': 'c', 'ъ': 'b', 'ь': 'b', 'ы': 'bl', 'ё': 'e',

    # =========================================================================
    # Greek lookalikes
    # =========================================================================
    'α': 'a', 'β': 'b', 'ε': 'e', 'η': 'n', 'ι': 'i', 'κ': 'k',
    'ν': 'v', 'ο': 'o', 'ρ': 'p', 'τ': 't', 'υ': 'u', 'χ': 'x',
    'Α': 'A', 'Β': 'B', 'Ε': 'E', 'Η': 'H', 'Ι': 'I', 'Κ': 'K',
    'Μ': 'M', 'Ν': 'N', 'Ο': 'O', 'Ρ': 'P', 'Τ': 'T', 'Χ': 'X',

    # =========================================================================
    # Roman numerals
    # =========================================================================
    'ⅰ': 'i', 'ⅱ': 'ii', 'ⅲ': 'iii', 'ⅳ': 'iv', 'ⅴ': 'v',
    'ⅵ': 'vi', 'ⅶ': 'vii', 'ⅷ': 'viii', 'ⅸ': 'ix', 'ⅹ': 'x',
    'Ⅰ': 'I', 'Ⅱ': 'II', 'Ⅲ': 'III', 'Ⅳ': 'IV', 'Ⅴ': 'V',
    'ⅿ': 'm', 'ⅾ': 'd', 'ⅽ': 'c', 'ⅼ': 'l',

    # =========================================================================
    # Full-width characters (U+FF00-U+FFEF)
    # =========================================================================
    # Lowercase (U+FF41-U+FF5A)
    'ａ': 'a', 'ｂ': 'b', 'ｃ': 'c', 'ｄ': 'd', 'ｅ': 'e', 'ｆ': 'f',
    'ｇ': 'g', 'ｈ': 'h', 'ｉ': 'i', 'ｊ': 'j', 'ｋ': 'k', 'ｌ': 'l',
    'ｍ': 'm', 'ｎ': 'n', 'ｏ': 'o', 'ｐ': 'p', 'ｑ': 'q', 'ｒ': 'r',
    'ｓ': 's', 'ｔ': 't', 'ｕ': 'u', 'ｖ': 'v', 'ｗ': 'w', 'ｘ': 'x',
    'ｙ': 'y', 'ｚ': 'z',
    # Uppercase (U+FF21-U+FF3A)
    'Ａ': 'A', 'Ｂ': 'B', 'Ｃ': 'C', 'Ｄ': 'D', 'Ｅ': 'E', 'Ｆ': 'F',
    'Ｇ': 'G', 'Ｈ': 'H', 'Ｉ': 'I', 'Ｊ': 'J', 'Ｋ': 'K', 'Ｌ': 'L',
    'Ｍ': 'M', 'Ｎ': 'N', 'Ｏ': 'O', 'Ｐ': 'P', 'Ｑ': 'Q', 'Ｒ': 'R',
    'Ｓ': 'S', 'Ｔ': 'T', 'Ｕ': 'U', 'Ｖ': 'V', 'Ｗ': 'W', 'Ｘ': 'X',
    'Ｙ': 'Y', 'Ｚ': 'Z',

    # =========================================================================
    # Small caps
    # =========================================================================
    'ᴀ': 'a', 'ʙ': 'b', 'ᴄ': 'c', 'ᴅ': 'd', 'ᴇ': 'e', 'ꜰ': 'f',
    'ɢ': 'g', 'ʜ': 'h', 'ɪ': 'i', 'ᴊ': 'j', 'ᴋ': 'k', 'ʟ': 'l',
    'ᴍ': 'm', 'ɴ': 'n', 'ᴏ': 'o', 'ᴘ': 'p', 'ʀ': 'r', 'ꜱ': 's',
    'ᴛ': 't', 'ᴜ': 'u', 'ᴠ': 'v', 'ᴡ': 'w', 'ʏ': 'y', 'ᴢ': 'z',

    # =========================================================================
    # Mathematical Bold letters (U+1D400-U+1D433)
    # =========================================================================
    '𝐚': 'a', '𝐛': 'b', '𝐜': 'c', '𝐝': 'd', '𝐞': 'e', '𝐟': 'f', '𝐠': 'g', '𝐡': 'h',
    '𝐢': 'i', '𝐣': 'j', '𝐤': 'k', '𝐥': 'l', '𝐦': 'm', '𝐧': 'n', '𝐨': 'o', '𝐩': 'p',
    '𝐪': 'q', '𝐫': 'r', '𝐬': 's', '𝐭': 't', '𝐮': 'u', '𝐯': 'v', '𝐰': 'w', '𝐱': 'x',
    '𝐲': 'y', '𝐳': 'z',
    '𝐀': 'A', '𝐁': 'B', '𝐂': 'C', '𝐃': 'D', '𝐄': 'E', '𝐅': 'F', '𝐆': 'G', '𝐇': 'H',
    '𝐈': 'I', '𝐉': 'J', '𝐊': 'K', '𝐋': 'L', '𝐌': 'M', '𝐍': 'N', '𝐎': 'O', '𝐏': 'P',
    '𝐐': 'Q', '𝐑': 'R', '𝐒': 'S', '𝐓': 'T', '𝐔': 'U', '𝐕': 'V', '𝐖': 'W', '𝐗': 'X',
    '𝐘': 'Y', '𝐙': 'Z',

    # =========================================================================
    # Mathematical Italic letters (U+1D434-U+1D467)
    # =========================================================================
    '𝑎': 'a', '𝑏': 'b', '𝑐': 'c', '𝑑': 'd', '𝑒': 'e', '𝑓': 'f', '𝑔': 'g', '𝑖': 'i',
    '𝑗': 'j', '𝑘': 'k', '𝑙': 'l', '𝑚': 'm', '𝑛': 'n', '𝑜': 'o', '𝑝': 'p', '𝑞': 'q',
    '𝑟': 'r', '𝑠': 's', '𝑡': 't', '𝑢': 'u', '𝑣': 'v', '𝑤': 'w', '𝑥': 'x', '𝑦': 'y',
    '𝑧': 'z',
    '𝐴': 'A', '𝐵': 'B', '𝐶': 'C', '𝐷': 'D', '𝐸': 'E', '𝐹': 'F', '𝐺': 'G', '𝐻': 'H',
    '𝐼': 'I', '𝐽': 'J', '𝐾': 'K', '𝐿': 'L', '𝑀': 'M', '𝑁': 'N', '𝑂': 'O', '𝑃': 'P',
    '𝑄': 'Q', '𝑅': 'R', '𝑆': 'S', '𝑇': 'T', '𝑈': 'U', '𝑉': 'V', '𝑊': 'W', '𝑋': 'X',
    '𝑌': 'Y', '𝑍': 'Z',

    # =========================================================================
    # Mathematical Bold Italic letters (U+1D468-U+1D49B)
    # =========================================================================
    '𝒂': 'a', '𝒃': 'b', '𝒄': 'c', '𝒅': 'd', '𝒆': 'e', '𝒇': 'f', '𝒈': 'g', '𝒉': 'h',
    '𝒊': 'i', '𝒋': 'j', '𝒌': 'k', '𝒍': 'l', '𝒎': 'm', '𝒏': 'n', '𝒐': 'o', '𝒑': 'p',
    '𝒒': 'q', '𝒓': 'r', '𝒔': 's', '𝒕': 't', '𝒖': 'u', '𝒗': 'v', '𝒘': 'w', '𝒙': 'x',
    '𝒚': 'y', '𝒛': 'z',
    '𝑨': 'A', '𝑩': 'B', '𝑪': 'C', '𝑫': 'D', '𝑬': 'E', '𝑭': 'F', '𝑮': 'G', '𝑯': 'H',
    '𝑰': 'I', '𝑱': 'J', '𝑲': 'K', '𝑳': 'L', '𝑴': 'M', '𝑵': 'N', '𝑶': 'O', '𝑷': 'P',
    '𝑸': 'Q', '𝑹': 'R', '𝑺': 'S', '𝑻': 'T', '𝑼': 'U', '𝑽': 'V', '𝑾': 'W', '𝑿': 'X',
    '𝒀': 'Y', '𝒁': 'Z',

    # =========================================================================
    # Mathematical Script letters (U+1D49C-U+1D4CF)
    # =========================================================================
    '𝒶': 'a', '𝒷': 'b', '𝒸': 'c', '𝒹': 'd', '𝒻': 'f', '𝒽': 'h',
    '𝒾': 'i', '𝒿': 'j', '𝓀': 'k', '𝓁': 'l', '𝓂': 'm', '𝓃': 'n', '𝓅': 'p', '𝓆': 'q',
    '𝓇': 'r', '𝓈': 's', '𝓉': 't', '𝓊': 'u', '𝓋': 'v', '𝓌': 'w', '𝓍': 'x', '𝓎': 'y',
    '𝓏': 'z',
    '𝒜': 'A', '𝒞': 'C', '𝒟': 'D', '𝒢': 'G', '𝒥': 'J', '𝒦': 'K',
    '𝒩': 'N', '𝒪': 'O', '𝒫': 'P', '𝒬': 'Q', '𝒮': 'S', '𝒯': 'T',
    '𝒰': 'U', '𝒱': 'V', '𝒲': 'W', '𝒳': 'X', '𝒴': 'Y', '𝒵': 'Z',

    # =========================================================================
    # Mathematical Bold Script letters (U+1D4D0-U+1D503)
    # =========================================================================
    '𝓪': 'a', '𝓫': 'b', '𝓬': 'c', '𝓭': 'd', '𝓮': 'e', '𝓯': 'f', '𝓰': 'g', '𝓱': 'h',
    '𝓲': 'i', '𝓳': 'j', '𝓴': 'k', '𝓵': 'l', '𝓶': 'm', '𝓷': 'n', '𝓸': 'o', '𝓹': 'p',
    '𝓺': 'q', '𝓻': 'r', '𝓼': 's', '𝓽': 't', '𝓾': 'u', '𝓿': 'v', '𝔀': 'w', '𝔁': 'x',
    '𝔂': 'y', '𝔃': 'z',
    '𝓐': 'A', '𝓑': 'B', '𝓒': 'C', '𝓓': 'D', '𝓔': 'E', '𝓕': 'F', '𝓖': 'G', '𝓗': 'H',
    '𝓘': 'I', '𝓙': 'J', '𝓚': 'K', '𝓛': 'L', '𝓜': 'M', '𝓝': 'N', '𝓞': 'O', '𝓟': 'P',
    '𝓠': 'Q', '𝓡': 'R', '𝓢': 'S', '𝓣': 'T', '𝓤': 'U', '𝓥': 'V', '𝓦': 'W', '𝓧': 'X',
    '𝓨': 'Y', '𝓩': 'Z',

    # =========================================================================
    # Mathematical Fraktur letters (U+1D504-U+1D537)
    # =========================================================================
    '𝔞': 'a', '𝔟': 'b', '𝔠': 'c', '𝔡': 'd', '𝔢': 'e', '𝔣': 'f', '𝔤': 'g', '𝔥': 'h',
    '𝔦': 'i', '𝔧': 'j', '𝔨': 'k', '𝔩': 'l', '𝔪': 'm', '𝔫': 'n', '𝔬': 'o', '𝔭': 'p',
    '𝔮': 'q', '𝔯': 'r', '𝔰': 's', '𝔱': 't', '𝔲': 'u', '𝔳': 'v', '𝔴': 'w', '𝔵': 'x',
    '𝔶': 'y', '𝔷': 'z',
    '𝔄': 'A', '𝔅': 'B', '𝔇': 'D', '𝔈': 'E', '𝔉': 'F', '𝔊': 'G',
    '𝔍': 'J', '𝔎': 'K', '𝔏': 'L', '𝔐': 'M', '𝔑': 'N', '𝔒': 'O', '𝔓': 'P', '𝔔': 'Q',
    '𝔖': 'S', '𝔗': 'T', '𝔘': 'U', '𝔙': 'V', '𝔚': 'W', '𝔛': 'X', '𝔜': 'Y',

    # =========================================================================
    # Mathematical Double-Struck letters (U+1D538-U+1D56B)
    # =========================================================================
    '𝕒': 'a', '𝕓': 'b', '𝕔': 'c', '𝕕': 'd', '𝕖': 'e', '𝕗': 'f', '𝕘': 'g', '𝕙': 'h',
    '𝕚': 'i', '𝕛': 'j', '𝕜': 'k', '𝕝': 'l', '𝕞': 'm', '𝕟': 'n', '𝕠': 'o', '𝕡': 'p',
    '𝕢': 'q', '𝕣': 'r', '𝕤': 's', '𝕥': 't', '𝕦': 'u', '𝕧': 'v', '𝕨': 'w', '𝕩': 'x',
    '𝕪': 'y', '𝕫': 'z',
    '𝔸': 'A', '𝔹': 'B', '𝔻': 'D', '𝔼': 'E', '𝔽': 'F', '𝔾': 'G',
    '𝕀': 'I', '𝕁': 'J', '𝕂': 'K', '𝕃': 'L', '𝕄': 'M', '𝕆': 'O',
    '𝕊': 'S', '𝕋': 'T', '𝕌': 'U', '𝕍': 'V', '𝕎': 'W', '𝕏': 'X', '𝕐': 'Y',

    # =========================================================================
    # Mathematical Bold Fraktur letters (U+1D56C-U+1D59F)
    # =========================================================================
    '𝖆': 'a', '𝖇': 'b', '𝖈': 'c', '𝖉': 'd', '𝖊': 'e', '𝖋': 'f', '𝖌': 'g', '𝖍': 'h',
    '𝖎': 'i', '𝖏': 'j', '𝖐': 'k', '𝖑': 'l', '𝖒': 'm', '𝖓': 'n', '𝖔': 'o', '𝖕': 'p',
    '𝖖': 'q', '𝖗': 'r', '𝖘': 's', '𝖙': 't', '𝖚': 'u', '𝖛': 'v', '𝖜': 'w', '𝖝': 'x',
    '𝖞': 'y', '𝖟': 'z',
    '𝕬': 'A', '𝕭': 'B', '𝕮': 'C', '𝕯': 'D', '𝕰': 'E', '𝕱': 'F', '𝕲': 'G', '𝕳': 'H',
    '𝕴': 'I', '𝕵': 'J', '𝕶': 'K', '𝕷': 'L', '𝕸': 'M', '𝕹': 'N', '𝕺': 'O', '𝕻': 'P',
    '𝕼': 'Q', '𝕽': 'R', '𝕾': 'S', '𝕿': 'T', '𝖀': 'U', '𝖁': 'V', '𝖂': 'W', '𝖃': 'X',
    '𝖄': 'Y', '𝖅': 'Z',

    # =========================================================================
    # Mathematical Sans-Serif letters (U+1D5A0-U+1D5D3)
    # =========================================================================
    '𝖺': 'a', '𝖻': 'b', '𝖼': 'c', '𝖽': 'd', '𝖾': 'e', '𝖿': 'f', '𝗀': 'g', '𝗁': 'h',
    '𝗂': 'i', '𝗃': 'j', '𝗄': 'k', '𝗅': 'l', '𝗆': 'm', '𝗇': 'n', '𝗈': 'o', '𝗉': 'p',
    '𝗊': 'q', '𝗋': 'r', '𝗌': 's', '𝗍': 't', '𝗎': 'u', '𝗏': 'v', '𝗐': 'w', '𝗑': 'x',
    '𝗒': 'y', '𝗓': 'z',
    '𝖠': 'A', '𝖡': 'B', '𝖢': 'C', '𝖣': 'D', '𝖤': 'E', '𝖥': 'F', '𝖦': 'G', '𝖧': 'H',
    '𝖨': 'I', '𝖩': 'J', '𝖪': 'K', '𝖫': 'L', '𝖬': 'M', '𝖭': 'N', '𝖮': 'O', '𝖯': 'P',
    '𝖰': 'Q', '𝖱': 'R', '𝖲': 'S', '𝖳': 'T', '𝖴': 'U', '𝖵': 'V', '𝖶': 'W', '𝖷': 'X',
    '𝖸': 'Y', '𝖹': 'Z',

    # =========================================================================
    # Mathematical Sans-Serif Bold letters (U+1D5D4-U+1D607)
    # =========================================================================
    '𝗮': 'a', '𝗯': 'b', '𝗰': 'c', '𝗱': 'd', '𝗲': 'e', '𝗳': 'f', '𝗴': 'g', '𝗵': 'h',
    '𝗶': 'i', '𝗷': 'j', '𝗸': 'k', '𝗹': 'l', '𝗺': 'm', '𝗻': 'n', '𝗼': 'o', '𝗽': 'p',
    '𝗾': 'q', '𝗿': 'r', '𝘀': 's', '𝘁': 't', '𝘂': 'u', '𝘃': 'v', '𝘄': 'w', '𝘅': 'x',
    '𝘆': 'y', '𝘇': 'z',
    '𝗔': 'A', '𝗕': 'B', '𝗖': 'C', '𝗗': 'D', '𝗘': 'E', '𝗙': 'F', '𝗚': 'G', '𝗛': 'H',
    '𝗜': 'I', '𝗝': 'J', '𝗞': 'K', '𝗟': 'L', '𝗠': 'M', '𝗡': 'N', '𝗢': 'O', '𝗣': 'P',
    '𝗤': 'Q', '𝗥': 'R', '𝗦': 'S', '𝗧': 'T', '𝗨': 'U', '𝗩': 'V', '𝗪': 'W', '𝗫': 'X',
    '𝗬': 'Y', '𝗭': 'Z',

    # =========================================================================
    # Mathematical Sans-Serif Italic letters (U+1D608-U+1D63B)
    # =========================================================================
    '𝘢': 'a', '𝘣': 'b', '𝘤': 'c', '𝘥': 'd', '𝘦': 'e', '𝘧': 'f', '𝘨': 'g', '𝘩': 'h',
    '𝘪': 'i', '𝘫': 'j', '𝘬': 'k', '𝘭': 'l', '𝘮': 'm', '𝘯': 'n', '𝘰': 'o', '𝘱': 'p',
    '𝘲': 'q', '𝘳': 'r', '𝘴': 's', '𝘵': 't', '𝘶': 'u', '𝘷': 'v', '𝘸': 'w', '𝘹': 'x',
    '𝘺': 'y', '𝘻': 'z',
    '𝘈': 'A', '𝘉': 'B', '𝘊': 'C', '𝘋': 'D', '𝘌': 'E', '𝘍': 'F', '𝘎': 'G', '𝘏': 'H',
    '𝘐': 'I', '𝘑': 'J', '𝘒': 'K', '𝘓': 'L', '𝘔': 'M', '𝘕': 'N', '𝘖': 'O', '𝘗': 'P',
    '𝘘': 'Q', '𝘙': 'R', '𝘚': 'S', '𝘛': 'T', '𝘜': 'U', '𝘝': 'V', '𝘞': 'W', '𝘟': 'X',
    '𝘠': 'Y', '𝘡': 'Z',

    # =========================================================================
    # Mathematical Sans-Serif Bold Italic letters (U+1D63C-U+1D66F)
    # =========================================================================
    '𝙖': 'a', '𝙗': 'b', '𝙘': 'c', '𝙙': 'd', '𝙚': 'e', '𝙛': 'f', '𝙜': 'g', '𝙝': 'h',
    '𝙞': 'i', '𝙟': 'j', '𝙠': 'k', '𝙡': 'l', '𝙢': 'm', '𝙣': 'n', '𝙤': 'o', '𝙥': 'p',
    '𝙦': 'q', '𝙧': 'r', '𝙨': 's', '𝙩': 't', '𝙪': 'u', '𝙫': 'v', '𝙬': 'w', '𝙭': 'x',
    '𝙮': 'y', '𝙯': 'z',
    '𝘼': 'A', '𝘽': 'B', '𝘾': 'C', '𝘿': 'D', '𝙀': 'E', '𝙁': 'F', '𝙂': 'G', '𝙃': 'H',
    '𝙄': 'I', '𝙅': 'J', '𝙆': 'K', '𝙇': 'L', '𝙈': 'M', '𝙉': 'N', '𝙊': 'O', '𝙋': 'P',
    '𝙌': 'Q', '𝙍': 'R', '𝙎': 'S', '𝙏': 'T', '𝙐': 'U', '𝙑': 'V', '𝙒': 'W', '𝙓': 'X',
    '𝙔': 'Y', '𝙕': 'Z',

    # =========================================================================
    # Mathematical Monospace letters (U+1D670-U+1D6A3)
    # =========================================================================
    '𝚊': 'a', '𝚋': 'b', '𝚌': 'c', '𝚍': 'd', '𝚎': 'e', '𝚏': 'f', '𝚐': 'g', '𝚑': 'h',
    '𝚒': 'i', '𝚓': 'j', '𝚔': 'k', '𝚕': 'l', '𝚖': 'm', '𝚗': 'n', '𝚘': 'o', '𝚙': 'p',
    '𝚚': 'q', '𝚛': 'r', '𝚜': 's', '𝚝': 't', '𝚞': 'u', '𝚟': 'v', '𝚠': 'w', '𝚡': 'x',
    '𝚢': 'y', '𝚣': 'z',
    '𝙰': 'A', '𝙱': 'B', '𝙲': 'C', '𝙳': 'D', '𝙴': 'E', '𝙵': 'F', '𝙶': 'G', '𝙷': 'H',
    '𝙸': 'I', '𝙹': 'J', '𝙺': 'K', '𝙻': 'L', '𝙼': 'M', '𝙽': 'N', '𝙾': 'O', '𝙿': 'P',
    '𝚀': 'Q', '𝚁': 'R', '𝚂': 'S', '𝚃': 'T', '𝚄': 'U', '𝚅': 'V', '𝚆': 'W', '𝚇': 'X',
    '𝚈': 'Y', '𝚉': 'Z',

    # =========================================================================
    # Circled letters (U+24B6-U+24E9)
    # =========================================================================
    'ⓐ': 'a', 'ⓑ': 'b', 'ⓒ': 'c', 'ⓓ': 'd', 'ⓔ': 'e', 'ⓕ': 'f', 'ⓖ': 'g', 'ⓗ': 'h',
    'ⓘ': 'i', 'ⓙ': 'j', 'ⓚ': 'k', 'ⓛ': 'l', 'ⓜ': 'm', 'ⓝ': 'n', 'ⓞ': 'o', 'ⓟ': 'p',
    'ⓠ': 'q', 'ⓡ': 'r', 'ⓢ': 's', 'ⓣ': 't', 'ⓤ': 'u', 'ⓥ': 'v', 'ⓦ': 'w', 'ⓧ': 'x',
    'ⓨ': 'y', 'ⓩ': 'z',
    'Ⓐ': 'A', 'Ⓑ': 'B', 'Ⓒ': 'C', 'Ⓓ': 'D', 'Ⓔ': 'E', 'Ⓕ': 'F', 'Ⓖ': 'G', 'Ⓗ': 'H',
    'Ⓘ': 'I', 'Ⓙ': 'J', 'Ⓚ': 'K', 'Ⓛ': 'L', 'Ⓜ': 'M', 'Ⓝ': 'N', 'Ⓞ': 'O', 'Ⓟ': 'P',
    'Ⓠ': 'Q', 'Ⓡ': 'R', 'Ⓢ': 'S', 'Ⓣ': 'T', 'Ⓤ': 'U', 'Ⓥ': 'V', 'Ⓦ': 'W', 'Ⓧ': 'X',
    'Ⓨ': 'Y', 'Ⓩ': 'Z',

    # =========================================================================
    # Parenthesized letters (U+249C-U+24B5)
    # =========================================================================
    '⒜': 'a', '⒝': 'b', '⒞': 'c', '⒟': 'd', '⒠': 'e', '⒡': 'f', '⒢': 'g', '⒣': 'h',
    '⒤': 'i', '⒥': 'j', '⒦': 'k', '⒧': 'l', '⒨': 'm', '⒩': 'n', '⒪': 'o', '⒫': 'p',
    '⒬': 'q', '⒭': 'r', '⒮': 's', '⒯': 't', '⒰': 'u', '⒱': 'v', '⒲': 'w', '⒳': 'x',
    '⒴': 'y', '⒵': 'z',

    # =========================================================================
    # Regional Indicator Symbols (U+1F1E6-U+1F1FF)
    # These are flag characters but can be used as letter substitutes
    # =========================================================================
    '🇦': 'a', '🇧': 'b', '🇨': 'c', '🇩': 'd', '🇪': 'e', '🇫': 'f', '🇬': 'g', '🇭': 'h',
    '🇮': 'i', '🇯': 'j', '🇰': 'k', '🇱': 'l', '🇲': 'm', '🇳': 'n', '🇴': 'o', '🇵': 'p',
    '🇶': 'q', '🇷': 'r', '🇸': 's', '🇹': 't', '🇺': 'u', '🇻': 'v', '🇼': 'w', '🇽': 'x',
    '🇾': 'y', '🇿': 'z',

    # =========================================================================
    # Subscript letters (limited availability in Unicode)
    # =========================================================================
    'ₐ': 'a', 'ₑ': 'e', 'ₒ': 'o', 'ₓ': 'x', 'ₕ': 'h', 'ₖ': 'k', 'ₗ': 'l',
    'ₘ': 'm', 'ₙ': 'n', 'ₚ': 'p', 'ₛ': 's', 'ₜ': 't',

    # =========================================================================
    # Modifier/Superscript letters
    # =========================================================================
    'ᵃ': 'a', 'ᵇ': 'b', 'ᶜ': 'c', 'ᵈ': 'd', 'ᵉ': 'e', 'ᶠ': 'f', 'ᵍ': 'g', 'ʰ': 'h',
    'ⁱ': 'i', 'ʲ': 'j', 'ᵏ': 'k', 'ˡ': 'l', 'ᵐ': 'm', 'ⁿ': 'n', 'ᵒ': 'o', 'ᵖ': 'p',
    'ʳ': 'r', 'ˢ': 's', 'ᵗ': 't', 'ᵘ': 'u', 'ᵛ': 'v', 'ʷ': 'w', 'ˣ': 'x', 'ʸ': 'y',
    'ᶻ': 'z',
    'ᴬ': 'A', 'ᴮ': 'B', 'ᴰ': 'D', 'ᴱ': 'E', 'ᴳ': 'G', 'ᴴ': 'H',
    'ᴵ': 'I', 'ᴶ': 'J', 'ᴷ': 'K', 'ᴸ': 'L', 'ᴹ': 'M', 'ᴺ': 'N', 'ᴼ': 'O', 'ᴾ': 'P',
    'ᴿ': 'R', 'ᵀ': 'T', 'ᵁ': 'U', 'ⱽ': 'V', 'ᵂ': 'W',

    # =========================================================================
    # Squared Latin letters (U+1F130-U+1F149)
    # =========================================================================
    '🄰': 'A', '🄱': 'B', '🄲': 'C', '🄳': 'D', '🄴': 'E', '🄵': 'F', '🄶': 'G', '🄷': 'H',
    '🄸': 'I', '🄹': 'J', '🄺': 'K', '🄻': 'L', '🄼': 'M', '🄽': 'N', '🄾': 'O', '🄿': 'P',
    '🅀': 'Q', '🅁': 'R', '🅂': 'S', '🅃': 'T', '🅄': 'U', '🅅': 'V', '🅆': 'W', '🅇': 'X',
    '🅈': 'Y', '🅉': 'Z',

    # =========================================================================
    # Negative Circled Latin letters (U+1F150-U+1F169)
    # =========================================================================
    '🅐': 'A', '🅑': 'B', '🅒': 'C', '🅓': 'D', '🅔': 'E', '🅕': 'F', '🅖': 'G', '🅗': 'H',
    '🅘': 'I', '🅙': 'J', '🅚': 'K', '🅛': 'L', '🅜': 'M', '🅝': 'N', '🅞': 'O', '🅟': 'P',
    '🅠': 'Q', '🅡': 'R', '🅢': 'S', '🅣': 'T', '🅤': 'U', '🅥': 'V', '🅦': 'W', '🅧': 'X',
    '🅨': 'Y', '🅩': 'Z',

    # =========================================================================
    # Negative Squared Latin letters (U+1F170-U+1F189)
    # =========================================================================
    '🅰': 'A', '🅱': 'B', '🅲': 'C', '🅳': 'D', '🅴': 'E', '🅵': 'F', '🅶': 'G', '🅷': 'H',
    '🅸': 'I', '🅹': 'J', '🅺': 'K', '🅻': 'L', '🅼': 'M', '🅽': 'N', '🅾': 'O', '🅿': 'P',
    '🆀': 'Q', '🆁': 'R', '🆂': 'S', '🆃': 'T', '🆄': 'U', '🆅': 'V', '🆆': 'W', '🆇': 'X',
    '🆈': 'Y', '🆉': 'Z',

    # =========================================================================
    # Latin Extended lookalikes
    # =========================================================================
    'ɑ': 'a', 'ƈ': 'c', 'ɗ': 'd', 'ɛ': 'e', 'ƒ': 'f', 'ɠ': 'g', 'ɦ': 'h',
    'ı': 'i', 'ɟ': 'j', 'ƙ': 'k', 'ℓ': 'l', 'ɱ': 'm', 'ɲ': 'n', 'ɔ': 'o', 'ƥ': 'p',
    'ɋ': 'q', 'ɼ': 'r', 'ʂ': 's', 'ƭ': 't', 'ʋ': 'v', 'ʍ': 'w', 'ȥ': 'z',

    # =========================================================================
    # IPA Extensions that resemble Latin letters
    # =========================================================================
    'ɐ': 'a', 'ɓ': 'b', 'ɕ': 'c', 'ɖ': 'd', 'ə': 'e', 'ɡ': 'g', 'ɥ': 'h',
    'ɨ': 'i', 'ʝ': 'j', 'ɫ': 'l', 'ɯ': 'm', 'ɵ': 'o', 'ɸ': 'p', 'ɹ': 'r',
    'ʃ': 's', 'ʇ': 't', 'ʊ': 'u', 'ʌ': 'v', 'ʎ': 'y', 'ʐ': 'z',
}

# Word-to-number mapping for text number bypass detection
WORD_NUMBERS = {
    "zero": "0", "one": "1", "two": "2", "three": "3", "four": "4",
    "five": "5", "six": "6", "seven": "7", "eight": "8", "nine": "9",
    "ten": "10", "eleven": "11", "twelve": "12", "thirteen": "13",
    "fourteen": "14", "fifteen": "15", "sixteen": "16", "seventeen": "17",
    "eighteen": "18", "nineteen": "19", "twenty": "20", "thirty": "30",
    "forty": "40", "fifty": "50", "sixty": "60", "seventy": "70",
    "eighty": "80", "ninety": "90", "hundred": "100",
    "twenty-seven hundred": "2700", "sixty-five hundred": "6500",
}

ABBREVIATIONS = {
    r"\bmin\b": "minimum",
    r"\bmax\b": "maximum",
    r"\bval\b": "value",
    r"\bprop\b": "property",
    r"\bprops\b": "properties",
    r"\btemp\b": "temperature",
    r"\bbright\b": "brightness",
    r"\bctrl\b": "control",
    r"\bcfg\b": "config",
    r"\bconf\b": "config",
}

SYNONYM_MAP = {
    # brightness synonyms
    'luminosity': 'brightness',
    'illumination': 'brightness',
    'intensity': 'brightness',
    'light level': 'brightness',
    'brilliance': 'brightness',
    'radiance': 'brightness',
    # minimum synonyms
    'floor': 'minimum',
    'lower limit': 'minimum',
    'at least': 'minimum',
    'no less than': 'minimum',
    'lowest': 'minimum',
    'bottom': 'minimum',
    # maximum synonyms
    'ceiling': 'maximum',
    'upper limit': 'maximum',
    'at most': 'maximum',
    'no more than': 'maximum',
    'highest': 'maximum',
    'top': 'maximum',
    'cap': 'maximum',
    # color_temp synonyms
    'color temperature': 'color_temp',
    'colour temperature': 'color_temp',
    'kelvin': 'color_temp',
    'warmth': 'color_temp',
    # property synonyms
    'attribute': 'property',
    'field': 'property',
    'setting': 'property',
    'parameter': 'property',
}

# NATO phonetic alphabet mapping for decoding phonetic-encoded text
NATO_PHONETIC_MAP = {
    'alpha': 'a', 'bravo': 'b', 'charlie': 'c', 'delta': 'd', 'echo': 'e',
    'foxtrot': 'f', 'golf': 'g', 'hotel': 'h', 'india': 'i', 'juliet': 'j',
    'kilo': 'k', 'lima': 'l', 'mike': 'm', 'november': 'n', 'oscar': 'o',
    'papa': 'p', 'quebec': 'q', 'romeo': 'r', 'sierra': 's', 'tango': 't',
    'uniform': 'u', 'victor': 'v', 'whiskey': 'w', 'xray': 'x', 'yankee': 'y',
    'zulu': 'z', 'zero': '0', 'one': '1', 'two': '2', 'three': '3', 'four': '4',
    'five': '5', 'six': '6', 'seven': '7', 'eight': '8', 'niner': '9',
    'underscore': '_', 'dash': '-',
}

EUPHEMISM_MAP = {
    # Constraint paraphrasing
    'upper limit': 'maximum',
    'lower bound': 'minimum',
    'upper bound': 'maximum',
    'lower limit': 'minimum',
    'allowed values': 'enum',
    'valid values': 'enum',
    'permitted values': 'enum',
    'acceptable values': 'enum',
    'valid range': 'minimum maximum',
    'acceptable range': 'minimum maximum',
    'permitted range': 'minimum maximum',
    'value constraints': 'minimum maximum',
    # Type euphemisms
    'whole number': 'integer',
    'numeric value': 'integer',
    'text value': 'string',
    'text field': 'string',
    # Structure euphemisms
    'list of options': 'enum',
    'set of choices': 'enum',
    'available options': 'enum',
    'possible values': 'enum',
    'data structure': 'object',
    'configuration object': 'object',
    # Action euphemisms
    'cannot exceed': 'maximum',
    'must not exceed': 'maximum',
    'should not exceed': 'maximum',
    'cannot be less than': 'minimum',
    'must be at least': 'minimum',
    'no greater than': 'maximum',
    'no smaller than': 'minimum',
}

# Emoji substitution map for semantic emoji-to-keyword detection
EMOJI_MAP = {
    # Light-related
    '💡': 'light', '🔦': 'light', '☀️': 'bright', '🌟': 'bright',
    '✨': 'bright', '🌞': 'bright', '💫': 'light',
    # Lock/security related
    '🔒': 'lock', '🔓': 'unlock', '🔐': 'lock', '🔑': 'pin',
    '🗝️': 'pin', '🚪': 'door',
    # Room-related
    '🏠': 'room', '🛋️': 'living_room', '🛏️': 'bedroom',
    '🍳': 'kitchen', '🚿': 'bathroom', '🚗': 'garage',
    # Value-related
    '⬆️': 'maximum', '⬇️': 'minimum', '📈': 'maximum', '📉': 'minimum',
    '🔝': 'maximum', '🔚': 'minimum',
    # Temperature-related
    '🌡️': 'temp', '🔥': 'temp', '❄️': 'temp', '🌡': 'temp',
    # Control-related
    '🎛️': 'control', '🎚️': 'control', '⚙️': 'control',
    # Color-related
    '🎨': 'color', '🌈': 'color',
    # Override/special
    '⚠️': 'override', '🚨': 'override',
}

# D-30: Multi-language translation map for detecting schema keywords in foreign languages
TRANSLATION_MAP = {
    # French translations
    'luminosité': 'brightness',
    'luminosite': 'brightness',
    'température': 'temperature',
    'couleur': 'color',
    'contrôle': 'control',
    'controle': 'control',
    'verrouillage': 'lock',
    'serrure': 'lock',
    'porte': 'door',
    'chambre': 'bedroom',
    'cuisine': 'kitchen',
    'salon': 'living_room',
    'salle de bain': 'bathroom',
    'propriétés': 'properties',
    'proprietes': 'properties',

    # German translations
    'helligkeit': 'brightness',
    'temperatur': 'temperature',
    'farbe': 'color',
    'steuerung': 'control',
    'kontrolle': 'control',
    'schloss': 'lock',
    'tür': 'door',
    'tur': 'door',
    'schlafzimmer': 'bedroom',
    'küche': 'kitchen',
    'kuche': 'kitchen',
    'wohnzimmer': 'living_room',
    'badezimmer': 'bathroom',
    'eigenschaften': 'properties',
    'mindestens': 'minimum',
    'höchstens': 'maximum',
    'hochstens': 'maximum',

    # Spanish translations
    'brillo': 'brightness',
    'cerradura': 'lock',
    'puerta': 'door',
    'dormitorio': 'bedroom',
    'cocina': 'kitchen',
    'sala': 'living_room',
    'baño': 'bathroom',
    'bano': 'bathroom',
    'garaje': 'garage',
    'propiedades': 'properties',
    'mínimo': 'minimum',
    'minimo': 'minimum',
    'máximo': 'maximum',
    'maximo': 'maximum',

    # Italian translations
    'luminosita': 'brightness',
    'controllo': 'control',
    'serratura': 'lock',
    'porta': 'door',
    'camera': 'bedroom',
    'soggiorno': 'living_room',

    # Portuguese translations
    'brilho': 'brightness',
    'controlo': 'control',
    'fechadura': 'lock',
    'quarto': 'bedroom',
    'banheiro': 'bathroom',
}

# ============================================================================
# Schema Keywords - Single source of truth
# Previously duplicated in 12 locations throughout plugin.py
# ============================================================================

# Full set of schema keywords for detection
SCHEMA_KEYWORDS = frozenset([
    "light_control", "lock_control", "brightness", "color_temp",
    "pin_override", "minimum", "maximum", "enum", "properties",
    "living_room", "bedroom", "kitchen", "bathroom",
    "front_door", "back_door", "garage"
])

# Version without underscores (for ciphers like Playfair that strip punctuation)
# Used by: _try_playfair_decode()
SCHEMA_KEYWORDS_NO_UNDERSCORE = frozenset(
    kw.replace('_', '') for kw in SCHEMA_KEYWORDS
)

# Bytes version for binary decoders (XOR)
# Used by: _try_xor_decode()
SCHEMA_KEYWORDS_BYTES = frozenset(kw.encode() for kw in SCHEMA_KEYWORDS)

# Subset for ciphers with shorter keyword lists (Vigenere, Rail Fence, Punycode)
SCHEMA_KEYWORDS_CORE = frozenset([
    'brightness', 'color_temp', 'pin_override', 'minimum', 'maximum',
    'light_control', 'lock_control', 'living_room', 'bedroom'
])

# List version for iteration (preserves order for deterministic behavior)
SCHEMA_KEYWORDS_LIST = [
    "light_control", "lock_control", "brightness", "color_temp",
    "pin_override", "minimum", "maximum", "enum", "properties",
    "living_room", "bedroom", "kitchen", "bathroom",
    "front_door", "back_door", "garage",
    # Add "pattern" and "regex" to protect regex pattern text from cipher corruption
    "pattern", "regex",
]
