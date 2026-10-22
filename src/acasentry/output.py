import csv
import unicodedata

# Ported from bbwarden (github.com/chriswayneh/bbwarden, src/bbwarden/cli.py escape()).
# Cc control, Cf format (bidi overrides, zero-width), Cs lone surrogates, Co private use,
# Cn unassigned, Zl/Zp line and paragraph separators (U+2028, U+2029).
_UNSAFE = ("Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp")


def _is_control(c):
    """C0, DEL, C1 (including CSI U+009B), and the Unicode categories in _UNSAFE."""
    o = ord(c)
    return o < 0x20 or 0x7F <= o <= 0x9F or unicodedata.category(c) in _UNSAFE


def escape(s):
    """Text safe for a terminal: every control or format character becomes its escaped
    code point (\\x1b, \\u202e, \\U000e0001), so names from Graph or Azure cannot move the
    cursor, set the title, add hyperlinks, clear the line or reorder text. Used for every
    table cell and every message printed from data. CSV output keeps the raw text."""
    out = []
    for c in str(s):
        if c == "\\":  # so a literal "\\x1b" in a name cannot pass for an escaped ESC
            out.append("\\\\")
        elif not _is_control(c):
            out.append(c)
        elif ord(c) <= 0xFF:
            out.append(f"\\x{ord(c):02x}")
        elif ord(c) <= 0xFFFF:
            out.append(f"\\u{ord(c):04x}")
        else:
            out.append(f"\\U{ord(c):08x}")
    return "".join(out)


def table(headers, rows):
    headers = [escape(h) for h in headers]
    rows = [[escape(c) for c in r] for r in rows]
    widths = [len(h) for h in headers]
    for r in rows:
        widths = [max(w, len(str(c))) for w, c in zip(widths, r)]
    fmt = "  ".join(f"{{:<{w}}}" for w in widths)
    lines = [fmt.format(*headers), fmt.format(*["-" * w for w in widths])]
    lines += [fmt.format(*[str(c) for c in r]) for r in rows]
    return "\n".join(l.rstrip() for l in lines)


FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r", "\n")


def csv_safe(value):
    """Neutralize spreadsheet formula injection (OWASP CSV injection guidance):
    cells starting with = + - @ tab, CR or LF, also after leading whitespace, get a
    leading single quote. The lone '-' placeholder is left as is."""
    text = str(value)
    if text == "-":  # placeholder cell used in tables, not a formula
        return text
    if text.startswith(FORMULA_PREFIXES) or text.lstrip().startswith(FORMULA_PREFIXES):
        return "'" + text
    return text


def write_csv(path, headers, rows):
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow([csv_safe(h) for h in headers])
        w.writerows([[csv_safe(c) for c in r] for r in rows])
