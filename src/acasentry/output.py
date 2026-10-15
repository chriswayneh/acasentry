import csv


def table(headers, rows):
    widths = [len(h) for h in headers]
    for r in rows:
        widths = [max(w, len(str(c))) for w, c in zip(widths, r)]
    fmt = "  ".join(f"{{:<{w}}}" for w in widths)
    lines = [fmt.format(*headers), fmt.format(*["-" * w for w in widths])]
    lines += [fmt.format(*[str(c) for c in r]) for r in rows]
    return "\n".join(l.rstrip() for l in lines)


FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def csv_safe(value):
    """Neutralize spreadsheet formula injection (OWASP CSV injection guidance):
    cells starting with = + - @ tab or CR get a leading single quote."""
    text = str(value)
    return "'" + text if text.startswith(FORMULA_PREFIXES) else text


def write_csv(path, headers, rows):
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow([csv_safe(h) for h in headers])
        w.writerows([[csv_safe(c) for c in r] for r in rows])
