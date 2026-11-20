#!/usr/bin/env python3
"""Check a text against ASD-STE100 Simplified Technical English rules.

This is a fast, approximate checker. It finds the rule breaks that people
make most often. It cannot replace a human check, but it catches the
mechanical faults (sentence length, contractions, banned words, and
verb forms) reliably.

Usage:
    python3 ste_check.py [FILE|-] [--mode auto|proc|desc] [--json] [--quiet]

  FILE       Text file to check. Use "-" or no FILE to read stdin.
  --mode     Text type. "proc" = procedural (max 20 words a sentence),
             "desc" = descriptive (max 25 words), "auto" = guess from the
             text (default).
  --json     Write the result as JSON.
  --quiet    Write only the summary line.

Exit code is 1 when the text has errors (rule breaks), 0 when it does not.

Rule numbers come from ASD-STE100 Issue 9, Part 1.
"""

import argparse
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = json.load(open(os.path.join(HERE, "ste_data.json"), encoding="utf-8"))
NON_APPROVED = DATA["non_approved"]
BANNED_MODALS = DATA["banned_modals"]
PHRASES = DATA["phrases"]
PHRASAL = DATA["phrasal_verbs"]
BE_VERBS = set(DATA["be_verbs"])
STOPWORDS = set(DATA["stopwords"])

UNIT = (
    r"(?:mm|cm|km|m|in|ft|yd|mi|kg|mg|g|lb|oz|ton|L|l|ml|gal|s|ms|ns|us|min|h|hr|"
    r"Hz|kHz|MHz|GHz|rpm|psi|bar|Pa|kPa|MPa|V|mV|kV|A|mA|W|kW|MW|J|N|Nm|C|F|K|"
    r"%|degC|degF|KB|MB|GB|TB|kbit|kbps|Mbps|Gbps|px|dpi|dpi|pt|em|rem|B|bit|bps)"
)
NUM_UNIT = re.compile(r"\b\d+(?:[.,]\d+)?\s*" + UNIT + r"\b")
ABBREV = {
    "e.g.", "i.e.", "etc.", "vs.", "no.", "fig.", "min.", "max.", "approx.",
    "inc.", "ltd.", "dr.", "mr.", "mrs.", "a.m.", "p.m.", "u.s.", "u.k.",
}

CONTRACTIONS = re.compile(r"\b\w+['\u2019](?:s|t|re|ve|ll|d|m)\b", re.IGNORECASE)
SEMICOLON = re.compile(r";")
LATIN = re.compile(r"\b(?:e\.g\.|i\.e\.|etc\.|vs\.)\b", re.IGNORECASE)
PERFECT = re.compile(
    r"\b(?:has|have|had)\s+(?:\w+ed|been|got|given|taken|made|done|shown|"
    r"known|found|seen|kept|sent|put|set|read|held|brought|built|written|"
    r"broken|chosen|driven|eaten|fallen|felt|left|lost|met|paid|run|said|"
    r"sold|spent|stood|told|understood|worn|won)\b",
    re.IGNORECASE,
)
PROGRESSIVE = re.compile(
    r"\b(?:am|is|are|was|were|be|been|being)\s+(\w+ing)\b", re.IGNORECASE
)
PASSIVE = re.compile(
    r"\b(?:is|are|was|were|be|been|get|gets|got)\s+(\w+(?:ed|en)|"
    r"done|made|given|taken|shown|known|found|seen|kept|sent|put|set|"
    r"read|held|built|written|broken|chosen|left|lost|run|sold|told)\b",
    re.IGNORECASE,
)
MUST_IMPERATIVE = re.compile(r"\b[Mm]ust\s+[a-z]+", re.IGNORECASE)
QUOTED = re.compile(r"\"[^\"]*\"|\u201c[^\u201d]*\u201d|'[^']{3,}'")
PAREN = re.compile(r"\([^()]*\)")
CODE_FENCE = re.compile(r"```.*?```", re.DOTALL)
INLINE_CODE = re.compile(r"`[^`]*`")
URL = re.compile(r"https?://\S+")

WORD = re.compile(r"[A-Za-z][A-Za-z'\-]*")
ALNUM = re.compile(r"\b[A-Za-z0-9]*\d[A-Za-z0-9]*\b")
CAP_SEQ = re.compile(r"\b(?:[A-Z][a-z']+\s+){1,}[A-Z][a-z']+\b")
ALLCAPS_SEQ = re.compile(r"\b[A-Z][A-Z0-9\-]*(?:\s+[A-Z][A-Z0-9\-]+)+\b")


def split_sentences(text):
    """Split text into sentences. Keep lines with their source line number."""
    text = text.replace("\r\n", "\n")
    out = []
    for line_no, line in enumerate(text.split("\n"), 1):
        s = line.strip()
        if not s:
            continue
        parts = re.split(r"(?<=[.!?])[\"')\]]?\s+(?=[A-Z0-9\"'(])", s)
        merged = []
        for p in parts:
            if merged and merged[-1].split() and (
                merged[-1].split()[-1].lower() in ABBREV
                or re.fullmatch(r"[A-Z]\.", merged[-1].split()[-1])
            ):
                merged[-1] = merged[-1] + " " + p
            else:
                merged.append(p)
        for p in merged:
            if p.strip():
                out.append((line_no, p.strip()))
    return out


def count_words(sentence):
    """Approximate the STE word count (rules 8.4-8.7)."""
    s = QUOTED.sub(" QUOTEDTEXT ", sentence)
    s = PAREN.sub(" PAREN ", s)
    s = ALLCAPS_SEQ.sub(" CAPS ", s)
    s = CAP_SEQ.sub(" PROPERNOUN ", s)
    s = NUM_UNIT.sub(" NUMUNIT ", s)
    s = ALNUM.sub(" ID ", s)
    s = re.sub(r"\b[A-Za-z][A-Za-z'\-]*(?:-[A-Za-z'\-]+)+\b", " HYPHWORD ", s)
    return len(re.findall(r"\S+", s))


def guess_mode(text):
    proc = 0
    desc = 0
    for line in text.split("\n"):
        s = line.strip()
        if re.match(r"^(?:[-*\u2022]|\d+[.)]|[A-Za-z][.)])\s+", s):
            proc += 1
        if re.match(r"^[A-Z][a-z]+\s+the\s+\w+", s):
            desc += 1
        if re.search(r"\b(?:WARNING|CAUTION|NOTE)\b", s):
            proc += 1
    return "proc" if proc >= desc and proc > 0 else "desc"


def strip_code(text):
    text = CODE_FENCE.sub("\n", text)
    text = INLINE_CODE.sub(" CODE ", text)
    text = URL.sub(" URL ", text)
    return text


def check(text, mode):
    clean = strip_code(text)
    if mode == "auto":
        mode = guess_mode(clean)
    limit = 20 if mode == "proc" else 25
    findings = []

    def add(rule, severity, kind, message, snippet="", suggestion=""):
        findings.append(
            {
                "rule": rule,
                "severity": severity,
                "type": kind,
                "message": message,
                "text": snippet,
                "suggestion": suggestion,
            }
        )

    for line_no, line in enumerate(clean.split("\n"), 1):
        if SEMICOLON.search(line):
            add("8.1", "error", "punctuation",
                "Semicolon is not permitted. Write two sentences.",
                line, "Replace the semicolon with a period.")
        for m in LATIN.finditer(line):
            add("GR-6", "warn", "latin_abbrev",
                "Do not use Latin abbreviations.", m.group(0),
                {"i.e.": "that is", "e.g.": "for example", "etc.": "write the items",
                 "vs.": "or"}[m.group(0).lower()])

    paragraphs = [p for p in re.split(r"\n\s*\n", clean) if p.strip()]
    for p in paragraphs:
        n_sent = len(split_sentences(p))
        if n_sent > 6:
            add("6.6", "warn", "paragraph_length",
                "Paragraph has {} sentences (maximum 6).".format(n_sent),
                p.split("\n")[0][:80], "Divide the paragraph.")

    for line_no, sent in sentences_with_lines(clean):
        wc = count_words(sent)
        if wc > limit:
            add("5.1" if mode == "proc" else "6.3", "warn", "sentence_length",
                "Sentence has {} words (maximum {} for {} text).".format(
                    wc, limit, "procedural" if mode == "proc" else "descriptive"),
                sent, "Divide the sentence into two sentences.")
        for m in CONTRACTIONS.finditer(sent):
            add("4.2", "error", "contraction",
                "Contraction is not permitted.", m.group(0),
                "Write the words in full.")
        words = WORD.findall(sent)
        lowered = [w.lower() for w in words]
        for i, w in enumerate(words):
            lw = w.lower().strip("'")
            if lw in NON_APPROVED and lw not in BANNED_MODALS:
                alts = NON_APPROVED[lw]["alts"]
                if alts and alts[0] in ("(remove)",):
                    add("1.1", "warn", "filler_word",
                        "'{}' is not approved STE. Remove it.".format(w), w, "")
                else:
                    add("1.1", "warn", "non_approved_word",
                        "'{}' is not approved STE.".format(w), w,
                        "Use: " + ", ".join(alts) if alts else "Use an approved word.")
            if lw in BANNED_MODALS:
                add("1.1", "warn", "modal_verb",
                    "'{}' is not the approved modal verb.".format(w), w,
                    "Use: " + ", ".join(BANNED_MODALS[lw]))
        low = " " + " ".join(lowered) + " "
        for phrase, rep in PHRASES.items():
            if " " + phrase + " " in low:
                add("1.1", "warn", "non_approved_phrase",
                    "'{}' is not approved STE.".format(phrase), phrase,
                    "Use: " + rep)
        for pv, rep in PHRASAL.items():
            if " " + pv + " " in low:
                add("9.3", "warn", "phrasal_verb",
                    "'{}' is a phrasal verb.".format(pv), pv, "Use: " + rep)
        for m in PROGRESSIVE.finditer(sent):
            if m.group(1).lower() not in ("something", "during"):
                add("3.2", "warn", "progressive_tense",
                    "'-ing' verb form is not approved as a tense.", m.group(0),
                    "Use the simple present or the imperative.")
        for m in PERFECT.finditer(sent):
            add("3.2", "warn", "perfect_tense",
                "Perfect tense is not approved.", m.group(0),
                "Use the simple past or simple present.")
        for m in PASSIVE.finditer(sent):
            add("3.6", "warn", "passive_voice",
                "Possible passive voice. Use the active voice.", m.group(0),
                "Write the agent as the subject.")
        for m in MUST_IMPERATIVE.finditer(sent):
            if not re.search(r"\b(?:WARNING|CAUTION)\b", sent, re.IGNORECASE):
                add("5.3", "warn", "must_before_verb",
                    "'must' before a verb. Use the imperative form.",
                    m.group(0), "Write the verb as a command.")
        cluster = noun_cluster(words)
        if cluster:
            add("2.1", "warn", "noun_cluster",
                "Possible multi-word noun longer than 3 words.", cluster,
                "Use a preposition or hyphenate the words.")
    return mode, limit, findings


def sentences_with_lines(text):
    for line_no, line in enumerate(text.split("\n"), 1):
        if not line.strip():
            continue
        for _, s in split_sentences(line):
            yield line_no, s


def noun_cluster(words):
    if len(words) < 5:
        return ""
    run = []
    for w in words + [" "]:
        lw = w.lower()
        if (
            lw not in STOPWORDS
            and lw not in BE_VERBS
            and not re.search(r"\d", lw)
            and not lw.endswith("ly")
            and not lw.endswith("ed")
            and re.fullmatch(r"[a-z][a-z'\-]*", lw)
        ):
            run.append(w)
        else:
            if len(run) >= 5:
                return " ".join(run)
            run = []
    return ""


def main():
    ap = argparse.ArgumentParser(description="Check text for ASD-STE100 rule breaks.")
    ap.add_argument("file", nargs="?", default="-")
    ap.add_argument("--mode", choices=["auto", "proc", "desc"], default="auto")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    text = sys.stdin.read() if args.file == "-" else open(args.file, encoding="utf-8").read()
    mode, limit, findings = check(text, args.mode)
    errors = [f for f in findings if f["severity"] == "error"]
    warns = [f for f in findings if f["severity"] == "warn"]
    n_sent = len(list(sentences_with_lines(strip_code(text))))

    if args.json:
        print(json.dumps(
            {"mode": mode, "limit": limit, "sentences": n_sent,
             "errors": len(errors), "warnings": len(warns),
             "findings": findings}, indent=1))
    else:
        print("STE check - mode: {}, sentences: {}, errors: {}, warnings: {}".format(
            mode, n_sent, len(errors), len(warns)))
        if not args.quiet:
            for f in findings:
                tag = "ERROR" if f["severity"] == "error" else "WARN "
                line = "[{}] rule {} ({}): {}  {}  -> {}".format(
                    tag, f["rule"], f["type"], f["message"],
                    ('"' + f["text"] + '"') if f["text"] else "", f["suggestion"])
                print(line)

    sys.exit(1 if errors else 0)


if __name__ == "__main__":
    main()
