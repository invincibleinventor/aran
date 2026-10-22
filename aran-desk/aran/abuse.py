"""On-device abuse classifier for chat exports and notification text.

Transparent and offline: no model download, no network. Each flag names the pattern
that fired, so a finding can be explained in court. English + Tamil (script and romanised).
A statistical model can replace classify_message() without changing callers.
"""
import re

from . import mlclassifier

# Coercive-control taxonomy. Each category: weight, bilingual label, and patterns.
CATEGORIES = {
    "surveillance": {
        "weight": 0.40,
        "en": "Surveillance — claims to watch her movements or messages",
        "ta": "கண்காணிப்பு — அவள் நடமாட்டத்தையோ செய்திகளையோ கண்காணிப்பதாகக் கூறுதல்",
        "patterns": [
            r"i can see (everything|you|where)", r"i know everything", r"i know (what|who|where) you",
            r"you were at", r"i saw you", r"check panren", r"phone[\s-]?a?\s*check",
            r"where (are|r) (you|u)", r"track(ing)? you", r"your location", r"watching you",
            r"கண்காணி", r"பார்க்கிற", r"செக் பண்ற",
        ],
    },
    "threat": {
        "weight": 0.40,
        "en": "Threat — intimidation or warning of harm",
        "ta": "அச்சுறுத்தல் — தீங்கு விளைவிப்பதாக மிரட்டல்",
        "patterns": [
            r"you will regret", r"regret it", r"or else", r"i('?ll| will) (hurt|kill|find)",
            r"consequence", r"you'?ll pay", r"warn(ing)? you", r"nadakkradhe vera", r"vidamaaten",
            r"அச்சுறுத்த", r"கொல்", r"விடமாட்டேன்",
        ],
    },
    "control": {
        "weight": 0.25,
        "en": "Control — commands, demands or coercion",
        "ta": "கட்டுப்பாடு — கட்டளை, வற்புறுத்தல்",
        "patterns": [
            r"come home now", r"come home", r"don'?t lie", r"answer me", r"right now",
            r"every ?day", r"you have to", r"i told your (mother|amma|parents)", r"amma kitta sonna",
            r"வீட்டுக்கு வா", r"பொய் சொல்லாத", r"உடனே",
        ],
    },
    "isolation": {
        "weight": 0.20,
        "en": "Isolation / jealousy — policing who she talks to",
        "ta": "தனிமைப்படுத்தல் / பொறாமை — அவள் பேசுபவர்களைக் கட்டுப்படுத்துதல்",
        "patterns": [
            r"who is \w+", r"why are you (messaging|texting|talking|calling)",
            r"stop talking to", r"don'?t (talk|message|text) (to )?\w+", r"why (did|are) you with",
            r"யாரு அவன்", r"பேசாத",
        ],
    },
}

# Gendered slurs and profanity. Curated from the AllProfanity Tamil list (github.com/ayush-jadaun/
# AllProfanity, MIT) plus common English, with dictionary-common words (paal=milk, pulla=child,
# maatu=cattle, vetta=cut, sappi, gomiyam) removed to keep false positives low.
SLUR_SCRIPT = ["ஓத்தா", "தேவடியா", "கூதி", "புண்ட", "புண்டை", "பொட்டை", "மயிரு", "சுன்னி",
               "தாயோளி", "ஊம்பு", "பொறுக்கி", "நாறு"]
SLUR_ROMAN = ["otha", "oththa", "ottha", "oththaa", "thevidiya", "thevdiya", "thevadiya",
              "koothi", "kuthi", "koothee", "kooti", "punda", "pundai", "pundek", "pundaik",
              "pottai", "mayiru", "myra", "myru", "sunni", "thayoli", "thayli", "thailee",
              "oombu", "oomba", "porukki", "poriki", "baadu", "soothu", "lavda", "lavadey",
              "pundamavaney", "narakoothi", "thevidiya paiyan", "thevidiya payale",
              "thevadiya paiya", "otha pundai", "dai pundai", "kena punda", "mutta punda",
              "sunni oombu", "pacha thevudiya",
              "fuck", "fucker", "fucking", "motherfucker", "bitch", "slut", "whore",
              "bastard", "asshole", "cunt", "dick", "randi", "bsdk"]
# Mild insults: real but weak; never enough to flag on their own.
SLUR_MILD = ["loosu", "muttaal", "naai", "idiot", "stupid"]

_SLUR_RE = re.compile(r"(?<![\w])(" + "|".join(re.escape(w) for w in SLUR_ROMAN) + r")(?![\w])", re.I)
_MILD_RE = re.compile(r"(?<![\w])(" + "|".join(re.escape(w) for w in SLUR_MILD) + r")(?![\w])", re.I)
_SLUR_LABEL = {"en": "Abusive language — gendered slur or profanity directed at her",
               "ta": "அவதூறு — பாலியல் திட்டு அல்லது கெட்ட வார்த்தை"}

_COMPILED = {c: [re.compile(p, re.I) for p in d["patterns"]] for c, d in CATEGORIES.items()}

# Directed-threat construction: catches violent/sexual threats that carry no slur word,
# e.g. "un kundi la umbrella sorugi paniduven". Fires only when all three co-occur, so an
# anatomical word or a verb on its own never flags. Target + act + first-person future "I will".
_SECOND = re.compile(r"\b(un|unga|unna|unnai|unnoda|unakku|nee|neenga|your|you)\b", re.I)
_FUTURE = re.compile(r"(iduven|iven|uven|duven|ppen|\bpen\b|idven|kuren|iren|panren|pannren|"
                     r"pannuven|panniduven|seiven|seiduven|kolluven|adippen|potten|poduven)", re.I)
_ACT = re.compile(r"(sorug|nuzhai|serthu|utha|kuthu|vettu|kollu|\bkol\b|\bsudu|nasukk|odaikk|"
                  r"udaikk|\bizhu|\bpudi|kizhi|thallu|\badi|kundi|sunni|mulai|\bmola\b|poolu|yoni|"
                  r"கூதி|புண்ட|சுன்னி|குண்டி)", re.I)


# First-person future ("I will …") in English, and harm/consequence words that make a
# directed statement a threat even with no slur or physical verb (intimidation, sextortion).
_ENGFUT = re.compile(r"\b(i\s?will|i['’]?ll|ima|imma|gonna|i\s?am\s?going\s?to|i['’]?m\s?going\s?to)\b", re.I)
_HARM = re.compile(r"(ruin|destroy|finish you|\bend you\b|suffer|\bregret\b|leak|expose|make .*viral|"
                   r"\bviral\b|nude|naked|screenshot|blackmail|\bkill\b|murder|\bhurt\b|\bharm\b|\bbeat\b|"
                   r"\bslap\b|acid|\bburn\b|\bstab\b|strangle|share your|post your|"
                   r"tell your (family|parents|husband|wife|everyone)|come to your (college|office|house|home|work))", re.I)


def _construction(text):
    """A directed threat built from grammar, not from a bad word: target + 'I will' + harm."""
    act = _ACT.search(text)
    harm = act or _HARM.search(text)
    future = _FUTURE.search(text) or _ENGFUT.search(text)
    if harm and future and _SECOND.search(text):
        return [{"category": "threat", "weight": 0.40,
                 "en": "Threat — a directed threat of harm (“I will … to you”)",
                 "ta": "அச்சுறுத்தல் — தீங்கு செய்வதாக நேரடி மிரட்டல்",
                 "match": harm.group(0)}]
    return []


def _slurs(text):
    hits = []
    m = _SLUR_RE.search(text)
    if not m:
        m = next((re.search(re.escape(w), text) for w in SLUR_SCRIPT if w in text), None)
    if m:
        hits.append({"category": "abuse_slur", "weight": 0.45, **_SLUR_LABEL, "match": m.group(0)})
    elif (mm := _MILD_RE.search(text)):
        hits.append({"category": "abuse_mild", "weight": 0.10, "en": "Insulting language",
                     "ta": "இழிவான வார்த்தை", "match": mm.group(0)})
    return hits

# WhatsApp export line: "12/10/26, 10:02 pm - R: Don't lie..."
_LINE = re.compile(r"^(\d{1,2}/\d{1,2}/\d{2,4}),?\s+([\d:\sapm.]+?)\s+-\s+([^:]+?):\s*(.*)$", re.I)
_SELF = {"me", "you", "self"}


def classify_message(text):
    """Return the categories whose patterns match, each with the matched span."""
    hits = []
    for category, patterns in _COMPILED.items():
        for pat in patterns:
            m = pat.search(text)
            if m:
                hits.append({"category": category, "weight": CATEGORIES[category]["weight"],
                             "en": CATEGORIES[category]["en"], "ta": CATEGORIES[category]["ta"],
                             "match": m.group(0)})
                break
    hits += _slurs(text)
    if not any(h["category"] == "threat" for h in hits):
        hits += _construction(text)
    return hits


def _band(score, has_threat):
    if has_threat or score >= 0.60:
        return "HIGH"
    if score >= 0.25:
        return "REVIEW"
    return "NORMAL"


def parse_chat(raw):
    """Parse a WhatsApp .txt export into messages. Continuation lines join the prior message."""
    messages = []
    for line in raw.splitlines():
        m = _LINE.match(line)
        if m:
            _, time, sender, body = m.groups()
            messages.append({"time": time.strip(), "sender": sender.strip(), "text": body.strip()})
        elif messages and line.strip():
            messages[-1]["text"] += " " + line.strip()
    return messages


def _flag(msg, hits, extra=None):
    score = min(1.0, sum(h["weight"] for h in hits))
    entry = {**msg, "score": round(score, 2), "categories": hits,
             "band": _band(score, any(h["category"] == "threat" for h in hits))}
    if extra:
        entry.update(extra)
    return entry


def _model_flag(msg):
    """Flag a message the rules missed when the statistical model is confident it's abusive.
    Opaque by design — labelled 'model' with its confidence, never dressed up as a rule hit."""
    p = mlclassifier.score(msg["text"])
    if p is None or p < mlclassifier.REVIEW:
        return None
    band = "HIGH" if p >= mlclassifier.HIGH else "REVIEW"
    hit = {"category": "model", "weight": round(p, 2),
           "en": f"Model — classifier flagged this as abusive ({p:.0%} confidence)",
           "ta": f"மாதிரி — வன்முறை எனக் கணித்தது ({p:.0%})", "match": ""}
    return {**msg, "score": round(p, 2), "categories": [hit], "band": band, "model_score": round(p, 2)}


def analyse_chat(name, raw):
    """Classify an incoming-message chat. 'Me' lines are the victim and are never flagged.
    A second pass joins consecutive messages from one sender, so a threat split across sends
    ('I will' … 'kill you') is caught even though neither message is abusive alone."""
    messages = parse_chat(raw)
    inc = [m for m in messages if m["sender"].lower() not in _SELF]
    flagged, cats = [], set()
    solo = {}
    for i, msg in enumerate(inc):
        hits = classify_message(msg["text"])
        solo[i] = bool(hits)
        if hits:
            flagged.append(_flag(msg, hits))
            cats.update(h["category"] for h in hits)
        else:
            mf = _model_flag(msg)
            if mf:
                solo[i] = True
                flagged.append(mf)
                cats.add("model")
    for i in range(len(inc) - 1):
        for j in (i + 1, min(i + 2, len(inc) - 1)):
            window = range(i, j + 1)
            if any(solo.get(k) for k in window) or len({inc[k]["sender"] for k in window}) != 1:
                continue
            hits = [h for h in classify_message(" ".join(inc[k]["text"] for k in window))
                    if h["category"] in ("threat", "abuse_slur")]
            if hits:
                flagged.append(_flag(inc[i], hits, {"text": " ".join(inc[k]["text"] for k in window),
                                                    "combined": len(window)}))
                cats.update(h["category"] for h in hits)
                break
    high = sum(1 for f in flagged if f["band"] == "HIGH")
    band = "HIGH" if high else ("REVIEW" if flagged else "NORMAL")
    return {"source": name, "messages": len(messages), "incoming": len(inc), "flagged": flagged,
            "categories": sorted(cats), "band": band, "high_count": high}
