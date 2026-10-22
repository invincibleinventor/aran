"""Train the Desk abuse classifier.

A calibrated linear model over word + character n-grams. Character n-grams let it
generalise past the lexicon: unseen romanisations ("paniduven" / "panniduven"),
misspellings and tone it was never shown as an exact string. It is the Desk's second
opinion — the on-device rules stay the explainable first pass; this catches what they miss.

Run: python3 model/train.py  ->  writes model/abuse_model.joblib
"""
import os
import random

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split
from sklearn.pipeline import FeatureUnion, Pipeline
import joblib

random.seed(17)

# --- Corpus generators. Each template is filled from slot lists to get volume and
# phrasing variety, so the model learns patterns rather than memorising sentences. ---
TGT = ["un", "unga", "unna", "your", "you", "nee", "unakku"]
NAME = ["Karthik", "Ravi", "Suresh", "him", "your friend", "that guy", "avan"]
FREQ = ["every day", "daily", "ellaa naalum", "every single day", "all the time"]
HARM = ["ruin your life", "end you", "hurt you badly", "destroy you", "finish you off",
        "leak your photos", "kill you", "break your legs", "make your life hell",
        "expose you to everyone", "come to your college", "beat you up"]
TVERB = ["adi", "kollu", "pudi", "sorugi", "nasukki", "odaichi"]
FUT = ["ppen", "uven", "iduven", "ven", "paniduven", "vaippen", "poduven"]
MEDIA = ["photos", "pics", "videos", "private pics", "nudes", "screenshots"]
REL = ["mother", "parents", "amma", "husband", "boss", "whole family"]
OBJ = ["umbrella", "stick", "knife", "rod"]
PLACE = ["college", "office", "house", "work", "hostel"]
SLUR = ["otha", "thevidiya", "punda", "koothi", "mayiru", "thayoli", "bitch", "slut",
        "whore", "randi", "pundamavaney", "sunni oombu", "kena punda"]
COND = ["leave me", "talk to him", "block me", "ignore me", "tell anyone"]

ABUSIVE = []
def add(xs): ABUSIVE.extend(xs)
for _ in range(220):
    add([f"{random.choice(['I will','Im gonna','I am going to','ill'])} {random.choice(HARM)}",
         f"if you {random.choice(COND)} {random.choice(['I will','im gonna'])} {random.choice(HARM)}",
         f"{random.choice(TGT)} kundi la {random.choice(OBJ)} va ulla {random.choice(TVERB)} {random.choice(FUT)}",
         f"{random.choice(TGT)} {random.choice(TVERB)}{random.choice(FUT)} da",
         f"I will leak {random.choice(['your','un'])} {random.choice(MEDIA)} online",
         f"everyone will see your {random.choice(MEDIA)}",
         f"I saw you with {random.choice(NAME)} yesterday",
         f"I know where you are {random.choice(FREQ)}",
         f"phone-a check panren {random.choice(FREQ)}, who is {random.choice(NAME)}?",
         f"stop talking to {random.choice(NAME)} right now",
         f"come home now, answer me, I told your {random.choice(REL)}",
         f"why are you messaging {random.choice(NAME)}, {random.choice(SLUR)}",
         f"you {random.choice(SLUR)}, come here now",
         f"{random.choice(SLUR)} {random.choice(SLUR)}",
         f"come to your {random.choice(PLACE)} and teach you a lesson",
         f"delete his number or {random.choice(['I will','im gonna'])} {random.choice(HARM)}"])

BENIGN = []
def addb(xs): BENIGN.extend(xs)
GREET = ["vanakkam", "hi da", "hello", "good morning", "hey", "nalla iruka?", "how are you"]
TASK = ["meeting at 5 pm", "send me the file", "call me when free", "lets have lunch tomorrow",
        "happy birthday", "congrats on the new job", "did you eat? saapta?", "take care, be safe",
        "I will help you with the project", "Ill pay you back tomorrow", "see you at office",
        "I will call you later", "miss you", "love you too", "proud of you",
        "the bus is late today", "submit the assignment by monday", "lets meet you at 6",
        "I am going to the market", "un photo romba nalla iruku", "thanks for your help",
        "can you share the notes", "I will send the money", "good night sleep well",
        "where should we meet for coffee", "the movie was great da"]
for _ in range(220):
    addb([random.choice(GREET), random.choice(TASK),
          f"{random.choice(GREET)}, {random.choice(TASK)}",
          f"I will {random.choice(['help you','call you','meet you','support you','miss you'])} {random.choice(['today','later','tomorrow',''])}".strip(),
          f"can you {random.choice(['send','share','check'])} the {random.choice(['file','notes','photos','report'])}",
          f"{random.choice(NAME)} is coming to the {random.choice(PLACE)} tomorrow",
          f"please {random.choice(['pay','send'])} the fees before {random.choice(['monday','friday'])}"])

X = ABUSIVE + BENIGN
y = [1] * len(ABUSIVE) + [0] * len(BENIGN)

Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.2, random_state=17, stratify=y)

model = Pipeline([
    ("feat", FeatureUnion([
        ("word", TfidfVectorizer(analyzer="word", ngram_range=(1, 2), min_df=2, sublinear_tf=True)),
        ("char", TfidfVectorizer(analyzer="char_wb", ngram_range=(2, 5), min_df=2, sublinear_tf=True)),
    ])),
    ("clf", LogisticRegression(max_iter=2000, class_weight="balanced", C=4.0)),
])
model.fit(Xtr, ytr)

print(f"corpus: {len(ABUSIVE)} abusive + {len(BENIGN)} benign = {len(X)}")
print(classification_report(yte, model.predict(Xte), target_names=["benign", "abusive"], digits=3))

# Sanity on the hard cases the rules miss or that should stay clean.
probes = ["come to your college and show you what I do", "you will see what happens to you",
          "I will ruin your life", "un kundi la umbrella sorugi paniduven",
          "I will help you move tomorrow", "Ill pay you back, no worries", "I will miss you a lot"]
for p in probes:
    print(f"  {model.predict_proba([p])[0][1]:.2f}  {p}")

out = os.path.join(os.path.dirname(__file__), "abuse_model.joblib")
joblib.dump(model, out)
print("saved", out)
