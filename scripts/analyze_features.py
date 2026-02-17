"""Deep analysis of feature quality"""
import pandas as pd

df = pd.read_csv('balanced_features.csv')
features = df.drop(['url','label'], axis=1)
phish = df[df.label==1]
legit = df[df.label==0]

print("=" * 70)
print("FEATURE QUALITY ANALYSIS")
print("=" * 70)

print(f"\nTotal: {len(df)} | Phishing: {len(phish)} | Legit: {len(legit)}")

print(f"\n{'Feature':<30s} {'Uniq':>4s} {'Phish=1%':>8s} {'Legit=1%':>8s} {'Diff':>6s}  {'Verdict'}")
print("-" * 85)

useful = 0
useless = 0
for col in features.columns:
    nuniq = features[col].nunique()
    p1 = (phish[col]==1).mean()*100
    l1 = (legit[col]==1).mean()*100
    diff = abs(p1 - l1)
    if nuniq <= 1:
        verdict = "DEAD (always same)"
        useless += 1
    elif diff > 5:
        verdict = "GOOD"
        useful += 1
    elif diff > 2:
        verdict = "weak"
        useful += 1
    else:
        verdict = "NO SIGNAL"
        useless += 1
    print(f"{col:<30s} {nuniq:>4d} {p1:>7.1f}% {l1:>7.1f}% {diff:>5.1f}%  {verdict}")

print(f"\nUseful features: {useful}")
print(f"Useless features: {useless}")
