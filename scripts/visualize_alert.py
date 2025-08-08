#!/usr/bin/env python3
"""
Simple visualization of alert counts from alerts.csv
Requires matplotlib.
"""
import argparse
import csv
from collections import Counter
import matplotlib.pyplot as plt

def main():
    p = argparse.ArgumentParser()
    p.add_argument('--csv', required=True, help='CSV produced by extract_alerts.py')
    args = p.parse_args()

    ctr = Counter()
    with open(args.csv, 'r') as f:
        reader = csv.DictReader(f)
        for r in reader:
            sig = r.get('signature','unknown')
            # generalize signature to a short label (first 40 chars)
            ctr[sig[:40]] += 1

    labels = list(ctr.keys())[:10]  # top 10
    values = [ctr[l] for l in labels]

    plt.figure(figsize=(10,6))
    plt.bar(labels, values)
    plt.xticks(rotation=45, ha='right')
    plt.title("Top detected alert signatures (top 10)")
    plt.ylabel("Count")
    plt.tight_layout()
    plt.show()

if __name__ == '__main__':
    main()
