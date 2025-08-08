#!/usr/bin/env python3
"""
Parse eve.json and produce a CSV of alerts for reporting.
Columns: timestamp, src_ip, dest_ip, proto, signature, priority
"""
import argparse
import json
import csv

def parse(eve_path, out_csv):
    with open(eve_path, 'r') as f, open(out_csv, 'w', newline='') as out:
        writer = csv.writer(out)
        writer.writerow(['timestamp','src_ip','dest_ip','proto','signature','priority'])
        for line in f:
            try:
                j = json.loads(line)
            except:
                continue
            if 'alert' in j:
                ts = j.get('timestamp','')
                src = j.get('src_ip','')
                dst = j.get('dest_ip','')
                proto = j.get('proto','')
                sig = j.get('alert',{}).get('signature','')
                prio = j.get('alert',{}).get('priority','')
                writer.writerow([ts,src,dst,proto,sig,prio])
    print(f"Saved alerts to {out_csv}")

if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('--eve', required=True)
    p.add_argument('--out', required=True)
    args = p.parse_args()
    parse(args.eve, args.out)
