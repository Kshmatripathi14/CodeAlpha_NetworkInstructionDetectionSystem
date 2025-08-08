"""
Realtime watcher for Suricata EVE JSON log.
When alerts are seen, optionally block the source IP using iptables.
Requires read access to eve.json and root for iptables blocking.
"""

import argparse
import json
import time
import subprocess
import os

def tail_f(path):
    with open(path, 'r') as f:
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue
            yield line

def block_ip(ip):
    # Check if already blocked (simple)
    check = subprocess.run(['sudo', 'iptables', '-C', 'INPUT', '-s', ip, '-j', 'DROP'],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if check.returncode == 0:
        print(f"[+] {ip} already blocked")
        return
    # Add drop rule
    subprocess.run(['sudo', 'iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'])
    print(f"[!] Blocked IP {ip} via iptables")

def handle_alert(alert, do_block=False):
    src_ip = alert.get('src_ip', 'unknown')
    dest_ip = alert.get('dest_ip', 'unknown')
    signature = alert.get('alert', {}).get('signature', 'no-signature')
    timestamp = alert.get('timestamp', '')
    print(f"[ALERT] {timestamp} {src_ip} -> {dest_ip} : {signature}")
    if do_block and src_ip != 'unknown':
        block_ip(src_ip)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--eve', required=True, help='Path to eve.json')
    parser.add_argument('--block', action='store_true', help='Block source IPs using iptables (requires sudo)')
    args = parser.parse_args()

    print("Starting Suricata EVE watcher...")
    for line in tail_f(args.eve):
        try:
            obj = json.loads(line)
        except Exception as e:
            continue
        # alert events have "alert" key
        if obj.get('event_type') == 'alert' or 'alert' in obj:
            handle_alert(obj, do_block=args.block)

if __name__ == '__main__':
    main()
