import json
import uuid
import sys
from stix2 import Indicator, Bundle
from datetime import datetime
import os

def log_status(message):
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {message}")

def create_stix_bundle(ip_file, domain_file):
    objects = []

    # Processing IPs
    if os.path.exists(ip_file):
        log_status(f"Reading IP addresses from {ip_file}...")
        with open(ip_file, 'r') as f:
            ips = [line.strip() for line in f if line.strip()]
            log_status(f"Found {len(ips)} IP addresses.")
            for ip in ips:
                objects.append(Indicator(
                    id=f"indicator--{uuid.uuid4()}",
                    pattern=f"[ipv4-addr:value = '{ip}']",
                    pattern_type="stix",
                    valid_from=datetime.now(),
                    labels=["malicious-activity", "pig-butchering"],
                    description="Pig Butchering scam infrastructure (IP)"
                ))
    else:
        log_status(f"Warning: {ip_file} not found. Skipping.")

    # Processing Domains
    if os.path.exists(domain_file):
        log_status(f"Reading domains from {domain_file}...")
        with open(domain_file, 'r') as f:
            domains = [line.strip() for line in f if line.strip()]
            log_status(f"Found {len(domains)} domains.")
            for domain in domains:
                objects.append(Indicator(
                    id=f"indicator--{uuid.uuid4()}",
                    pattern=f"[domain-name:value = '{domain}']",
                    pattern_type="stix",
                    valid_from=datetime.now(),
                    labels=["malicious-activity", "pig-butchering"],
                    description="Pig Butchering scam infrastructure (Domain)"
                ))
    else:
        log_status(f"Warning: {domain_file} not found. Skipping.")

    log_status(f"Packaging {len(objects)} indicators into STIX 2.1 bundle...")
    bundle = Bundle(objects=objects)
    return bundle.serialize(indent=4)

if __name__ == "__main__":
    log_status("Starting STIX 2.1 conversion process...")

    try:
        stix_data = create_stix_bundle('ips.txt', 'domains.txt')

        output_file = 'pig_butchering_threats.json'
        with open(output_file, 'w') as f:
            f.write(stix_data)

        log_status(f"Process completed successfully.")
        log_status(f"Output saved to: {output_file}")

    except Exception as e:
        log_status(f"Critical Error: {str(e)}")
        sys.exit(1)
