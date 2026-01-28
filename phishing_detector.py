import re
import logging
import json
import os
import sys
import argparse
from abc import ABC, abstractmethod
from typing import List

# --- Logging Setup ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - [%(levelname)s] - %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger(__name__)

# --- Interfaces ---
class PhishingIndicator(ABC):
    @abstractmethod
    def scan(self, email_content: str) -> List[str]:
        pass

# --- Detectors ---
class UrgencyDetector(PhishingIndicator):
    def __init__(self, keywords: List[str]):
        self.keywords = keywords

    def scan(self, email_content: str) -> List[str]:
        findings = []
        upper_content = email_content.upper()
        for keyword in self.keywords:
            if keyword in upper_content:
                findings.append(f"Urgency: '{keyword}'")
        return findings

class SuspiciousLinkDetector(PhishingIndicator):
    def scan(self, email_content: str) -> List[str]:
        findings = []
        ip_pattern = r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
        matches = re.findall(ip_pattern, email_content)
        for match in matches:
            findings.append(f"Suspicious Link: IP Address found ({match})")
        return findings

class SenderSpoofingDetector(PhishingIndicator):
    def __init__(self, protected_domains: List[str]):
        self.protected_domains = protected_domains

    def scan(self, email_content: str) -> List[str]:
        findings = []
        email_pattern = r"[\w\.-]+@([\w\.-]+)"
        found_emails = re.findall(email_pattern, email_content)
        
        for domain in found_emails:
            domain_lower = domain.lower()
            
            is_legit = False
            for brand in self.protected_domains:
                if brand in domain_lower:
                    if f"{brand}.com" in domain_lower or f"{brand}.co" in domain_lower:
                        is_legit = True
                        break
            if is_legit: continue

            normalized = domain_lower.replace('1', 'l').replace('0', 'o').replace('3', 'e').replace('@', 'a').replace('!', 'i')

            for brand in self.protected_domains:
                if brand in normalized and brand not in domain_lower:
                    findings.append(f"Spoofing: '{domain}' -> '{brand}'")
                    
        return findings

# --- Main Engine ---
class PhishingScanner:
    def __init__(self, config_path=None):
        if config_path is None:
            base_dir = os.path.dirname(os.path.abspath(__file__))
            config_path = os.path.join(base_dir, "config.json")
        
        self.config = self._load_config(config_path)
        
        self.detectors = [
            UrgencyDetector(self.config.get("urgency_keywords", [])),
            SuspiciousLinkDetector(),
            SenderSpoofingDetector(self.config.get("protected_domains", []))
        ]

    def _load_config(self, path):
        if not os.path.exists(path):
            logger.warning("Config file not found, using defaults.")
            return {"urgency_keywords": ["URGENT"], "protected_domains": ["paypal"]}
        try:
            with open(path, "r", encoding="utf-8") as f:
                logger.info(f"Loaded rules from {os.path.basename(path)}")
                return json.load(f)
        except: return {}

    def run_scan(self, email_text: str):
        logger.info("Starting heuristic analysis...")
        all_threats = []
        for detector in self.detectors:
            threats = detector.scan(email_text)
            if threats:
                for t in threats:
                    logger.info(f"Detection: {t}")
                all_threats.extend(threats)
        return all_threats

# --- CLI Execution Block ---
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Phishing Intelligence Engine CLI")
    parser.add_argument("file", help="Path to email text file")
    
    if len(sys.argv) < 2:
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args()

    if not os.path.exists(args.file):
        print(f"Error: File '{args.file}' not found.")
        sys.exit(1)

    with open(args.file, "r", encoding="utf-8") as f:
        content = f.read()

    print("\n" + "="*50)
    print(" 🛡️  CYBER PHISHING INTELLIGENCE - CLI MODE")
    print("="*50)
    
    scanner = PhishingScanner()
    threats = scanner.run_scan(content)

    print("\n" + "-"*50)
    print(" 📋 SCAN REPORT")
    print("-"*50)
    
    if threats:
        print(f"❌ STATUS: MALICIOUS (Risk Level: HIGH)")
        print(f"🔍 Findings ({len(threats)}):")
        for i, t in enumerate(threats, 1):
            print(f"   {i}. {t}")
    else:
        print("✅ STATUS: CLEAN")
        print("   No indicators of compromise found.")
    
    print("-"*50 + "\n")