import json
import re
import requests

from bs4 import BeautifulSoup
from mitreattack.stix20 import MitreAttackData
from rich.console import Console
from stix2 import MemoryStore
from typing import Any
from urllib.parse import urljoin

console = Console()
print = console.print

MITRE_ENTERPRISE_ATTACK = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
MITRE_MOBILE_ATTACK = "https://raw.githubusercontent.com/mitre/cti/master/mobile-attack/mobile-attack.json"
MITRE_ICS_ATTACK = "https://raw.githubusercontent.com/mitre/cti/master/ics-attack/ics-attack.json"

TTP_REGEX = r"\b(T\d{4}(?:\.\d{1,3})?)\b"

TID_REMAP = {
    "T1086": "T1059.001",
    "T1155": "T1059.002",
    "T1150": "T1547.011",
    "T1162": "T1547.011",
}

def fetch(url: str, timeout: int = 30) -> str:
    resp = requests.get(url, timeout=timeout)
    resp.raise_for_status()
    return resp.text

def remap_old_tid(tid: str) -> str:
    return TID_REMAP.get(tid, tid)

def filter_goal_ttps(ttps: list[Any]) -> list[Any]:
    goals = []
    for ttp in ttps:
        tactics = ttp["tactics"]
        if "impact" in tactics or "exfiltration" in tactics:
            goals.append(ttp)

    for g in goals:
        ttps.remove(g)

    return goals

class MitreAttack:
    def __init__(self):
        self.data = self.prepare_mitre_attack_data()

    def prepare_mitre_attack_data(self) -> MitreAttackData:
        print(":books: Preparing MITRE ATT&CK data files", style="bright_black")
        mem_store = MemoryStore()

        print("  :inbox_tray: Loading Enterprise", style="bright_black")
        enterprise_json = json.loads(fetch(MITRE_ENTERPRISE_ATTACK))
        mem_store.add(enterprise_json)

        print("  :inbox_tray: Loading Mobile", style="bright_black")
        mobile_json = json.loads(fetch(MITRE_MOBILE_ATTACK))
        mem_store.add(mobile_json)

        print("  :inbox_tray: Loading ICS", style="bright_black")
        ics_json = json.loads(fetch(MITRE_ICS_ATTACK))
        mem_store.add(ics_json)

        return MitreAttackData(src=mem_store)

    def get_mitre_info(self, tid: str) -> dict[str, Any]:
        technique = self.data.get_object_by_attack_id(tid, "attack-pattern")
        if technique:
            if hasattr(technique, "kill_chain_phases"):
                tactics = [t.phase_name for t in technique.kill_chain_phases] # type: ignore
                return {"name": technique.name, "id": tid, "tactics": tactics}
            print(f"    :warning: No tactics found in MITRE attack data: {tid}", style="yellow")
            return {"name": technique.name, "id": tid, "tactics": []}

        name = self.scrape_mitre_name(tid)
        if name:
            print(f"    :warning: Deprecated TTP, no tactics found: {tid}", style="yellow")
            return {"name": name, "id": tid, "tactics": []}
        
        print(f"    :warning: No info found for TTP: {tid}", style="yellow")
        return {"name": "", "id": tid, "tactics": []}
        
    def scrape_mitre_name(self, tid: str) -> str | None:
        # Try a few MITRE ATT&CK technique URL patterns to find a canonical name.
        # Some MITRE technique pages redirect using a client-side meta-refresh; follow those.
        MITRE_BASE = "https://attack.mitre.org"
        candidates = []
        if "." in tid:
            base, sub = tid.split(".", 1)
            sub = sub.zfill(3)
            candidates.append(f"{MITRE_BASE}/techniques/{base}/{sub}/")
            candidates.append(f"{MITRE_BASE}/techniques/{base}/")
        else:
            candidates.append(f"{MITRE_BASE}/techniques/{tid}/")

        max_follow = 5
        for start_url in candidates:
            current_url = start_url
            for _ in range(max_follow):
                try:
                    resp_text = fetch(current_url)
                except requests.HTTPError:
                    break

                s = BeautifulSoup(resp_text, "html.parser")
                # If we have an <h1>, prefer that as the canonical title
                h1 = s.find("h1")
                if h1 and h1.get_text(strip=True):
                    text = h1.get_text(strip=True)
                    return re.sub(r":(?!:)", ": ", text)

                # Look for meta refresh redirects and follow them if present
                meta = s.find("meta")
                if meta and meta.get("content"):
                    content = str(meta.get("content"))
                    murl = re.search(r"url=(.+)$", content, flags=re.I)
                    if murl:
                        target = murl.group(1).strip().strip('"').strip("'")
                        # build absolute URL for relative redirects
                        current_url = urljoin(MITRE_BASE, target)
                        # follow the redirect (loop)
                        continue
                break
        return None
