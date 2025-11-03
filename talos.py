import json
import re

from pathlib import Path
from typing import Any, Iterator
from rich.console import Console
from bs4 import BeautifulSoup

from utils import fetch, filter_goal_ttps, remap_old_tid, MitreAttack, TTP_REGEX

BASE_URL = "https://raw.githubusercontent.com/Cisco-Talos/IOCs/refs/heads/main"
TALOS_BLOG_REGEX = r"""(?:https?://)?blog\.talosintelligence\.com(?:/[^\s'"\)\]\}>,.;:]*)?"""

console = Console()
print = console.print

def yield_talos_ioc_jsons(talos_root: Path) -> Iterator[tuple[str, Any]]:
    root = Path(talos_root).resolve()
    if not root.exists() or not root.is_dir():
        return

    # Deterministic ordering makes results predictable in tests and CLIs
    for path in sorted(root.rglob("*.json")):
        if not path.is_file():  # defensive, though rglob("*.json") should already be files
            continue

        rel = path.relative_to(root).as_posix()
        url = f"{BASE_URL}/{rel}"
        text = path.read_text(encoding="utf-8")
        obj = json.loads(text)

        yield url, obj

class TalosReport:
    def __init__(self, url: str, contents: Any, mitre_attack: MitreAttack):
        self.url = url
        self.contents = contents
        self.mitre_attack = mitre_attack

    def get_nested(self, dictn, keys: list[str], default=None):
        d = dictn
        for key in keys:
            if key == "[0]" and len(d) > 0:
                d = d[0]
            elif isinstance(d, dict) and key in d:
                d = d[key]
            else:
                return default
        return d
    
    def format_url(self, url: str) -> str:
        if not isinstance(url, str) or url.strip() == "":
            return url

        # Match optional scheme, host, and path
        m = re.match(r'^(?:https?://)?(?P<host>blog\.talosintelligence\.com)(?P<path>/.*)?$', url)
        if not m:
            # If it doesn't look like the Talos blog host, just ensure https and return
            if url.startswith("http://"):
                return "https://" + url.split("http://", 1)[1]
            if not url.startswith("https://"):
                return f"https://{url}"
            return url

        host = m.group("host")
        path = m.group("path") or ""

        # Remove leading date segment /YYYY/MM/ if present
        date_seg = re.match(r"^/(\d{4})/(\d{2})(?P<rest>/.*)?$", path)
        if date_seg:
            rest = date_seg.group("rest") or ""
            normalized_path = rest
        else:
            normalized_path = path

        # Ensure we return https://host + normalized_path
        return f"https://{host}{normalized_path}"

    def find_title(self) -> str:
        # Has the format { "type": "bundle", ... }
        objects = self.contents.get("objects")
        if objects is not None:
            for obj in objects:
                if obj.get("type") == "report":
                    return obj.get("name")

        # Has the format { "id": ... }
        title = self.get_nested(self.contents, [
            "related_packages",
            "related_packages",
            "[0]",
            "package",
            "incidents",
            "[0]",
            "title",
        ])

        if title is not None:
            return title
        
        # Has the format { "response": ... } (reddriver.json)
        title = self.get_nested(self.contents, [
            "response",
            "[0]",
            "Event",
            "info",
        ])

        if title is not None:
            return title
        
        print(f"    :warning: No title found", style="red")
        return ""
    
    def find_url(self) -> str:
        text = json.dumps(self.contents)
        matches = re.findall(TALOS_BLOG_REGEX, text)
        if len(matches) == 1:
            return self.format_url(matches[0])
        if len(matches) > 1:
            print(f"    :warning: More than one URL found, only capturing the first", style="yellow")
            return self.format_url(matches[0])
                    
        print(f"    :warning: No URL found", style="yellow")
        return ""

    def find_date(self) -> str:
        # Has the format { "type": "bundle", ... }
        objects = self.contents.get("objects")
        if objects is not None:
            for obj in objects:
                if obj.get("type") == "identity":
                    return obj.get("created")
                
        # Has the format { "id": ... }
        timestamp = self.contents.get("timestamp")
        if timestamp is not None:
            return timestamp
        
        # Has the format { "response": ... } (reddriver.json)   
        timestamp = self.get_nested(self.contents, [
            "response",
            "[0]",
            "Event",
            "date",
        ])
        if timestamp is not None:
            return timestamp
                
        print(f"    :warning: No date found", style="red")
        return ""
    
    def find_ttps(self) -> list[dict[str, Any]]:
        ttps = []
        
        # Has the format { "type": "bundle", ... }
        objects = self.contents.get("objects")
        if objects is not None:
            for obj in objects:
                if obj.get("type") == "attack-pattern":
                    ttp_text = obj.get("name")
                    if ttp_text is None:
                        continue
                    tids = re.findall(TTP_REGEX, ttp_text)
                    if len(tids) == 0:
                        continue
                    tid = remap_old_tid(tids[0])
                    ttps.append(self.mitre_attack.get_mitre_info(tid))

        if len(ttps) > 0:
            return ttps
        
        # Has the format { "id": ... }
        ttp_objects = self.get_nested(self.contents, [
            "related_packages",
            "related_packages",
            "[0]",
            "package",
            "ttps",
            "ttps",
        ])
        if ttp_objects is not None:
            for obj in ttp_objects:
                ttp_text = self.get_nested(obj, [
                    "behavior",
                    "attack_patterns",
                    "[0]",
                    "title"
                ])
                if ttp_text is None:
                    continue
                tids = re.findall(TTP_REGEX, ttp_text)
                if len(tids) == 0:
                    continue
                tid = remap_old_tid(tids[0])
                ttps.append(self.mitre_attack.get_mitre_info(tid))
        
        if len(ttps) > 0:
            return ttps

        # Has the format { "response": ... } (reddriver.json)   
        ttp_objects = self.get_nested(self.contents, [
            "response",
            "[0]",
            "Event",
            "Galaxy",
            "[0]",
            "GalaxyCluster",
        ])
        if ttp_objects is not None:
            for obj in ttp_objects:
                ttp_text = obj.get("value")
                if ttp_text is None:
                    continue
                tids = re.findall(TTP_REGEX, ttp_text)
                if len(tids) == 0:
                    continue
                tid = remap_old_tid(tids[0])
                ttps.append(self.mitre_attack.get_mitre_info(tid))

        if len(ttps) > 0:
            return ttps
        
        # Last resort: regex search the entire text for TTPs
        text = json.dumps(self.contents)
        for tid in re.findall(TTP_REGEX, text):
            tid = remap_old_tid(tid)
            ttps.append(self.mitre_attack.get_mitre_info(tid))
        if len(ttps) > 0:
            return ttps
        
        print(f"    :warning: No TTPs found", style="yellow")
        return []
          
    def scrape_summary(self, url: str) -> str:
        try:
            html = fetch(url)
        except Exception as e:
            if "404" in str(e):
                print(f"    :warning: Summary not found: URL returned a 404 error", style="yellow")
            else:
                print(f"    :warning: Summary not found: {e}", style="red")
            return ""

        soup = BeautifulSoup(html, "html.parser")

        # Try to find the main article/container first
        content = None
        # Prefer <article>
        content = soup.find("article")
        if content is None:
            # Look for common content container class names
            content = soup.find(
                "div",
                class_=re.compile(r"(entry|post|article|content|post-body)", flags=re.I),
            )
        if content is None:
            # Fallback to <main>
            content = soup.find("main")

        # 1) Look for a UL with multiple LIs near top of the content
        if content:
            ul = content.find("ul")
            if ul:
                lis = [li.get_text(strip=True) for li in ul.find_all("li") if li.get_text(strip=True)]
                if len(lis) >= 1:
                    return "\n".join(lis)

        # 2) Search the whole page for the first UL with multiple LIs
        for ul in soup.find_all("ul"):
            lis = [li.get_text(strip=True) for li in ul.find_all("li") if li.get_text(strip=True)]
            if len(lis) >= 1:
                return "\n".join(lis)

        # 3) Fallback to first few paragraph texts inside the content or page
        paragraphs = []
        if content:
            paragraphs = [p.get_text(strip=True) for p in content.find_all("p") if p.get_text(strip=True)]
        if not paragraphs:
            paragraphs = [p.get_text(strip=True) for p in soup.find_all("p") if p.get_text(strip=True)]

        if paragraphs:
            # Return first up to 7 paragraphs joined by newline
            return "\n".join(paragraphs[:7])

        return ""


def main():
    root = Path(__file__).parent / "talos-iocs"
    total_ttps = 0
    mitre_attack = MitreAttack()
    reports: list[dict] = []

    for url, contents in yield_talos_ioc_jsons(root):
        print(f":mag: Analyzing {url}", style="bright_black")
        talos_report = TalosReport(url, contents, mitre_attack)
        ttps = talos_report.find_ttps()
        goals = filter_goal_ttps(ttps)
        url = talos_report.find_url()
        reports.append({
            "title": talos_report.find_title(),
            "source": "talos",
            "url": url,
            "date": talos_report.find_date(),
            "summary": "" if url == "" else talos_report.scrape_summary(url),
            "mitigations": "",
            "goals": goals,
            "ttps": ttps,
        })
        total_ttps += len(ttps)

    output_file = "talos-out.json"
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(reports, f, indent=2)

    print(f"Wrote {len(reports)} matching reports to {output_file} with {total_ttps} total TTPs")


if __name__ == "__main__":
    main()

