import json
import pathlib
from typing import Any, Iterator
from rich.console import Console

from utils import filter_goal_ttps, remap_old_tid, MitreAttack

PULSES_JSON = pathlib.Path(__file__).with_name("alienvault-pulses.json")

console = Console()
print = console.print


def extract_pulses(obj: Any) -> Iterator[dict]:
    if isinstance(obj, list):
        for item in obj:
            if isinstance(item, dict):
                yield item
            else:
                # ignore non-dict list members
                continue
        return

    if isinstance(obj, dict):
        for key in ("results", "pulses", "data", "objects"):
            if key in obj and isinstance(obj[key], list):
                for item in obj[key]:
                    if isinstance(item, dict):
                        yield item
                return

        # fallback: treat the dict itself as a single pulse
        yield obj


class AlienVaultPulse:
    def __init__(self, pulse: dict, mitre_attack: MitreAttack):
        self.pulse = pulse
        self.mitre_attack = mitre_attack

    def find_title(self) -> str:
        for key in ("name", "title", "headline"):
            if key in self.pulse and self.pulse[key]:
                return str(self.pulse[key])
        # fallback to id-like field
        if "id" in self.pulse and self.pulse["id"]:
            return str(self.pulse["id"])
        print(f"    :warning: No title found", style="yellow")
        return ""

    def find_url(self) -> str:
        references = self.pulse.get("references", [])
        if isinstance(references, list) and len(references) > 0:
            return str(references[0])
        print(f"    :warning: No URL found", style="yellow")
        return ""

    def find_date(self) -> str:
        created = self.pulse.get("created")
        if created:
            return created
        print(f"    :warning: No date found", style="yellow")
        return ""

    def find_summary(self) -> str:
        description = self.pulse.get("description", "")
        if description:
            return str(description)
        print(f"    :warning: No summary found", style="yellow")
        return ""

    def find_ttps(self) -> list[dict[str, Any]]:
        ttps = []
        attack_ids = self.pulse.get("attack_ids", [])
        
        if not isinstance(attack_ids, list):
            print(f"    :warning: attack_ids is not a list", style="yellow")
            return []

        for tid in attack_ids:
            tid_str = str(tid)
            tid_str = remap_old_tid(tid_str)
            ttps.append(self.mitre_attack.get_mitre_info(tid_str))

        if len(ttps) == 0:
            print(f"    :warning: No TTPs found", style="yellow")

        return ttps


def main(path: pathlib.Path | None = None) -> int:
    path = pathlib.Path(path) if path else PULSES_JSON
    try:
        with path.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
    except FileNotFoundError:
        print(f"File not found: {path}", style="red")
        return 2
    except json.JSONDecodeError as e:
        print(f"Invalid JSON in {path}: {e}", style="red")
        return 3

    total_ttps = 0
    mitre_attack = MitreAttack()
    reports: list[dict] = []

    for pulse in extract_pulses(data):
        title = AlienVaultPulse(pulse, mitre_attack).find_title()
        print(f":mag: Analyzing {title}", style="bright_black")
        
        av_pulse = AlienVaultPulse(pulse, mitre_attack)
        ttps = av_pulse.find_ttps()
        goals = filter_goal_ttps(ttps)
    
        reports.append({
            "title": title,
            "source": "alienvault",
            "url": av_pulse.find_url(),
            "date": av_pulse.find_date(),
            "summary": av_pulse.find_summary(),
            "mitigations": "",
            "goals": goals,
            "ttps": ttps,
        })
        total_ttps += len(ttps)

    output_file = "alienvault-out.json"
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(reports, f, indent=2)

    print(f"Wrote {len(reports)} pulses to {output_file} with {total_ttps} total TTPs")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

