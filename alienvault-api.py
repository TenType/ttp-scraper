import csv

from collections import defaultdict

import requests
from dotenv import load_dotenv
from OTXv2 import OTXv2
from OTXv2 import IndicatorTypes
import os

class OTXClient:
    def __init__(self, api_key=None):
        self.api_key = api_key or os.environ.get("OTX_API_KEY")
        if not self.api_key:
            raise ValueError("OTX_API_KEY not provided")
        self.otx = OTXv2(self.api_key)

    def get_indicator_details(self, indicator, indicator_type=IndicatorTypes.IPv4):
        """
        Fetches details about a specific indicator (e.g., IP, domain, URL).

        Args:
            indicator (str): The IOC value.
            indicator_type (str): The type of indicator. Use IndicatorTypes.

        Returns:
            dict: Indicator details.
        """
        result, data = self.otx.get_indicator_details_full(indicator_type, indicator), defaultdict()
        # 1. General Info: reputation
        data['Reputation'] = result.get('general', {}).get('reputation')

        # 2. Pulse Info
        pulses = result.get('general', {}).get("pulse_info", {}).get("pulses", [])
        data['Tags'] = []
        data['Adversaries'] = []
        data['Malware_Families'] = []
        data['Attack_IDs'] = []
        data['Industries'] = []

        for pulse in pulses:
            data['Tags'].extend(pulse.get("tags", []))
            data['Adversaries'].append(pulse.get("adversary", ""))
            data['Malware_Families'].extend(pulse.get("malware_families", []))
            attack_id = []
            for att in pulse.get("attack_ids", []):
                attack_id.append(att.get('id', ''))
            data['Attack_IDs'].extend(attack_id)
            data['Industries'].extend(pulse.get("industries", []))

        for key in ['Tags', 'Adversaries', 'Malware_Families', 'Attack_IDs', 'Industries']:
            data[key] = list(set(filter(None, data[key])))

        # 3. Malware section
        data['Malware_Hashes'] = []
        data['AV_Detections'] = []
        for entry in result.get("malware", {}).get("data", []):
            hash_val = entry.get('hash')
            data['Malware_Hashes'].append(hash_val)
            detections = entry.get('detections', {})
            for engine, label in detections.items():
                if label and label.lower() != "none":
                    data['AV_Detections'].append({
                        'hash': hash_val,
                        'engine': engine,
                        'label': label
                    })

        # 4. Related URLs
        data['Associated_URLs'] = [
            u.get('url') for u in result.get("url_list", {}).get("url_list", [])
            if u.get('url')
        ]
        data['Associated_URLs'] = list(set(data['Associated_URLs']))
    # def extract_domain(self, result, data):
        # 5. Passive DNS
        data['Domains'] = [
            r.get("hostname") for r in result.get("passive_dns", {}).get("passive_dns", [])
            if r.get("hostname")
        ]
        data['Domains'] = list(set(data['Domains']))

        return data

    def get_pulses(self):
        """
        Fetch the latest pulses.

        Returns:
            list: Recent pulses from the OTX community.
        """
        return self.otx.getall()
    
    def get_pulse_by_id(self, id):
        page, csv_file_name, all_indicators = 1, "cl0p_indicators_with_role.csv", []
        full_pulse = self.otx.get_pulse_details(id)

        # print(f"Pulse name: {pulse.get('name')}")
        # print(f"Indicators: {[i['indicator'] for i in pulse.get('indicators', [])]}")
        indicators, all_indicators = full_pulse.get("indicators", []), []

        for indicator in indicators:
            role = indicator.get("role")
            if role:
                all_indicators.append({
                    "pulse_name": full_pulse.get('name'),
                    "indicator": indicator.get("indicator"),
                    "type": indicator.get("type"),
                    "role": role
                })

        # Save to CSV
        with open(csv_file_name, mode='w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=["pulse_name", "indicator", "type", "role"])
            writer.writeheader()
            writer.writerows(all_indicators)

        print(f"Saved {len(all_indicators)} indicators to {csv_file_name}")

    @staticmethod
    def search_pulse_using_url():
        API_KEY = "" # your api key
        SEARCH_TERM = "clop"
        otx = OTXv2(API_KEY)

        page = 1
        all_pulses = []

        while True:
            url = f"https://otx.alienvault.com/api/v1/search/pulses?q={SEARCH_TERM}&page={page}"
            headers = {"X-OTX-API-KEY": API_KEY}

            response = requests.get(url, headers=headers)
            data = response.json()

            pulses = data.get("results", [])
            if not pulses:
                break

            all_pulses.extend(pulses)
            page += 1

        print(f"Found {len(all_pulses)} pulses for '{SEARCH_TERM}'")


    def search_all_pulses_with_keyword(self, keyword):
        page, csv_file_name, all_indicators = 1, "cl0p_indicators_with_role.csv", []


        search_results = self.otx.search_pulses(keyword)
        pulses = search_results.get("results", [])

        for pulse in pulses:
            pulse_id = pulse.get("id")
            pulse_name = pulse.get("name")

            try:
                full_pulse = self.otx.get_pulse_details(pulse_id)
                indicators = full_pulse.get("indicators", [])

                for indicator in indicators:
                    role = indicator.get("role")
                    if role:
                        all_indicators.append({
                            "pulse_name": pulse_name,
                            "indicator": indicator.get("indicator"),
                            "type": indicator.get("type"),
                            "role": role
                        })
            except Exception as e:
                print(f"Failed to fetch pulse {pulse_id}: {e}")

        # Save to CSV
        with open(csv_file_name, mode='w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=["pulse_name", "indicator", "type", "role"])
            writer.writeheader()
            writer.writerows(all_indicators)

        print(f"Saved {len(all_indicators)} indicators to {csv_file_name}")

    def extract_associated_url(self, indicator):
        urls = self.get_section(indicator, IndicatorTypes.IPv4, 'url_list')
        data = defaultdict(set)
        for url_entry in urls.get("url_list", []):
            associated_url = url_entry.get("url")
            if associated_url:
                data['URLs'].add(associated_url)
        return data

    def extract_domain_name(self, indicator):
        dns = self.get_section(indicator, IndicatorTypes.IPv4, 'passive_dns')
        data = defaultdict(set)
        for record in dns.get("passive_dns", []):
            hostname = record.get("hostname")
            if hostname:
                data['Domains'].add(hostname)
        return data

    def get_section(self, indicator, indicator_type, section):
        # this method is too easily rate limited, rather use  full_indicator_details
        data = self.otx.get_indicator_details_by_section(indicator_type, indicator, section=section)
        return data

# Example usage
if __name__ == "__main__":
    load_dotenv()
    client = OTXClient()
    try:
        pulses = client.get_pulses()
        print(pulses)
    except Exception as e:
        print(f"Error extracting data: {e}")
