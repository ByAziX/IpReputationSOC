import pandas as pd
import requests
from collections import Counter
from datetime import datetime

category_mapping = {
    1: "DNS Compromise",
    2: "DNS Poisoning",
    3: "Fraud Orders",
    4: "DDoS Attack",
    5: "FTP Brute-Force",
    6: "Ping of Death",
    7: "Phishing",
    8: "Fraud VoIP",
    9: "Open Proxy",
    10: "Web Spam",
    11: "Email Spam",
    12: "Blog Spam",
    13: "VPN IP",
    14: "Port Scan",
    15: "Hacking",
    16: "SQL Injection",
    17: "Spoofing",
    18: "Brute-Force",
    19: "Bad Web Bot",
    20: "Exploited Host",
    21: "Web App Attack",
    22: "SSH",
    23: "IoT Targeted"
}

class IpBlockedAPI:
    def __init__(self, api_key):
        self.api_key = api_key

    def _make_request(self, url, headers, params=None):
        try:
            response = requests.get(url, headers=headers, params=params)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"Error occurred during API request: {e}")
            return None

    def check_ip_abuse(self, ip):
        url = 'https://api.abuseipdb.com/api/v2/check'
        params = {
            'ipAddress': ip,
            'maxAgeInDays': 90,
            'verbose': True
        }
        headers = {
            'Accept': 'application/json',
            'Key': self.api_key
        }
        return self._make_request(url, headers, params)

    def process_file(self, filename):
        try:
            df = pd.read_excel(filename)
        except FileNotFoundError:
            df = pd.DataFrame(columns=["IP", "isPublic", "isWhitelisted", "abuseConfidenceScore", "countryCode", "usageType", "isp", "domain", "hostnames", "isTor", "totalReports", "numDistinctUsers", "lastReportedAt", "Most_Common_Comment", "Most_Common_Category", "IP_check"])

        ips_to_check = df[df['IP_check'].isna()]['IP'].dropna().unique()

        for ip in ips_to_check:
            abuse_result = self.check_ip_abuse(ip)
            if abuse_result:
                data = abuse_result['data']
                today_date = datetime.today().strftime('%Y-%m-%d')
                
                comments = [report["comment"] for report in data.get("reports", [])]
                categories = [category for report in data.get("reports", []) for category in report.get("categories", [])]

                most_common_comment = Counter(comments).most_common(1)[0][0] if comments else "None"
                most_common_category_num = Counter(categories).most_common(1)[0][0] if categories else "None"
                most_common_category = category_mapping.get(most_common_category_num, "Unknown Category")

                ip_data = {
                    "blocage_date": today_date,
                    "IP": data.get("ipAddress"),
                    "isWhitelisted": data.get("isWhitelisted"),
                    "abuseConfidenceScore": data.get("abuseConfidenceScore"),
                    "countryCode": data.get("countryCode"),
                    "countryName": data.get("countryName"),
                    "usageType": data.get("usageType"),
                    "isp": data.get("isp"),
                    "domain": data.get("domain"),
                    "isTor": data.get("isTor"),
                    "totalReports": data.get("totalReports"),
                    "numDistinctUsers": data.get("numDistinctUsers"),
                    "lastReportedAt": data.get("lastReportedAt"),
                    "Most_Common_Comment": most_common_comment,
                    "Most_Common_Category": most_common_category,
                    "IP_check": True
                }

                existing_entry = df[df['IP'] == ip]
                if existing_entry.empty:
                    df = df.append(ip_data, ignore_index=True)
                else:
                    idx = existing_entry.index[0]
                    for key, value in ip_data.items():
                        df.at[idx, key] = value

        df['IP_check'] = df['IP_check'].astype(bool)
        df.to_excel(filename, index=False)

api_key = '79e4fd6e9853cd458888772dec91df33befc0880df1645fafebbffc594eea91c5140e1d9fd7009e9'  
filename = 'ip_blocked.xlsx'

ip_blocked_api = IpBlockedAPI(api_key)

ip_blocked_api.process_file(filename)

print("Excel file has been updated.")