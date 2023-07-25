import requests
import statistics
import os
import re
import json

class IpReputationAPI:
    def __init__(self, api_key, vt_api_key):
        self.api_key = api_key
        self.vt_api_key = vt_api_key
        self.abuse_confidence_scores = []
        self.abuse_report_counts = []

    def _make_request(self, url, headers):
        try:
            response = requests.get(url, headers=headers)
            response.raise_for_status()  # Raises an exception for 4xx and 5xx status codes
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"Error occurred during API request: {e}")
            return None

    def check_ip_abuse(self, ip):
        url = f'https://api.abuseipdb.com/api/v2/check?ipAddress={ip}'
        headers = {
            'Accept': 'application/json',
            'Key': self.api_key
        }
        result = self._make_request(url, headers)
        if result:
            self.abuse_confidence_scores.append(result['data']['abuseConfidenceScore'])
            self.abuse_report_counts.append(result['data']['totalReports'])
        return result

    def check_ip_vt(self,url):
        url = url
        headers = {
            'x-apikey': self.vt_api_key
        }
        return self._make_request(url, headers)

    def extract_ips_from_file(self, filename):
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'  # Motif regex pour rechercher les adresses IP
        ips = []

        with open(filename, 'r') as file:
            for line in file:
                ip_matches = re.findall(ip_pattern, line)
                ips.extend(ip_matches)

        return ips

    def process_file(self, filename, output_filename, backup_filename):
        ips = self.extract_ips_from_file(filename)  # Récupérer les adresses IP du fichier

        results = [] 

        for ip in ips:
            abuse_result = self.check_ip_abuse(ip)
            vt_result = self.check_ip_vt("https://www.virustotal.com/api/v3/ip_addresses/"+ip)
            vt_result_files = self.check_ip_vt("https://www.virustotal.com/api/v3/ip_addresses/"+ip+"/relationships/communicating_files")

            ip_data = {}  # Dictionnaire pour stocker les informations de l'adresse IP

            try:
                abuse_confidence_score = abuse_result['data']['abuseConfidenceScore']
                abuse_report_count = abuse_result['data']['totalReports']

                self.abuse_confidence_scores.append(abuse_confidence_score)
                self.abuse_report_counts.append(abuse_report_count)

                ip_data['ip'] = ip
                ip_data['abuseIPDB'] = {
                    'score': abuse_confidence_score,
                    'country': abuse_result['data']['countryCode'],
                    'domain': abuse_result['data']['domain'],
                    'isp': abuse_result['data']['isp'],
                    'reports': abuse_report_count
                }

                if abuse_confidence_score >= 50 and abuse_report_count >= 10:
                    ip_data['abuseIPDB']['status'] = 'malveillante'
                else:
                    ip_data['abuseIPDB']['status'] = 'non malveillante'
            except (TypeError, KeyError):
                ip_data['abuseIPDB'] = {
                    'status': 'erreur'
                }

            try:
                vt_malicious_count = vt_result['data']['attributes']['last_analysis_stats']['malicious']
                
                ip_data['virusTotal'] = {
                    'malicious_count': vt_malicious_count
                }

                if vt_malicious_count > 0:
                    ip_data['virusTotal']['status'] = 'malveillante'
                else:
                    ip_data['virusTotal']['status'] = 'non malveillante'
            except (TypeError, KeyError):
                ip_data['virusTotal'] = {
                    'status': 'erreur'
                }

            results.append(ip_data)  # Ajouter le dictionnaire de l'adresse IP aux résultats

        with open(output_filename, 'w') as output_file, open(backup_filename, 'w') as backup_file:
            json.dump(results, output_file, indent=2)  # Écrire les résultats au format JSON dans le fichier de sortie
            json.dump(results, backup_file, indent=2)  # Écrire les résultats au format JSON dans le fichier de sauvegarde

        # Calculer le seuil dynamique
        confidence_threshold, report_threshold = self.calculate_dynamic_threshold()

        if confidence_threshold is not None and report_threshold is not None:
            print(f"Seuil dynamique pour la confiance d'abus : {confidence_threshold}")
            print(f"Seuil dynamique pour le nombre de rapports d'abus : {report_threshold}")
        else:
            print("Il n'y a pas assez de données pour calculer un seuil dynamique.")

    def calculate_dynamic_threshold(self):
        if not self.abuse_confidence_scores or not self.abuse_report_counts:
            return None

        # Calculer la moyenne et l'écart type des valeurs de confiance d'abus et de rapports d'abus
        confidence_mean = statistics.mean(self.abuse_confidence_scores)
        confidence_stddev = statistics.stdev(self.abuse_confidence_scores)
        report_mean = statistics.mean(self.abuse_report_counts)
        report_stddev = statistics.stdev(self.abuse_report_counts)

        # Définir le seuil comme étant la moyenne moins un écart type pour la confiance d'abus
        # et la moyenne plus un écart type pour le nombre de rapports d'abus
        confidence_threshold = confidence_mean - confidence_stddev
        report_threshold = report_mean + report_stddev

        return confidence_threshold, report_threshold

# Clés d'API-
api_key = 'c0de62e930d896074fa8b8a2d6ada9af39584c2406e7d14594a01f455004bc0d7cbfccaf557dcf31'  
vt_api_key = '468c05938613dc576ecb90a6b015bdcf78417884e65afa66618994be749638f3'

# Noms de fichiers
filename = 'ip_addresses.txt'
output_filename = 'ip_results.json'
backup_filename = 'ip_results_backup.json'

# Créer une instance de la classe IpReputationAPI
ip_reputation_api = IpReputationAPI(api_key, vt_api_key)

# Traiter le fichier et vérifier les adresses IP
ip_reputation_api.process_file(filename, output_filename, backup_filename)

print(f"Les résultats ont été enregistrés dans le fichier {output_filename}.")
print(f"Une copie de sauvegarde des résultats a été enregistrée dans le fichier {backup_filename}.")
