import datetime
import json
import socket
import logging as log


log.basicConfig(level=log.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def create_auth_token_header(auth_token):
    """
    Création du header d'authentification
    """
     headers = {
            'Accept': 'application/json',
            'Key': self.api_key
        }
    auth_token_header_value = 'Accept ' + auth_token
    auth_token_header = {'Authorization': auth_token_header_value}
    return auth_token_header


def send_to_logstash(data, LOGSTASH_HOST, LOGSTASH_PORT):
    """
    Envoie les données à Logstash via le protocole TCP.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((LOGSTASH_HOST, LOGSTASH_PORT))

        data_str = json.dumps(data)
        sock.sendall(data_str.encode())

        sock.close()
    except Exception as e:
        log.error(f"Error sending data to Logstash: %s", e)
        raise

def save_to_file(fileName, data):
    """
    Sauvegarde les données dans un fichier JSON
    """
    try:
        with open(fileName, 'w', encoding='utf-8') as outfile:
            json.dump(data, outfile)
    except Exception as e:
        log.error(f"Error saving data to file: %s", e)
        raise

def load_from_file(fileName):
    """
    Charge les données à partir d'un fichier JSON
    """
    try:
        with open(fileName, encoding='utf-8') as json_file:
            data = json.load(json_file)
            return data
    except Exception as e:
        log.error(f"Error loading data from file: %s", e)
        raise