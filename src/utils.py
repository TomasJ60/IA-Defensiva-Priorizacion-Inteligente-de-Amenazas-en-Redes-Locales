import psycopg2
from config import DB_CONFIG
from osint import consultar_virustotal

def get_db_connection():
    return psycopg2.connect(**DB_CONFIG)
