import sqlite3
from sqlite3 import Error
import logging
from datetime import datetime

DB_FILE_LOCATION = 'C:\\Users\\yuval\\OneDrive\\Desktop\\11th grade\\cyber\\dnsserver\\cacheinfo.db'
FORMAT = '%(asctime)s %(levelname)s %(threadName)s %(message)s'
FILENAMELOG = 'cachelog.log'


class Cache:
    def __init__(self):
        self.db_file = DB_FILE_LOCATION

    def create_connection(self):
        conn = None
        try:
            conn = sqlite3.connect(self.db_file)
        except Error as e:
            print(e)
        return conn

    def create_tables(self):
        conn = self.create_connection()
        with conn:
            cache_table = '''CREATE TABLE IF NOT EXISTS cache_table (
                             id INTEGER PRIMARY KEY AUTOINCREMENT,
                             ip TEXT NOT NULL,
                             domain TEXT NOT NULL,
                             ttl INTEGER NOT NULL,
                             type TEXT NOT NULL                        
                        );'''
            conn.execute(cache_table)

    def insert_row(self, ip, domain, ttl, type):
        conn = self.create_connection()
        with conn:
            cursor = conn.cursor()
            cursor.execute("INSERT INTO cache_table (ip, domain, ttl, type) VALUES (?, ?, ?, ?)",
                           (ip, domain, ttl, type))
            conn.commit()
            logging.debug("Row inserted")

    """
    def validate_user(self, username, password):
        conn = self.create_connection()
        with conn:
            query = "SELECT * FROM users WHERE username = ? AND password = ?"
            result = conn.execute(query, (username, password)).fetchone()
            return result is not None
    """

    def check_ip_exists(self, ip):
        conn = self.create_connection()
        with conn:
            cursor = conn.cursor()
            query = "SELECT * FROM cache_table WHERE ip = ?"
            cursor.execute(query, (ip,))
            result = cursor.fetchone()
            if result is not None:
                logging.debug(ip + "exist in cache")
                return True
            logging.debug(ip + "does not exist in cache")
            return False

    def check_domain_exists(self, domain):
        conn = self.create_connection()
        with conn:
            cursor = conn.cursor()
            query = "SELECT * FROM cache_table WHERE domain = ?"
            cursor.execute(query, (domain,))
            result = cursor.fetchone()
            if result is not None:
                logging.debug(domain + "exist in cache")
                return True
            logging.debug(domain + "does not exist in cache")
            return False

    def get_ip_info(self, ip):
        if self.check_ip_exists(ip):
            conn = self.create_connection()
            with conn:
                cursor = conn.cursor()
                query = "SELECT * FROM cache_table WHERE ip = ?"
                conn.execute(query, (ip,))
                result = cursor.fetchone()
                return result
        return None

    def get_domain_info(self, domain):
        if self.check_domain_exists(domain):
            conn = self.create_connection()
            with conn:
                cursor = conn.cursor()
                query = "SELECT * FROM cache_table WHERE domain = ?"
                conn.execute(query, (domain,))
                result = cursor.fetchone()
                return result
        return None

    def delete_expired_records(self):
        conn = self.create_connection()
        with conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id, ttl FROM cache_table")
            rows = cursor.fetchall()
            current_time = datetime.now()
            for row in rows:
                row_id, row_ttl = row
                row_ttl = datetime.strptime(row_ttl, '%Y-%m-%d %H:%M:%S.%f')
                if row_ttl < current_time:
                    cursor.execute("DELETE FROM cache_table WHERE id = ?", (row_id,))
            conn.commit()

    def print_cache_table(self):
        conn = self.create_connection()
        with conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM cache_table")
            rows = cursor.fetchall()
            for row in rows:
                print(row)


if __name__ == '__main__':
    logging.basicConfig(filename=FILENAMELOG, level=logging.DEBUG, format=FORMAT)