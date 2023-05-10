import logging
import sqlite3
from sqlite3 import Error
from datetime import datetime
# import logging

CACHE_FILE_LOCATION = 'cacheinfo.db'
# FORMAT = '%(asctime)s %(levelname)s %(threadName)s %(message)s'
# FILENAMELOG = 'cachelog.log'


class Cache:
    def __init__(self):
        self.db_file = CACHE_FILE_LOCATION

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
                                ttl TEXT NOT NULL,
                                type TEXT NOT NULL             
                            );'''
            conn.execute(cache_table)

    def insert_row(self, ip, domain, ttl, type):
        self.delete_expired_records()
        conn = self.create_connection()
        with conn:
            cursor = conn.cursor()
            cursor.execute("INSERT INTO cache_table (ip, domain, ttl, type) VALUES (?, ?, ?, ?)",
                           (ip, domain, ttl, type))
            conn.commit()
            # logging.debug("Row inserted")

    """
    def validate_?(self, username, password):
        conn = self.create_connection()
        with conn:
            query = "SELECT * FROM users WHERE username = ? AND password = ?"
            result = conn.execute(query, (username, password)).fetchone()
            return result is not None
    
    def check_ip_exists(self, ip):
        self.delete_expired_records()
        conn = self.create_connection()
        with conn:
            cursor = conn.cursor()
            query = "SELECT * FROM cache_table WHERE ip = ?"
            cursor.execute(query, (ip,))
            result = cursor.fetchone()
            if result is not None:
                # logging.debug(ip + "exist in cache")
                return True
            # logging.debug(ip + "does not exist in cache")
            return False

    def check_domain_exists(self, domain):
        self.delete_expired_records()
        conn = self.create_connection()
        with conn:
            cursor = conn.cursor()
            query = "SELECT * FROM cache_table WHERE domain = ?"
            cursor.execute(query, (domain,))
            result = cursor.fetchone()
            if result is not None:
                # logging.debug(domain + "exist in cache")
                return True
            # logging.debug(domain + "does not exist in cache")
            return False
    """

    def get_ip_info(self, ip):
        self.delete_expired_records()
        conn = self.create_connection()
        with conn:
            query = "SELECT * FROM cache_table WHERE ip = ?"
            result = conn.execute(query, (ip,)).fetchone()
            return result

    def get_domain_info(self, domain):
        self.delete_expired_records()
        conn = self.create_connection()
        with conn:
            query = "SELECT * FROM cache_table WHERE domain = ?"
            result = conn.execute(query, (domain,)).fetchone()
            return result

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
        self.delete_expired_records()
        conn = self.create_connection()
        with conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM cache_table")
            rows = cursor.fetchall()
            for row in rows:
                print(row)

    def delete_all_records(self):
        conn = self.create_connection()
        with conn:
            conn.execute("DELETE FROM cache_table")
            # logging.info("All records deleted from cache_table")