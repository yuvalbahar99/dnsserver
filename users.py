import logging
import sqlite3
from sqlite3 import Error
from datetime import datetime

USERS_FILE_LOCATION = 'usersinfo.db'


class Users:
    def __init__(self):
        self.db_file = USERS_FILE_LOCATION

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
            users_table = '''CREATE TABLE IF NOT EXISTS users_table (
                                username TEXT PRIMARY KEY,
                                password TEXT NOT NULL      
                            );'''
            conn.execute(users_table)

    def add_user(self, username, password):
        """
        the function adds new row to the table, withe the users name and password
        :param username: the new username to add
        :param password: his password
        :return:
        """
        conn = self.create_connection()
        with conn:
            cursor = conn.cursor()
            cursor.execute("INSERT INTO users_table (username, password) VALUES (?, ?)", (username, password))
            conn.commit()
            logging.debug(username + " User was added")
            self.print_users_table()

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

    def user_is_valid(self, username, password):
        """
        the function checks if the received username and password
        matches to the one on the table.
        if the username do not exist or the password do not match
        the password of the username, return False
        otherwise, return True.
        ** each users have different username
        :param username: the received username
        :param password: the received password
        :return: if user is exist in the users table
        """
        conn = self.create_connection()
        with conn:
            query = "SELECT * FROM users_table WHERE username = ?"
            result = conn.execute(query, (username,)).fetchone()
            if result is None:
                return False
            password_in_table = result[1]

            # להוסיף פה פונקציית האש!!!!

            return password_in_table == password

    def username_already_exist(self, username):
        """
        the function checks if the received username exist in the table
        :param username: the received username
        :return: if username exist in the users table
        """
        print('in')
        conn = self.create_connection()
        print(conn)
        with conn:
            cursor = conn.cursor()
            query = "SELECT * FROM users_table WHERE username = ?"
            cursor.execute(query, (username,))
            result = cursor.fetchone()
            print(result)
            return result is not None

    def print_users_table(self):
        print('got here')
        conn = self.create_connection()
        with conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users_table")
            rows = cursor.fetchall()
            print(rows)
            for row in rows:
                print(row)

    def delete_all_records(self):
        conn = self.create_connection()
        with conn:
            conn.execute("DELETE FROM users_table")
            # logging.info("All records deleted from cache_table")
