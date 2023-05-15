import logging

TTL = '2123-05-16 18:17:23.198305'
IP = '1.2.3.4'
TYPE = '1'


class ParentalControl:
    def __init__(self, cache):
        self.cache = cache

    def add_blocking(self, domain):
        self.cache.delete_expired_records()
        conn = self.cache.create_connection()
        with conn:
            cursor = conn.cursor()
            if self.cache.get_domain_info(domain):
                self.cache.delete_row(domain)
            self.cache.insert_row(IP, domain, TTL, TYPE)
            conn.commit()
            logging.debug("Row inserted- " + domain)
        self.cache.print_cache_table()

    def remove_blocking(self, domain):
        conn = self.cache.create_connection()
        with conn:
            if self.cache.get_domain_info(domain):
                self.cache.delete_row(domain)
                logging.debug('Deleted blocking- ' + domain)
        self.cache.print_cache_table()

    def return_block_list(self):
        conn = self.cache.create_connection()
        blocked_list = []
        with conn:
            cursor = conn.cursor()
            query = "SELECT * FROM cache_table WHERE ttl = ?"  # התאם את TTL לערך ה-X שלך
            cursor.execute(query, (TTL,))
            rows = cursor.fetchall()
            for row in rows:
                blocked_list.append(row[2])
        return blocked_list