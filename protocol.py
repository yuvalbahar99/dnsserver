
class Protocol:
    def __init__(self, message_data):
        self.message_data = message_data

    def add_protocol(self):
        data_len = len(self.message_data)
        data_len = str(data_len)
        new_data_message = 'start' + data_len + '*' + self.message_data
        return new_data_message


