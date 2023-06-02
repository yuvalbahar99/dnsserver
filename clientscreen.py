import logging
import socket
import subprocess
import tkinter as tk
from tkinter import filedialog
from tkinter import messagebox
from tkinter import StringVar
from PIL import Image, ImageTk
from protocol import Protocol

SERVER_IP = '10.0.0.23'
# SERVER_IP = "172.16.15.49"
PORT = 80
PC_FILE_PATH = 'pcimage.jpeg'


class FirstScreen:
    def __init__(self):
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_socket.connect((SERVER_IP, PORT))

        self.root = tk.Tk()
        self.root.title("parental control")
        # הגדרת המסך בגודל מלא
        self.root.geometry("{0}x{1}+0+0".format(self.root.winfo_screenwidth(), self.root.winfo_screenheight()))

        self.root.protocol("WM_DELETE_WINDOW", self.close_first_screen)

        self.logo_img = Image.open(PC_FILE_PATH)
        self.logo_photo = ImageTk.PhotoImage(self.logo_img)

        self.background_label = tk.Label(self.root, image=self.logo_photo)
        self.background_label.place(x=0, y=0, relwidth=1, relheight=1)

        self.sign_up_button = tk.Button(self.root, text="  Sign Up  ", command=self.open_sign_up_screen)
        self.sign_up_button.place(relx=0.5, rely=0.45, anchor="center")

        self.log_in_button = tk.Button(self.root, text="  Log In  ", command=self.open_log_in_screen)
        self.log_in_button.place(relx=0.5, rely=0.40, anchor="center")

    def open_sign_up_screen(self):
        self.root.withdraw()  # הסתרת החלון הראשי
        signup_screen = SignUpScreen(self)  # יצירת מסך הרשמה חדש

    def close_sign_up_screen(self):
        self.root.deiconify()  # הצגת החלון הראשי
        self.root.focus_force()  # כניסה לחלון הראשי

    def open_log_in_screen(self):
        self.root.withdraw()
        login_screen = LogInScreen(self)  # יצירת מסך התחברות חדש

    def close_log_in_screen(self):
        self.root.deiconify()
        self.root.focus_force()

    def run(self):
        self.root.mainloop()

    def close_first_screen(self):
        message = 'C'
        protocol = Protocol(message)
        message = protocol.add_protocol()
        self.client_socket.send(message.encode())
        self.client_socket.close()
        self.root.destroy()  # סגירת החלון הראשי


class SignUpScreen:
    def __init__(self, first_screen):
        self.first_screen = first_screen
        self.client_socket = first_screen.client_socket

        # הגדרת המסך בגודל מלא
        self.signup_screen = tk.Toplevel(self.first_screen.root)
        self.signup_screen.title("Sign Up")
        self.signup_screen.geometry("{0}x{1}+0+0".format(self.signup_screen.winfo_screenwidth(),
                                                         self.first_screen.root.winfo_screenheight()))

        self.logo_img = Image.open(PC_FILE_PATH)
        self.logo_photo = ImageTk.PhotoImage(self.logo_img)

        self.background_label = tk.Label(self.signup_screen, image=self.logo_photo)
        self.background_label.place(x=0, y=0, relwidth=1, relheight=1)

        self.signup_screen.protocol("WM_DELETE_WINDOW", self.close_signup_screen)

        self.username_entry_var = StringVar()
        self.username_entry = tk.Entry(self.signup_screen, textvariable=self.username_entry_var)
        self.username_entry.place(relx=0.5, rely=0.5, anchor="center")

        self.password_entry_var = StringVar()
        self.password_entry = tk.Entry(self.signup_screen, textvariable=self.password_entry_var, show="*")
        self.password_entry.place(relx=0.5, rely=0.55, anchor="center")

        self.confirm_password_entry_var = StringVar()
        self.confirm_password_entry = tk.Entry(self.signup_screen, textvariable=self.confirm_password_entry_var,
                                               show="*")
        self.confirm_password_entry.place(relx=0.5, rely=0.6, anchor="center")

        self.username_label = tk.Label(self.signup_screen, text=" Username: ")
        self.username_label.place(relx=0.45, rely=0.5, anchor="e")

        self.password_label = tk.Label(self.signup_screen, text=" Password: ")
        self.password_label.place(relx=0.45, rely=0.55, anchor="e")

        self.confirm_password_label = tk.Label(self.signup_screen, text=" Confirm Password: ")
        self.confirm_password_label.place(relx=0.45, rely=0.6, anchor="e")

        self.signup_button = tk.Button(self.signup_screen, text="  Sign Up  ", command=self.sign_up)
        self.signup_button.place(relx=0.5, rely=0.65, anchor="center")

    def sign_up(self):
        print('entered the button')
        username = self.username_entry.get()
        password = self.password_entry.get()
        confirm_password = self.confirm_password_entry.get()

        self.username_entry.delete(0, tk.END)
        self.password_entry.delete(0, tk.END)
        self.confirm_password_entry.delete(0, tk.END)

        validation = self.check_validation(username, password, confirm_password)
        if not validation:
            return

        self.send_request(username, password)

        server_response = self.client_socket.recv(5).decode()
        if server_response.startswith('start'):
            while not server_response.endswith('*'):
                server_response += self.client_socket.recv(1).decode()
        data_len = server_response[5:-1]  # data len to receive
        data_len = int(data_len)
        if data_len > 0:
            server_response = self.client_socket.recv(data_len).decode()
            if server_response == 'DONE':
                messagebox.showinfo("Message", f"Added New User")
                self.open_user_requests_screen()
            elif server_response != 'ERROR':
                messagebox.showinfo("Message", f"{server_response}")

    def check_validation(self, username, password, confirm_password):
        problems = ''
        if password != confirm_password:
            problems += 'The passwords do not match\n'
        if len(username) < 4 or len(password) < 4:
            problems += "The username and password should be at least 4 letters\n"
        if '*' in username or '*' in password:
            problems += "The username and password should not contain '*'"
        if problems == '':
            return True
        else:
            messagebox.showinfo("Message", f"{problems}")
            return False

    def send_request(self, username, password):
        message_data = 'S*' + username + '*' + password
        protocol = Protocol(message_data)
        message = protocol.add_protocol()
        self.client_socket.send(message.encode())

    def open_user_requests_screen(self):
        self.signup_screen.withdraw()  # הסתרת מסך ההרשמה
        user_requests_screen = UserRequestsScreen(self.first_screen)  # יצירת מסך הבקשות של המשתמש

    def close_signup_screen(self):
        self.signup_screen.destroy()
        self.first_screen.root.deiconify()


class LogInScreen:
    def __init__(self, first_screen):
        self.first_screen = first_screen
        self.client_socket = first_screen.client_socket

        # הגדרת המסך בגודל מלא
        self.login_screen = tk.Toplevel(self.first_screen.root)
        self.login_screen.title("Log In")
        self.login_screen.geometry("{0}x{1}+0+0".format(self.login_screen.winfo_screenwidth(),
                                                         self.first_screen.root.winfo_screenheight()))

        self.logo_img = Image.open(PC_FILE_PATH)
        self.logo_photo = ImageTk.PhotoImage(self.logo_img)

        self.background_label = tk.Label(self.login_screen, image=self.logo_photo)
        self.background_label.place(x=0, y=0, relwidth=1, relheight=1)

        self.login_screen.protocol("WM_DELETE_WINDOW", self.close_login_screen)

        self.username_entry_var = StringVar()
        self.username_entry = tk.Entry(self.login_screen, textvariable=self.username_entry_var)
        self.username_entry.place(relx=0.5, rely=0.5, anchor="center")

        self.password_entry_var = StringVar()
        self.password_entry = tk.Entry(self.login_screen, textvariable=self.password_entry_var, show="*")
        self.password_entry.place(relx=0.5, rely=0.55, anchor="center")

        self.username_label = tk.Label(self.login_screen, text=" Username: ")
        self.username_label.place(relx=0.45, rely=0.5, anchor="e")

        self.password_label = tk.Label(self.login_screen, text=" Password: ")
        self.password_label.place(relx=0.45, rely=0.55, anchor="e")

        self.login_button = tk.Button(self.login_screen, text="  Log In  ", command=self.log_in)
        self.login_button.place(relx=0.5, rely=0.6, anchor="center")

    def log_in(self):
        username = self.username_entry.get()
        password = self.password_entry.get()

        self.username_entry.delete(0, tk.END)
        self.password_entry.delete(0, tk.END)

        validation = self.check_validation(username, password)
        if not validation:
            return

        self.send_request(username, password)

        # השרת אמור להחזיר אישור או אי אישור (במקרה שבו הסיסמא ושם המשתמש אינם תואמים)
        server_response = self.client_socket.recv(5).decode()
        if server_response.startswith('start'):
            while not server_response.endswith('*'):
                server_response += self.client_socket.recv(1).decode()
        data_len = server_response[5:-1]  # data len to receive
        data_len = int(data_len)
        if data_len > 0:
            server_response = self.client_socket.recv(data_len).decode()
            if server_response == 'DONE':
                messagebox.showinfo("Message", f"Log in successfully")
                self.open_user_requests_screen()
            elif server_response != 'ERROR':
                messagebox.showinfo("Message", f"{server_response}")

    def check_validation(self, username, password):
        problems = ''
        if len(username) < 4 or len(password) < 4:
            problems += "The username and password should be at least 4 letters\n"
        if '*' in username or '*' in password:
            problems += "The username and password should not contain '*'"
        if problems == '':
            return True
        else:
            messagebox.showinfo("Message", f"{problems}")
            return False

    def send_request(self, username, password):
        message_data = 'L*' + username + '*' + password
        protocol = Protocol(message_data)
        message = protocol.add_protocol()
        self.client_socket.send(message.encode())

    def open_user_requests_screen(self):
        self.login_screen.withdraw()  # הסתרת מסך ההרשמה
        user_requests_screen = UserRequestsScreen(self.first_screen)  # יצירת מסך הבקשות של המשתמש

    def close_login_screen(self):
        self.login_screen.destroy()
        self.first_screen.root.deiconify()


class UserRequestsScreen:
    def __init__(self, first_screen):
        self.first_screen = first_screen
        self.client_socket = first_screen.client_socket

        self.user_requests_screen = tk.Toplevel(self.first_screen.root)
        self.user_requests_screen.title("User Requests")
        self.user_requests_screen.geometry("{0}x{1}+0+0".format(self.user_requests_screen.winfo_screenwidth(),
                                                                self.first_screen.root.winfo_screenheight()))

        self.logo_img = Image.open(PC_FILE_PATH)
        self.logo_photo = ImageTk.PhotoImage(self.logo_img)

        self.background_label = tk.Label(self.user_requests_screen, image=self.logo_photo)
        self.background_label.place(x=0, y=0, relwidth=1, relheight=1)

        self.user_requests_screen.protocol("WM_DELETE_WINDOW", self.close_user_requests_screen)

        # Create buttons
        self.add_button = tk.Button(self.user_requests_screen, text="Add Blocking",
                                    command=self.open_add_blocking_screen)
        self.remove_button = tk.Button(self.user_requests_screen, text="Remove Blocking",
                                       command=self.open_remove_blocking_screen)
        self.view_button = tk.Button(self.user_requests_screen, text="View Blocked List",
                                     command=self.view_blocked_list)

        # Place buttons in the center
        self.add_button.place(relx=0.5, rely=0.45, anchor="center")
        self.remove_button.place(relx=0.5, rely=0.5, anchor="center")
        self.view_button.place(relx=0.5, rely=0.55, anchor="center")

    def view_blocked_list(self):
        message_data = 'V'
        protocol = Protocol(message_data)
        message = protocol.add_protocol()
        self.client_socket.send(message.encode())

        server_response = self.client_socket.recv(5).decode()
        if server_response.startswith('start'):
            while not server_response.endswith('*'):
                server_response += self.client_socket.recv(1).decode()
        data_len = server_response[5:-1]  # data len to receive
        data_len = int(data_len)
        if data_len > 0:
            server_response = self.client_socket.recv(data_len).decode()
            messagebox.showinfo("Message", f"{server_response}")
        else:
            messagebox.showinfo("Message", "blocked addresses list is empty")

    def open_add_blocking_screen(self):
        self.user_requests_screen.withdraw()  # הסתרת מסך ההרשמה
        add_blocking_screen = AddBlockingScreen(self.user_requests_screen, self.client_socket)
        # יצירת מסך הבקשות של המשתמש

    def open_remove_blocking_screen(self):
        self.user_requests_screen.withdraw()  # הסתרת מסך ההרשמה
        remove_blocking_screen = RemoveBlockingScreen(self.user_requests_screen, self.client_socket)
        # יצירת מסך הבקשות של המשתמש

    def close_user_requests_screen(self):
        logging.debug('close socket')
        self.user_requests_screen.destroy()
        self.first_screen.root.deiconify()


class RemoveBlockingScreen:
    def __init__(self, user_req_screen, client_socket):
        self.user_req_screen = user_req_screen
        self.client_socket = client_socket

        # הגדרת המסך בגודל מלא
        self.remove_blocking_screen = tk.Toplevel(self.user_req_screen)
        self.remove_blocking_screen.title("Remove Blocking")
        self.remove_blocking_screen.geometry("{0}x{1}+0+0".format(self.remove_blocking_screen.winfo_screenwidth(),
                                                                  self.user_req_screen.winfo_screenheight()))

        self.logo_img = Image.open(PC_FILE_PATH)
        self.logo_photo = ImageTk.PhotoImage(self.logo_img)

        self.background_label = tk.Label(self.remove_blocking_screen, image=self.logo_photo)
        self.background_label.place(x=0, y=0, relwidth=1, relheight=1)

        self.remove_blocking_screen.protocol("WM_DELETE_WINDOW", self.close_remove_blocking_screen)

        self.address_entry_var = StringVar()
        self.address_entry = tk.Entry(self.remove_blocking_screen, textvariable=self.address_entry_var)
        self.address_entry.place(relx=0.5, rely=0.5, anchor="center")

        self.address_label = tk.Label(self.remove_blocking_screen, text=" Blocked Address: ")
        self.address_label.place(relx=0.45, rely=0.5, anchor="e")

        self.remove_address_button = tk.Button(self.remove_blocking_screen, text="  Remove Blocking  ",
                                               command=self.remove_blocking)
        self.remove_address_button.place(relx=0.5, rely=0.55, anchor="center")

    def remove_blocking(self):
        address = self.address_entry.get()
        self.address_entry.delete(0, tk.END)

        validation = self.check_validation(address)
        if not validation:
            return

        self.send_request(address)

        server_response = self.client_socket.recv(5).decode()
        if server_response.startswith('start'):
            while not server_response.endswith('*'):
                server_response += self.client_socket.recv(1).decode()
        data_len = server_response[5:-1]  # data len to receive
        data_len = int(data_len)
        if data_len > 0:
            server_response = self.client_socket.recv(data_len).decode()
            if server_response == 'DONE':
                messagebox.showinfo("Message", "Removed the blocking")
            else:
                messagebox.showinfo("Message", f"{server_response}")
        self.close_remove_blocking_screen()

    def check_validation(self, address):
        if '*' in address:
            messagebox.showinfo("Message", "The address should not contain '*'")
            return False
        return True

    def send_request(self, address):
        message_data = 'R*' + address
        protocol = Protocol(message_data)
        message = protocol.add_protocol()
        self.client_socket.send(message.encode())

    def close_remove_blocking_screen(self):
        self.remove_blocking_screen.destroy()
        self.user_req_screen.deiconify()


class AddBlockingScreen:
    def __init__(self, user_req_screen, client_socket):
        self.user_req_screen = user_req_screen
        self.client_socket = client_socket

        # הגדרת המסך בגודל מלא
        self.add_blocking_screen = tk.Toplevel(self.user_req_screen)
        self.add_blocking_screen.title("Add Blocking")
        self.add_blocking_screen.geometry("{0}x{1}+0+0".format(self.add_blocking_screen.winfo_screenwidth(),
                                                               self.user_req_screen.winfo_screenheight()))

        self.logo_img = Image.open(PC_FILE_PATH)
        self.logo_photo = ImageTk.PhotoImage(self.logo_img)

        self.background_label = tk.Label(self.add_blocking_screen, image=self.logo_photo)
        self.background_label.place(x=0, y=0, relwidth=1, relheight=1)

        self.add_blocking_screen.protocol("WM_DELETE_WINDOW", self.close_add_blocking_screen)

        self.address_entry_var = StringVar()
        self.address_entry = tk.Entry(self.add_blocking_screen, textvariable=self.address_entry_var)
        self.address_entry.place(relx=0.5, rely=0.5, anchor="center")

        self.new_address_entry_var = StringVar()
        self.new_address_entry = tk.Entry(self.add_blocking_screen, textvariable=self.new_address_entry_var)
        self.new_address_entry.place(relx=0.5, rely=0.55, anchor="center")

        self.address_label = tk.Label(self.add_blocking_screen, text=" Address To Block: ")
        self.address_label.place(relx=0.45, rely=0.5, anchor="e")

        self.new_address_label = tk.Label(self.add_blocking_screen, text=" The New Address: ")
        self.new_address_label.place(relx=0.45, rely=0.55, anchor="e")

        self.remove_address_button = tk.Button(self.add_blocking_screen, text="  Add Blocking  ",
                                               command=self.add_blocking)
        self.remove_address_button.place(relx=0.5, rely=0.6, anchor="center")

    def add_blocking(self):
        address = self.address_entry.get()
        new_address = self.new_address_entry.get()

        self.address_entry.delete(0, tk.END)
        self.new_address_entry.delete(0, tk.END)

        validation = self.check_validation(address, new_address)
        if not validation:
            return

        self.send_request(address, new_address)

        server_response = self.client_socket.recv(5).decode()
        if server_response.startswith('start'):
            while not server_response.endswith('*'):
                server_response += self.client_socket.recv(1).decode()
        data_len = server_response[5:-1]  # data len to receive
        data_len = int(data_len)
        if data_len > 0:
            server_response = self.client_socket.recv(data_len).decode()
            if server_response == 'DONE':
                messagebox.showinfo("Message", "Added the new blocking")
            else:
                messagebox.showinfo("Message", f"{server_response}")
        self.close_add_blocking_screen()

    def check_validation(self, address, new_address):
        # לוודא שהכניסו ב- New כתובת של IP!!!!
        problems = ''
        if '*' in address:
            problems += "The address should not contain '*'"
        if not self.check_ip(new_address):
            problems += "New address is not valid-\nIt should be 4 numbers separate with a dot ('.')\n" \
                        "Also each num should be in range of 0-255"
        if problems != '':
            messagebox.showinfo("Message", f'{problems}')
            return False
        return True

    def check_ip(self, new_address):
        flag = True
        if '.' in new_address:
            numbers = new_address.split('.')
            if len(numbers) != 4:
                flag = False
            for num in numbers:
                if num.isdigit():
                    if int(num) < 0 or int(num) > 255:
                        flag = False
                else:
                    flag = False
        else:
            flag = False
        return flag

    def send_request(self, address, new_address):
        message_data = 'A*' + address + '*' + new_address
        protocol = Protocol(message_data)
        message = protocol.add_protocol()
        self.client_socket.send(message.encode())

    def close_add_blocking_screen(self):
        self.add_blocking_screen.destroy()
        self.user_req_screen.deiconify()


if __name__ == "__main__":
    app = FirstScreen()
    app.run()
