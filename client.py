import socket
import subprocess
import tkinter as tk
from tkinter import filedialog
from tkinter import messagebox
from PIL import Image, ImageTk

SERVER_IP = '10.0.0.23'
# SERVER_IP = "172.16.15.49"
PORT = 8246
# PC_FILE_PATH = 'pcimage.jpeg'
PC_FILE_PATH = 'pcimage.jpeg'


class Client:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("parental control")

        self.logo_img = Image.open(PC_FILE_PATH)
        self.logo_photo = ImageTk.PhotoImage(self.logo_img)

        # Set background image
        self.background_label = tk.Label(self.root, image=self.logo_photo)
        self.background_label.place(x=0, y=0, relwidth=1, relheight=1)

        # Create buttons
        self.add_button = tk.Button(self.root, text="Add Blocking", command=self.add_blocking)
        self.remove_button = tk.Button(self.root, text="Remove Blocking", command=self.remove_blocking)
        self.view_button = tk.Button(self.root, text="View Blocked List", command=self.view_blocked_list)

        # Place buttons in the center
        self.add_button.place(relx=0.5, rely=0.45, anchor="center")
        self.remove_button.place(relx=0.5, rely=0.5, anchor="center")
        self.view_button.place(relx=0.5, rely=0.55, anchor="center")

        self.address_entry = tk.Entry(self.root)  # Create an entry field
        self.address_entry.place(relx=0.5, rely=0.6, anchor="center")

    def send_req(self, address, command):
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_socket.connect((SERVER_IP, PORT))
        if not address.endswith('.'):
            address += '.'
        self.client_socket.send(("*start*" + command + address + "*end*").encode())
        response = self.client_socket.recv(7).decode()
        if response.startswith('*start*'):
            while not response.endswith('*end*'):
                response += self.client_socket.recv(1).decode()
        self.client_socket.close()
        return response[7:-5]

    def add_blocking(self):
        address = self.address_entry.get()  # Get the entered address
        command = 'A'  # add
        res = self.send_req(address, command)
        if res != 'ERROR':
            messagebox.showinfo("Message", f"Added blocking: {address}")
        else:
            messagebox.showinfo("Message", f"Error in adding blocking: {address}")

    def remove_blocking(self):
        address = self.address_entry.get()  # Get the entered address
        command = 'R'  # remove
        res = self.send_req(address, command)
        if res != 'ERROR':
            messagebox.showinfo("Message", f"Removed blocking: {address}")
        else:
            messagebox.showinfo("Message", f"Error in removing blocking: {address}")

    def view_blocked_list(self):
        command = 'V'  # remove
        res = self.send_req('', command)
        messagebox.showinfo("Message", f"Blocked list:\n{res}")


def main():
    client = Client()
    client.root.mainloop()


if __name__ == "__main__":
    main()
