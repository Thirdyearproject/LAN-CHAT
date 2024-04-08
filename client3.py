import socket
import threading
import tkinter as tk
from tkinter import scrolledtext
from tkinter import messagebox
import datetime

# Client configuration
HOST = '172.16.2.136' #SERVER IP ADDRESS
PORT = 9999

# Color constants
DARK_GREY = '#121212'
MEDIUM_GREY = '#1F1B24'
OCEAN_BLUE = '#464EB8'
WHITE = "white"

# Font constants
FONT = ("Times New Roman", 17)
BUTTON_FONT = ("Times New Roman", 15)
SMALL_FONT = ("Times New Roman", 13)

# Socket creation
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# XOR encryption/decryption function
def xor_encrypt_decrypt(data, key):
    return ''.join(chr(ord(char) ^ key) for char in data)

# Function to add message to the GUI message box
def add_message(message):
    timestamp = datetime.datetime.now().strftime('%H:%M:%S')
    message_with_timestamp = f"[{timestamp}] {message}"
    message_box.config(state=tk.NORMAL)
    message_box.insert(tk.END, message_with_timestamp + '\n')
    message_box.config(state=tk.DISABLED)

# Function to connect to the server
def connect():
    password = password_textbox.get()
    if password != '':
        try:
            client.connect((HOST, PORT))
            print("Successfully connected to server")
            add_message("[SERVER] Successfully connected to the server")
        except Exception as e:
            messagebox.showerror("Unable to connect to server", f"Unable to connect to server {HOST} {PORT}: {e}")
            return
        
        username = username_textbox.get()
        group_code = group_code_textbox.get()
        if username != '' and group_code != '':
            client.sendall(xor_encrypt_decrypt(f"{username}:{group_code}:{password}", 5).encode())
        else:
            messagebox.showerror("Invalid input", "Username and group code cannot be empty")
    else:
        messagebox.showerror("Password required", "Please enter the password")

    threading.Thread(target=listen_for_messages_from_server, args=(client, 5)).start()

    username_textbox.config(state=tk.DISABLED)
    username_button.config(state=tk.DISABLED)
    group_code_textbox.config(state=tk.DISABLED)
    password_textbox.config(state=tk.DISABLED)
    password_button.config(state=tk.DISABLED)

# Function to send message to the server
def send_message():
    message = message_textbox.get()
    group_code = group_code_textbox.get()
    if message != '' and group_code != '':
        client.sendall(xor_encrypt_decrypt(f"{message}:{group_code}", 5).encode())
        add_message(f"[You]: {message}")
        message_textbox.delete(0, len(message))
    else:
        messagebox.showerror("Empty message or group code", "Message and group code cannot be empty")

# Function to listen for messages from the server
def listen_for_messages_from_server(client, key):
    while True:
        message = xor_encrypt_decrypt(client.recv(2048).decode('utf-8'), key)
        if message != '':
            add_message(message)
        else:
            messagebox.showerror("Error", "Message received from client is empty")

# GUI setup
root = tk.Tk()
root.geometry("1335x600")
root.title("Messenger Client")
root.resizable(True, True)

root.grid_rowconfigure(0, weight=1)
root.grid_rowconfigure(1, weight=4)
root.grid_rowconfigure(2, weight=1)

top_frame = tk.Frame(root, width=600, height=100, bg=DARK_GREY)
top_frame.grid(row=0, column=0, sticky=tk.NSEW)

middle_frame = tk.Frame(root, width=600, height=400, bg=MEDIUM_GREY)
middle_frame.grid(row=1, column=0, sticky=tk.NSEW)

bottom_frame = tk.Frame(root, width=600, height=100, bg=DARK_GREY)
bottom_frame.grid(row=2, column=0, sticky=tk.NSEW)

# Widgets creation
username_label = tk.Label(top_frame, text="Username:", font=FONT, bg=DARK_GREY, fg=WHITE)
username_label.pack(side=tk.LEFT, padx=10)

username_textbox = tk.Entry(top_frame, font=FONT, bg=MEDIUM_GREY, fg=WHITE, width=23)
username_textbox.pack(side=tk.LEFT)

group_code_label = tk.Label(top_frame, text="Group Code:", font=FONT, bg=DARK_GREY, fg=WHITE)
group_code_label.pack(side=tk.LEFT, padx=10)

group_code_textbox = tk.Entry(top_frame, font=FONT, bg=MEDIUM_GREY, fg=WHITE, width=23)
group_code_textbox.pack(side=tk.LEFT)

password_label = tk.Label(top_frame, text="Password:", font=FONT, bg=DARK_GREY, fg=WHITE)
password_label.pack(side=tk.LEFT, padx=10)

password_textbox = tk.Entry(top_frame, font=FONT, bg=MEDIUM_GREY, fg=WHITE, width=23)
password_textbox.pack(side=tk.LEFT)

username_button = tk.Button(top_frame, text="Join", font=BUTTON_FONT, bg=OCEAN_BLUE, fg=WHITE, command=connect)
username_button.pack(side=tk.LEFT, padx=15)

password_button = tk.Button(top_frame, text="Submit", font=BUTTON_FONT, bg=OCEAN_BLUE, fg=WHITE, command=connect)
password_button.pack(side=tk.LEFT, padx=15)

message_textbox = tk.Entry(bottom_frame, font=FONT, bg=MEDIUM_GREY, fg=WHITE, width=98)
message_textbox.pack(side=tk.LEFT, padx=10)

message_button = tk.Button(bottom_frame, text="Send", font=BUTTON_FONT, bg=OCEAN_BLUE, fg=WHITE, command=send_message)
message_button.pack(side=tk.LEFT, padx=10)

message_box = scrolledtext.ScrolledText(middle_frame, font=SMALL_FONT, bg=MEDIUM_GREY, fg=WHITE, width=120, height=26.5)
message_box.config(state=tk.DISABLED)
message_box.pack(side=tk.TOP)

# Start the GUI main loop
def main():
    root.mainloop()

if __name__ == '__main__':
    main()
