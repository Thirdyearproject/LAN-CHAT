import socket
import threading

# Server configuration
HOST = socket.gethostbyname(socket.gethostname())
PORT = 9999  # Port to listen on
LISTENER_LIMIT = 5  # Maximum number of simultaneous connections
active_clients = []  # List to store active client connections

# Function for XOR encryption/decryption
def xor_encrypt_decrypt(data, key):
    return ''.join(chr(ord(char) ^ key) for char in data)

# Function to send messages to a specific group
def send_messages_to_group(message, key, group_code):
    for user in active_clients:
        if user[2] == group_code:
            user[1].sendall(xor_encrypt_decrypt(message, key).encode())

# Function to listen for messages from a client
def listen_for_messages(client, username, key, group_code):
    while True:
        message = xor_encrypt_decrypt(client.recv(2048).decode('utf-8'), key)
        if message:
            if message.startswith('@'):
                dest_username, message = message.split(maxsplit=1)
                dest_username = dest_username[1:]
                send_message_to_user(username, dest_username, message, key)
            else:
                final_msg = f"[{username}]: {message.split(':', maxsplit=1)[0]}"
                send_messages_to_group(final_msg, key, group_code)
        else:
            print(f"The message sent from client {username} is empty")
            break

# Function to send a message to a specific user
def send_message_to_user(sender_username, dest_username, message, key):
    for user in active_clients:
        if user[0] == dest_username:
            user[1].sendall(xor_encrypt_decrypt(f"[{sender_username} to {dest_username}]: {message.split(':', maxsplit=1)[0]}", key).encode())
            break

# Function to handle a client connection
def client_handler(client, key):
    while True:
        data = xor_encrypt_decrypt(client.recv(2048).decode('utf-8'), key)
        if data:
            username, group_code = data.split(':')  
            active_clients.append((username, client, group_code))
            prompt_message = f"SERVER: {username} joined the chat"
            send_messages_to_group(prompt_message, key, group_code)
            break
        else:
            print("Client username is empty")

    threading.Thread(target=listen_for_messages, args=(client, username, key, group_code)).start()

# Main function to run the server
def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        server.bind((HOST, PORT))
        print(f"Running the server on {HOST} {PORT}")
    except Exception as e:
        print(f"Unable to bind to host {HOST} and port {PORT}: {e}")

    server.listen(LISTENER_LIMIT)

    while True:
        client, address = server.accept()
        print(f"Successfully connected to client {address[0]} {address[1]}")
        threading.Thread(target=client_handler, args=(client, 5)).start()

if __name__ == '__main__':
    main()
