import socket
import threading
from datetime import datetime

# Fake services and ports
SERVICES = {
    "Fake-FTP": 2121,
    "Fake-SSH": 2222,
    "Fake-HTTP": 8080,
}

LOG_FILE = "honeypot.log"


def classify_attack(command):
    """Classify a command received by the honeypot."""
    command = command.strip().lower()

    if "wget" in command or "curl" in command:
        return "Malware Download Attempt"
    elif "rm -rf" in command:
        return "Destructive Command"
    elif "nc" in command or "netcat" in command:
        return "Backdoor Attempt"
    elif "chmod" in command:
        return "Privilege Escalation"
    elif command == "":
        return "Brute Force / Login Attempt"
    else:
        return "Reconnaissance / Unknown"


def log_to_file(data):
    """Write detailed attack information to the log file."""
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(data + "\n")


def log_attack(service, addr, port):
    """Write a simple CSV-compatible entry for the dashboard."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"{timestamp},{service},{addr[0]},{port}"
    print(log_entry)

    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(log_entry + "\n")


def start_honeypot(service, port):
    """Start a TCP listener for one fake service."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        sock.bind(("0.0.0.0", port))
        sock.listen(5)

        print(f"[+] {service} honeypot running on port {port}")

        while True:
            conn, addr = sock.accept()
            log_attack(service, addr, port)

            try:
                conn.settimeout(10)

                conn.sendall(b"login: ")
                username = conn.recv(1024).decode(errors="ignore").strip()

                conn.sendall(b"password: ")
                password = conn.recv(1024).decode(errors="ignore").strip()

                conn.sendall(b"$ ")
                command = conn.recv(1024).decode(errors="ignore").strip()

                attack_log = (
                    f"[{datetime.now()}]\n"
                    f"Service: {service}\n"
                    f"IP: {addr[0]}\n"
                    f"Port: {port}\n"
                    f"Username Tried: {username}\n"
                    f"Password Tried: {password}\n"
                    f"Command Executed: {command}\n"
                    f"Attack Type: {classify_attack(command)}\n"
                    + "-" * 50
                )

                print(attack_log)
                log_to_file(attack_log)

            except (socket.timeout, ConnectionResetError, BrokenPipeError):
                pass
            except Exception as e:
                print(f"[!] Error handling {addr[0]} on {service}: {e}")
            finally:
                conn.close()

    except OSError as e:
        print(f"[!] Could not start {service} on port {port}: {e}")
    finally:
        sock.close()


def main():
    print("\n[+] Starting honeypot services...\n")

    for service, port in SERVICES.items():
        thread = threading.Thread(
            target=start_honeypot,
            args=(service, port),
            daemon=True,
        )
        thread.start()

    print("\n[+] Honeypot is ACTIVE. Waiting for connections...\n")

    try:
        while True:
            threading.Event().wait(1)
    except KeyboardInterrupt:
        print("\n[+] Honeypot stopped.")


if __name__ == "__main__":
    main()
