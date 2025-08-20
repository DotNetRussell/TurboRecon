import argparse
import subprocess
import xml.etree.ElementTree as ET
import os
from datetime import datetime
from tabulate import tabulate

def run_command(command, output_file=None):
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        output = result.stdout + result.stderr
        if output_file:
            with open(output_file, 'a') as f:
                f.write(f"\n{'='*40}\nCommand: {command}\n{'='*40}\n{output}\n")
        return output, result.returncode
    except Exception as e:
        error_msg = f"Error running command {command}: {str(e)}"
        if output_file:
            with open(output_file, 'a') as f:
                f.write(f"\n{'='*40}\n{error_msg}\n")
        return error_msg, 1

def ping_target(ip, output_file):
    print(f"Pinging target {ip}...")
    output, returncode = run_command(f"ping -c 4 {ip}", output_file)
    if returncode != 0:
        print("Ping failed. Target may be down.")
        return False
    print("Ping successful. Target is up.")
    return True

def parse_nmap_xml(xml_file):
    ports_info = []
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
        for port in root.findall(".//port"):
            port_id = port.get('portid')
            protocol = port.get('protocol')
            state = port.find('state').get('state')
            service = port.find('service').get('name') if port.find('service') is not None else 'unknown'
            if state == 'open':
                ports_info.append({'port': port_id, 'protocol': protocol, 'service': service})
    except Exception as e:
        print(f"Error parsing nmap XML: {str(e)}")
    return ports_info

def run_nmap(ip, output_file):
    print(f"Running nmap scan on {ip}...")
    nmap_cmd = f"nmap -p- -sC -sV -oX nmap_scan.xml {ip}"
    output, _ = run_command(nmap_cmd, output_file)
    ports_info = parse_nmap_xml("nmap_scan.xml")
    return ports_info

def run_nikto(ip, port, output_file):
    print(f"Running nikto on {ip}:{port}...")
    nikto_cmd = f"nikto -h http://{ip}:{port}"
    run_command(nikto_cmd, output_file)

def run_dirb(ip, port, output_file):
    print(f"Running dirb on {ip}:{port}...")
    dirb_cmd = f"dirb http://{ip}:{port} -S -o dirb_output.txt"
    run_command(dirb_cmd, output_file)

def run_gobuster(ip, port, output_file):
    print(f"Running gobuster on {ip}:{port}...")
    gobuster_cmd = f"gobuster dir -u http://{ip}:{port} -w /usr/share/wordlists/dirb/common.txt -o gobuster_output.txt"
    run_command(gobuster_cmd, output_file)

def run_whatweb(ip, port, output_file):
    print(f"Running whatweb on {ip}:{port}...")
    whatweb_cmd = f"whatweb http://{ip}:{port}"
    run_command(whatweb_cmd, output_file)

def run_curl(ip, port, output_file):
    print(f"Running curl banner grabbing on {ip}:{port}...")
    curl_cmd = f"curl -I http://{ip}:{port}"
    run_command(curl_cmd, output_file)

def run_cewl(ip, port, output_file):
    print(f"Running cewl on {ip}:{port}...")
    cewl_cmd = f"cewl http://{ip}:{port} -w cewl_wordlist.txt"
    run_command(cewl_cmd, output_file)

def run_enum4linux(ip, output_file):
    print(f"Running enum4linux on {ip}...")
    enum4linux_cmd = f"enum4linux -a {ip}"
    run_command(enum4linux_cmd, output_file)

def run_smbclient(ip, output_file):
    print(f"Running smbclient enumeration on {ip}...")
    smbclient_cmd = f"smbclient -L //{ip} -N"
    run_command(smbclient_cmd, output_file)

def run_smb_null_session(ip, output_file):
    print(f"Checking SMB null session on {ip}...")
    smb_null_cmd = f"smbclient -L //{ip} -U '%' -N"
    run_command(smb_null_cmd, output_file)

def run_rpc_null_session(ip, output_file):
    print(f"Checking RPC null session on {ip}...")
    rpc_null_cmd = f"rpcclient -U '' -N {ip} -c 'srvinfo;netshareenum'"
    run_command(rpc_null_cmd, output_file)

def run_ftp_anonymous(ip, port, output_file):
    print(f"Attempting anonymous FTP login on {ip}:{port}...")
    ftp_cmd = f"ftp -n {ip} {port} <<END\nquote USER anonymous\nquote PASS anonymous@\nquit\nEND"
    run_command(ftp_cmd, output_file)

def run_hydra_ftp(ip, port, username, wordlist, threads, output_file):
    print(f"Running hydra FTP brute-force on {ip}:{port} with username '{username}', wordlist '{wordlist}', and {threads} threads...")
    hydra_cmd = f"hydra -l {username} -P {wordlist} ftp://{ip}:{port} -t {threads}"
    run_command(hydra_cmd, output_file)

def run_hydra_ssh(ip, port, username, wordlist, threads, output_file):
    print(f"Running hydra SSH brute-force on {ip}:{port} with username '{username}', wordlist '{wordlist}', and {threads} threads...")
    hydra_cmd = f"hydra -l {username} -P {wordlist} ssh://{ip}:{port} -t {threads}"
    run_command(hydra_cmd, output_file)

def run_hydra_telnet(ip, port, username, wordlist, threads, output_file):
    print(f"Running hydra Telnet brute-force on {ip}:{port} with username '{username}', wordlist '{wordlist}', and {threads} threads...")
    hydra_cmd = f"hydra -l {username} -P {wordlist} telnet://{ip}:{port} -t {threads}"
    run_command(hydra_cmd, output_file)

def run_evil_winrm(ip, port, output_file):
    print(f"Checking WinRM null session and common logins on {ip}:{port}...")
    # Null session check
    print(f"Trying WinRM null session...")
    null_cmd = f"evil-winrm -i {ip} -u '' -p '' -P {port} --no-banner -s whoami"
    run_command(null_cmd, output_file)
    
    # Common credentials check
    common_creds = [
        ("Administrator", "password"),
        ("Administrator", "admin"),
        ("Administrator", "Password123")
    ]
    for username, password in common_creds:
        print(f"Trying WinRM login with {username}:{password}...")
        winrm_cmd = f"evil-winrm -i {ip} -u '{username}' -p '{password}' -P {port} --no-banner -s whoami"
        run_command(winrm_cmd, output_file)

def run_ssh_nmap(ip, port, output_file):
    print(f"Running nmap SSH enumeration on {ip}:{port}...")
    ssh_nmap_cmd = f"nmap --script ssh2-enum-algos,ssh-auth-methods -p {port} {ip}"
    run_command(ssh_nmap_cmd, output_file)

def run_dnsenum(ip, output_file):
    print(f"Running dnsenum on {ip}...")
    dnsenum_cmd = f"dnsenum --enum {ip}"
    run_command(dnsenum_cmd, output_file)

def run_snmpcheck(ip, output_file):
    print(f"Running snmpcheck on {ip}...")
    snmpcheck_cmd = f"snmpcheck -t {ip}"
    run_command(snmpcheck_cmd, output_file)

def run_smtp_enum(ip, port, output_file):
    print(f"Running SMTP user enumeration on {ip}:{port}...")
    smtp_enum_cmd = f"smtp-user-enum -M VRFY -U /usr/share/seclists/Usernames/top-usernames-shortlist.txt -t {ip} -p {port}"
    run_command(smtp_enum_cmd, output_file)

def run_nfs_showmount(ip, output_file):
    print(f"Running showmount on {ip}...")
    showmount_cmd = f"showmount -e {ip}"
    run_command(showmount_cmd, output_file)

def run_kerberos_nmap(ip, port, domain, output_file):
    print(f"Running nmap Kerberos enumeration on {ip}:{port}...")
    kerberos_cmd = f"nmap --script krb5-enum-users --script-args krb5-enum-users.realm={domain} -p {port} {ip}"
    run_command(kerberos_cmd, output_file)

def run_ldapsearch(ip, port, domain, output_file):
    print(f"Running ldapsearch on {ip}:{port}...")
    ldap_cmd = f"ldapsearch -x -H ldap://{ip}:{port} -b 'dc={domain.split('.')[0]},dc={domain.split('.')[1]}'"
    run_command(ldap_cmd, output_file)

def run_rpcclient(ip, output_file):
    print(f"Running rpcclient enumeration on {ip}...")
    rpc_cmd = f"rpcclient -U '' -N {ip} -c 'enumdomusers'"
    run_command(rpc_cmd, output_file)

def run_nbtscan(ip, output_file):
    print(f"Running nbtscan on {ip}...")
    nbtscan_cmd = f"nbtscan {ip}"
    run_command(nbtscan_cmd, output_file)

def run_telnet_nmap(ip, port, output_file):
    print(f"Running nmap Telnet enumeration on {ip}:{port}...")
    telnet_cmd = f"nmap --script telnet-encryption,telnet-ntlm-info -p {port} {ip}"
    run_command(telnet_cmd, output_file)

def run_vnc_nmap(ip, port, output_file):
    print(f"Running nmap VNC enumeration on {ip}:{port}...")
    vnc_cmd = f"nmap --script vnc-info -p {port} {ip}"
    run_command(vnc_cmd, output_file)

def run_mysql_nmap(ip, port, output_file):
    print(f"Running nmap MySQL enumeration on {ip}:{port}...")
    mysql_cmd = f"nmap --script mysql-info,mysql-users -p {port} {ip}"
    run_command(mysql_cmd, output_file)

def main():
    parser = argparse.ArgumentParser(description="OSCP Pentesting Automation Script with Configurable Brute-Forcing, Null Session, and WinRM Checks")
    parser.add_argument("ip", help="Target IP address")
    parser.add_argument("--no-ping", action="store_true", help="Disable ping check")
    parser.add_argument("--username", default="admin", help="Username for FTP, SSH, and Telnet brute-forcing (default: admin)")
    parser.add_argument("--wordlist", default="/usr/share/wordlists/rockyou.txt", 
                        help="Path to password wordlist for FTP, SSH, and Telnet brute-forcing (default: /usr/share/wordlists/rockyou.txt)")
    parser.add_argument("--threads", type=int, default=4, 
                        help="Number of threads for FTP, SSH, and Telnet brute-forcing with hydra (default: 4)")
    parser.add_argument("--domain", default="example.local", 
                        help="Domain for Kerberos and LDAP enumeration (default: example.local)")
    args = parser.parse_args()

    ip = args.ip
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = f"pentest_report_{ip}_{timestamp}.txt"

    # Validate wordlist file
    if not os.path.isfile(args.wordlist):
        print(f"Error: Wordlist file '{args.wordlist}' does not exist.")
        return

    # Initialize output file
    with open(output_file, 'w') as f:
        f.write(f"Pentest Report for {ip}\nGenerated on: {timestamp}\n\n")

    # Step 1: Ping check (if not disabled)
    if not args.no_ping:
        if not ping_target(ip, output_file):
            print("Exiting due to ping failure.")
            return

    # Step 2: Run nmap scan
    ports_info = run_nmap(ip, output_file)

    # Step 3: Scan open ports with appropriate tools
    scanned_ports = []
    for port_info in ports_info:
        port = port_info['port']
        service = port_info['service'].lower()
        scanned_ports.append([port, service, "Scanned"])

        if service in ['http', 'https']:
            run_nikto(ip, port, output_file)
            run_dirb(ip, port, output_file)
            run_gobuster(ip, port, output_file)
            run_whatweb(ip, port, output_file)
            run_curl(ip, port, output_file)
            run_cewl(ip, port, output_file)
        elif service == 'smb':
            run_enum4linux(ip, output_file)
            run_smbclient(ip, output_file)
            run_smb_null_session(ip, output_file)
            run_rpc_null_session(ip, output_file)
        elif service == 'ftp':
            run_ftp_anonymous(ip, port, output_file)
            run_hydra_ftp(ip, port, args.username, args.wordlist, args.threads, output_file)
        elif service == 'ssh':
            run_ssh_nmap(ip, port, output_file)
            run_hydra_ssh(ip, port, args.username, args.wordlist, args.threads, output_file)
        elif service == 'dns':
            run_dnsenum(ip, output_file)
        elif service in ['snmp', 'snmptrap']:
            run_snmpcheck(ip, output_file)
        elif service == 'smtp':
            run_smtp_enum(ip, port, output_file)
        elif service == 'nfs':
            run_nfs_showmount(ip, output_file)
        elif service == 'kerberos':
            run_kerberos_nmap(ip, port, args.domain, output_file)
        elif service == 'ldap':
            run_ldapsearch(ip, port, args.domain, output_file)
        elif service in ['msrpc', 'epmap']:
            run_rpcclient(ip, output_file)
            run_rpc_null_session(ip, output_file)
        elif service in ['netbios-ns', 'netbios-dgm', 'netbios-ssn']:
            run_nbtscan(ip, output_file)
        elif service == 'telnet':
            run_telnet_nmap(ip, port, output_file)
            run_hydra_telnet(ip, port, args.username, args.wordlist, args.threads, output_file)
        elif service == 'vnc':
            run_vnc_nmap(ip, port, output_file)
        elif service == 'mysql':
            run_mysql_nmap(ip, port, output_file)
        elif service == 'wsman' or (service == 'http' and port in ['5985', '5986']):
            run_evil_winrm(ip, port, output_file)
        else:
            with open(output_file, 'a') as f:
                f.write(f"No specific tool for service {service} on port {port}\n")

    # Step 4: Output table
    print("\nScan Summary:")
    headers = ["Port", "Service", "Status"]
    print(tabulate(scanned_ports, headers=headers, tablefmt="grid"))

    # Step 5: Finalize output file
    with open(output_file, 'a') as f:
        f.write("\nScan Summary Table:\n")
        f.write(tabulate(scanned_ports, headers=headers, tablefmt="plain"))
        f.write(f"\nDetailed scan results saved to {output_file}\n")

    print(f"\nDetailed scan results saved to {output_file}")

if __name__ == "__main__":
    main()
