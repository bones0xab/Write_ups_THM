# Passive recognition
---

Passive recognition : Gathering information without direct interacting information about the target 

Active recognition : Gathering infor indirectely

Whois : is req and res for purpose to give details about domain he listen in port 43

Nslookup : finder of Ipadd (from a domain ) 

`$nslookup tryhack.me`

or `$nslookup -type=record  DNS SERVER (like google or claudfire)`

`$dig DNS`

DNSDumpster IS to give you more informatic and more subdomains

[Shodan.io](http://Shodan.io) : is Search engine for internet connect devices allowing users to discover and analyse various devices and systems, servers, routers ,also can provide Ip address , hosting company , location and ports and other stuff


***

# Active Recognition 
---

***Ping***

To see if the target are connected or not 

***Traceroute***

This is for knowing the number of routers or hops that our packet go through them

-The process is to send TTL = 1 from the source to the first Router and the router replies with ICMP and time out of TTL=0 and Combined with IP of it, so the Source now has the IP of the router and he send another packet with TTL + 1,  hence the packet is sent to the next router and so on to the destination 

`$traceroute DNS` 

***Telnet***

For connect to remote system and use CLI of it 

default port 23

`$telnet IP port`

***nc***

This is to listening on port 

`$nc IP port` 

When we get into the server we use this command for making it listen clearly : 

`$nc -vnlp PORT`


***

# Nmap Live Host Discovery
---

***Enumeration Targets*** 

It’s the process to choose many target with different possibilities and syntax 

- list: **`MACHINE_IP scanme.nmap.org example.com`** will scan 3 IP addresses.
- range: **`10.11.12.15-20`** will scan 6 IP addresses: **`10.11.12.15`**, **`10.11.12.16`**,… and **`10.11.12.20`**.
- subnet: **`MACHINE_IP/30`** will sc
- 
- an 4 IP addresses.
- You can also make an file as input to It .

***Discovering Live Hosts***

To discover also hosts we can make ARP request or ICMP or TCP and UDP

‘*We use this live hosts to save time from offline Pcs that aren’t connected’*

- ARP : are possible in the same network

-Locally : must be a privileged user of rom sudoers to scan the local area using the ARP request.

-Outside : When privilege user tries to scan targets  outside the local, uses ICMP echo requests, TCP 

-Outside without privilege : the user tries TCP 3 way handshake by sending packets to ports.

*— To see the online devices*  

`$nmap -sn tagets`

— *To make scan without port scanning* 

**`$nmap -pr -sn IPadd`**

*—To scan locally using arp for local up hosts it send queries* 

`$arp-scan IP`

*— To scan using ping request ICMP* 

This method has one problem is the new firewall has a security to block ICMP 

`$nmap -PE -sn IPadd/mask`

ICMP TIMESTAMP 

- ICMP timestamp  to discover live hosts
    
    ICMP (Internet Control Message Protocol) timestamp requests serve the purpose of determining the current time on a remote host. When a timestamp request is sent to a remote host, it responds with a timestamp containing the time at which it received the request*
    
    ![Untitled](https://prod-files-secure.s3.us-west-2.amazonaws.com/a278e308-9a46-4c09-9885-a4e5acab95ec/c10af347-46f1-4b8f-ba2c-7757ab3f975c/Untitled.png)
    
- ICMP address mac to discover live hosts
    
    `$nmap -PM -sn Ip/mask` 
    
- ICMP with echo reply
    
    `$nmap -PE -sn Ip/m`
    

— *To scan using TCP and UDP*

**TCP SYN ping (don t require privileged account)**

The process of this is to send a packet with SYN flag on port TCP 80 and waiting for the respond , so and open port will reply with 3 handshake and we discovert the live host and closed port will not respond.

`$nmap -PSport -sn ip/masi`   in the port sectino we can make `port`  or `port-port` to make range or choose a ports `p,p,p`.

**Notes** **:** **Privelige users (root and sudoers) are the only can send packets and don t need complete the 3 handchake** 

**TCP ACK ping  (require privilege account)** 

The process here is to send the packet with ACK flag and we see is the host is up by the response of the host by RST flag ,if he respond with it so the hust is up if not the host aren’t live .

 `$sudo -PAport -sn ip/mask` 

*— To scan using UDP ping* 

The process here is to send a UDP packet and getting the response from it , if the response is open okey continue, else you get ICMP type 3 reply that the port is closed.

`$nmap -PU -sn Ip/mask`

**Masscan** 

This is to discover the available systems also, is fast and quite aggressive with the rate of packets

`$masscan ip/mask -pport` 

*— To scan using Reverse DNS lookup*

by default nmap reverse the DNS ip .

If we want to disable add option `-n` 

-To lookup for offline host also add option `-R` 

- **SUMMARY**
    
    ou have learned how ARP, ICMP, TCP, and UDP can detect live hosts by completing this room. Any response from a host is an indication that it is online. Below is a quick summary of the command-line options for Nmap that we have covered.
    
    | Scan Type | Example Command |
    | --- | --- |
    | ARP Scan | **`sudo nmap -PR -sn MACHINE_IP/24`** |
    | ICMP Echo Scan | **`sudo nmap -PE -sn MACHINE_IP/24`** |
    | ICMP Timestamp Scan | **`sudo nmap -PP -sn MACHINE_IP/24`** |
    | ICMP Address Mask Scan | **`sudo nmap -PM -sn MACHINE_IP/24`** |
    | TCP SYN Ping Scan | **`sudo nmap -PS22,80,443 -sn MACHINE_IP/30`** |
    | TCP ACK Ping Scan | **`sudo nmap -PA22,80,443 -sn MACHINE_IP/30`** |
    | UDP Ping Scan | **`sudo nmap -PU53,161,162 -sn MACHINE_IP/30`** |
    
    Remember to add **`-sn`** if you are only interested in host discovery without port-scanning. Omitting **`-sn`** will let Nmap default to port-scanning the live hosts.
    
    | Option | Purpose |
    | --- | --- |
    | **`-n`** | no DNS lookup |
    | **`-R`** | reverse-DNS lookup for all hosts |
    | **`-sn`** | host discovery only |


---



***Vulnerability 101*** 

- There are five common vulnerabilities

| Vulnerability  | Description |
| --- | --- |
| OS  | This from vulnerability of privilege escalation  |
| Configuration based | This is of incorrectly config of service like providing sensitive information in website  |
| Default credetial | LIke admin admin |
| Application Logic | An error in result of poorly designed application  |
| Human Factor | From Human behavior like phising human and SE |

-There are a framework used to scoring the dangerous of the vulnerability

-Advantages of CVSS is a framework recommended by organisations to see risks score

-VPR is a modern framework of organizations

- Vulnerabulity databases

These are the databases of infosec journey about the vulnerabilities about each day how the exploitations and stuff of hacking

→NVD : This for searching for vulnerabilities in databases for free

→Exploit-DB : This store an exploitations of websites and software 

This are tools to search for exploits and try to use them for specific things

`This is a type of vulnerability is`:**Version Disclosure**



***



The Metasploit Framework is a set of tools that allow information gathering, scanning, exploitation, exploit development, post-exploitation, and more.

THE FRAMEWORK : 

—> msfconsole  is the interface

—>Modules : Are small components of MTP for a certain purpose or a task Such as exploits and scanners and payloads and a 

—>Tools : Those are the helpful vulnerability research and vulnerability assessment.

---

- **Modules**

***Auxiliary*** 

That perform tasks such as scanning, fuzzing , service enumeration 

***Key functions*** 

- Scanning: Perform network scans to discover hosts’ open ports and services

Example: auxiliary/scanner/portscan/tcp 

- Fuzzing : DIscover of vulnerabilities

Example: auxiliary/fuzzers/ftp/ftp_pre_post (this is for FTP protocol)

- Service Enumeration: Identify and gather information about running services

Example: auxiliary/scanner/http/http_version 

- Brute forcing

Attempt to guess passwords for different services 

Example: auxiliary/scanner/ssh/ssh_login 

- DOS

Perform attacks to temporarily disable services 

Example: auxiliary/dos/TCP/synflood 

After practice : 

→Set: to make an option for the module 

→Unset: to remove the option inserted 

→Info: To see the current configuration and some commands related to the task you have.

---

***Encoders***

This will encode the exploit and payload in the hope that a signature-based antivirus solution may miss them (signature-based antivirus are the security solutions that have a database of known threats) and the code to be delivered and executed.

 **Key Functions**

Obfuscation 

Transform the payload into different format to evade signature-based detection system antivirus the concept is to make it harder for security tools to recognize and block it .

Avoiding Bad Characters 

Avoiding bad characters cause during the exploitation certain characters can break the exploit this encoder can help ensuring the payload doesn’t appear in the the successful execution of exploit.

Polymorphism 

Is the process of making different encoded version of the same payload to make it difficult for security systems to detect the payload based on static signature.

Size Reduction

This is the process for compressing the data for fitting into specific memory constraints.

Compatibility

This is where the encoders change the payload to be compatible for the environment of the target.

Avoiding Null Bytes

Avoiding null bytes for purpose of making the payload work and not be dead

---

 ***Evasion***

The main goal here to avoid and help the encoder to by pass the security and the antivirus and IDS and the features of security

→Keyfunctions 

*Encoding:* Modify the payload to change the signature to make it harder for AV solutions

*Obfuscation:* like the previous module where we talk about it

*Environment Checks:* Incorporate checks to determine if the code is running in a virtualized environment or sandbox or honeypot and take appropriate actions to avoid execution in such environments

*Dynamic evasion:* Implement runtime techniques to change the payload appearance dynamically such as changing process names or injecting code into legitimate processes to hide malicious activities.

Protocol manipulation: Modify network protocols to avoid detection by IDS/IPS systems, modify such as packets signatures.

Exploits: is to take advantage of vulnerabilities in target systems to gain unauthorized access or execute arbitrary code. Exploits are used to penetrate the target system by leveraging specific weaknesses in software, applications, or services, thereby allowing attackers to control the system or escalate privileges.

No Operation Module: Increase the reliability of the exploit execution, by buffering the memory until plain and making the malicious payload in the end, No operation make the part of memory with lot of NOP NOP to the overwealming and the next are the payload , the NOP are instructions to pas the instruction to the net iterate for that reason the EIP pointer go through the memory next to next to the payload code .

Payloads: These are running in the target system, to help us achieve the desired results such as running payload to open a shell in the target or some stuff like that!

- Payload types
    
    Singles: self contained (to execute immediately) that do not need to download an additional component to run such as : /shell_verse_result `(inline)`
    
    Staged: are the one who’s small in size and have lot of \ to separate the payloads such as : /shell/verse/result `(with slashes)`
    


***

## Working with modules
---

**RHOSTS:** the remote host to make the Ip target or the range of Ips or file list of Ips

**RPORT:** remote port of target that has the vulnerability application is running on.

**PAYLOAD:** payload utilized

**LHOST:** localhost, the attacking machine IP

**LPORT:** this is the local port you will use for the reverse shell to connect back to, this is a port on your attacking machine

**SESSION:** each connection established to the target system using Metasploit has a session ID 

- unset : to clear the inserted value  (`unset parameter` )
- unset all : to remove all the sheet
- setg : is to use the value in all modules without re typing it
- unsetg: To remove the value from all the modules that use it

---

to interact with the sessions are running you use `sessions -i`

***



