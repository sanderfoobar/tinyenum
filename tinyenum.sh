#!/bin/bash
#A script to enumerate local information from a Linux host
export TIME_STYLE='+'

_echo() {
  echo "$@" | sed 's/root root/~root/g'
}

# useful binaries (thanks to https://gtfobins.github.io/)
binarylist='aria2c\|arp\|ash\|awk\|base64\|bash\|busybox\|cat\|chmod\|chown\|cp\|csh\|curl\|cut\|dash\|date\|dd\|diff\|dmsetup\|docker\|ed\|emacs\|env\|expand\|expect\|file\|find\|flock\|fmt\|fold\|ftp\|gawk\|gdb\|gimp\|git\|grep\|head\|ht\|iftop\|ionice\|ip$\|irb\|jjs\|jq\|jrunscript\|ksh\|ld.so\|ldconfig\|less\|logsave\|lua\|make\|man\|mawk\|more\|mv\|mysql\|nano\|nawk\|nc\|netcat\|nice\|nl\|nmap\|node\|od\|openssl\|perl\|pg\|php\|pic\|pico\|python\|readelf\|rlwrap\|rpm\|rpmquery\|rsync\|ruby\|run-parts\|rvim\|scp\|script\|sed\|setarch\|sftp\|sh\|shuf\|socat\|sort\|sqlite3\|ssh$\|start-stop-daemon\|stdbuf\|strace\|systemctl\|tail\|tar\|taskset\|tclsh\|tee\|telnet\|tftp\|time\|timeout\|ul\|unexpand\|uniq\|unshare\|vi\|vim\|watch\|wget\|wish\|xargs\|xxd\|zip\|zsh'

system_info()
{
_echo -e "SYSTEM ##############################################"

#basic kernel info
unameinfo=`uname -a 2>/dev/null`
if [ "$unameinfo" ]; then
  _echo -e "[-] Kernel information:\n$unameinfo"
  _echo -e "\n"
fi

procver=`cat /proc/version 2>/dev/null`
if [ "$procver" ]; then
  _echo -e "[-] Kernel information (continued):\n$procver"
  _echo -e "\n"
fi

#search all *-release files for version info
release=`cat /etc/*-release 2>/dev/null`
if [ "$release" ]; then
  _echo -e "[-] Specific release information:\n$release"
  _echo -e "\n"
fi

#target hostname info
hostnamed=`hostname 2>/dev/null`
if [ "$hostnamed" ]; then
  _echo -e "[-] Hostname:\n$hostnamed"
  _echo -e "\n"
fi

#search for suid files
allsuid=`find / -perm -4000 -type f 2>/dev/null`
findsuid=`find $allsuid -perm -4000 -type f -exec ls -la {} 2>/dev/null \;`
if [ "$findsuid" ]; then
  _echo -e "[-] SUID files:\n$findsuid"
  _echo -e "\n"
fi

if [ "$export" ] && [ "$findsuid" ]; then
  mkdir $format/suid-files/ 2>/dev/null
  for i in $findsuid; do cp $i $format/suid-files/; done 2>/dev/null
fi

#list of 'interesting' suid files - feel free to make additions
intsuid=`find $allsuid -perm -4000 -type f -exec ls -la {} \; 2>/dev/null | grep -w $binarylist 2>/dev/null`
if [ "$intsuid" ]; then
  _echo -e "[+] Possibly interesting SUID files:\n$intsuid"
  _echo -e "\n"
fi

#lists world-writable suid files
wwsuid=`find $allsuid -perm -4002 -type f -exec ls -la {} 2>/dev/null \;`
if [ "$wwsuid" ]; then
  _echo -e "[+] World-writable SUID files:\n$wwsuid"
  _echo -e "\n"
fi

#lists world-writable suid files owned by root
wwsuidrt=`find $allsuid -uid 0 -perm -4002 -type f -exec ls -la {} 2>/dev/null \;`
if [ "$wwsuidrt" ]; then
  _echo -e "[+] World-writable SUID files owned by root:\n$wwsuidrt"
  _echo -e "\n"
fi

#search for sgid files
allsgid=`find / -perm -2000 -type f 2>/dev/null`
findsgid=`find $allsgid -perm -2000 -type f -exec ls -la {} 2>/dev/null \;`
if [ "$findsgid" ]; then
  _echo -e "[-] SGID files:\n$findsgid"
  _echo -e "\n"
fi

if [ "$export" ] && [ "$findsgid" ]; then
  mkdir $format/sgid-files/ 2>/dev/null
  for i in $findsgid; do cp $i $format/sgid-files/; done 2>/dev/null
fi

#list of 'interesting' sgid files
intsgid=`find $allsgid -perm -2000 -type f  -exec ls -la {} \; 2>/dev/null | grep -w $binarylist 2>/dev/null`
if [ "$intsgid" ]; then
  _echo -e "[+] Possibly interesting SGID files:\n$intsgid"
  _echo -e "\n"
fi

#lists world-writable sgid files
wwsgid=`find $allsgid -perm -2002 -type f -exec ls -la {} 2>/dev/null \;`
if [ "$wwsgid" ]; then
  _echo -e "[+] World-writable SGID files:\n$wwsgid"
  _echo -e "\n"
fi

#lists world-writable sgid files owned by root
wwsgidrt=`find $allsgid -uid 0 -perm -2002 -type f -exec ls -la {} 2>/dev/null \;`
if [ "$wwsgidrt" ]; then
  _echo -e "[+] World-writable SGID files owned by root:\n$wwsgidrt"
  _echo -e "\n"
fi

#list all files with POSIX capabilities set along with there capabilities
fileswithcaps=`getcap -r / 2>/dev/null || /sbin/getcap -r / 2>/dev/null`
if [ "$fileswithcaps" ]; then
  _echo -e "[+] Files with POSIX capabilities set:\n$fileswithcaps"
  _echo -e "\n"
fi

if [ "$export" ] && [ "$fileswithcaps" ]; then
  mkdir $format/files_with_capabilities/ 2>/dev/null
  for i in $fileswithcaps; do cp $i $format/files_with_capabilities/; done 2>/dev/null
fi

#searches /etc/security/capability.conf for users associated capapilies
userswithcaps=`grep -v '^#\|none\|^$' /etc/security/capability.conf 2>/dev/null`
if [ "$userswithcaps" ]; then
  _echo -e "[+] Users with specific POSIX capabilities:\n$userswithcaps"
  _echo -e "\n"
fi

if [ "$userswithcaps" ] ; then
#matches the capabilities found associated with users with the current user
matchedcaps=`_echo -e "$userswithcaps" | grep \`whoami\` | awk '{print $1}' 2>/dev/null`
	if [ "$matchedcaps" ]; then
		_echo -e "[+] Capabilities associated with the current user:\n$matchedcaps"
		_echo -e "\n"
		#matches the files with capapbilities with capabilities associated with the current user
		matchedfiles=`_echo -e "$matchedcaps" | while read -r cap ; do _echo -e "$fileswithcaps" | grep "$cap" ; done 2>/dev/null`
		if [ "$matchedfiles" ]; then
			_echo -e "[+] Files with the same capabilities associated with the current user (You may want to try abusing those capabilties):\n$matchedfiles"
			_echo -e "\n"
			#lists the permissions of the files having the same capabilies associated with the current user
			matchedfilesperms=`_echo -e "$matchedfiles" | awk '{print $1}' | while read -r f; do ls -la $f ;done 2>/dev/null`
			_echo -e "[+] Permissions of files with the same capabilities associated with the current user:\n$matchedfilesperms"
			_echo -e "\n"
			if [ "$matchedfilesperms" ]; then
				#checks if any of the files with same capabilities associated with the current user is writable
				writablematchedfiles=`_echo -e "$matchedfiles" | awk '{print $1}' | while read -r f; do find $f -writable -exec ls -la {} + ;done 2>/dev/null`
				if [ "$writablematchedfiles" ]; then
					_echo -e "[+] User/Group writable files with the same capabilities associated with the current user:\n$writablematchedfiles"
					_echo -e "\n"
				fi
			fi
		fi
	fi
fi

}

user_info()
{
_echo -e "USER/GROUP ##########################################"

#current user details
currusr=`id 2>/dev/null`
if [ "$currusr" ]; then
  _echo -e "[-] Current user/group info:\n$currusr"
  _echo -e "\n"
fi

#who else is logged on
loggedonusrs=`w 2>/dev/null`
if [ "$loggedonusrs" ]; then
  _echo -e "[-] Who else is logged on:\n$loggedonusrs"
  _echo -e "\n"
fi

#added by phackt - look for adm group (thanks patrick)
adm_users=$(_echo -e "$grpinfo" | grep "(adm)")
if [[ ! -z $adm_users ]];
  then
    _echo -e "[-] It looks like we have some admin users:\n$adm_users"
    _echo -e "\n"
fi

#checks to see if any hashes are stored in /etc/passwd (depreciated  *nix storage method)
hashesinpasswd=`grep -v '^[^:]*:[x]' /etc/passwd 2>/dev/null`
if [ "$hashesinpasswd" ]; then
  _echo -e "[+] It looks like we have password hashes in /etc/passwd!\n$hashesinpasswd"
  _echo -e "\n"
fi

# /etc/passwd
readpasswd=`cat /etc/passwd 2>/dev/null`

if [ "$export" ] && [ "$readpasswd" ]; then
  mkdir $format/etc-export/ 2>/dev/null
  cp /etc/passwd $format/etc-export/passwd 2>/dev/null
fi

#checks to see if the shadow file can be read
readshadow=`cat /etc/shadow 2>/dev/null`
if [ "$readshadow" ]; then
  _echo -e "[+] We can read the shadow file!\n$readshadow"
  _echo -e "\n"
fi

if [ "$export" ] && [ "$readshadow" ]; then
  mkdir $format/etc-export/ 2>/dev/null
  cp /etc/shadow $format/etc-export/shadow 2>/dev/null
fi

#checks to see if /etc/master.passwd can be read - BSD 'shadow' variant
readmasterpasswd=`cat /etc/master.passwd 2>/dev/null`
if [ "$readmasterpasswd" ]; then
  _echo -e "[+] We can read the master.passwd file!\n$readmasterpasswd"
  _echo -e "\n"
fi

if [ "$export" ] && [ "$readmasterpasswd" ]; then
  mkdir $format/etc-export/ 2>/dev/null
  cp /etc/master.passwd $format/etc-export/master.passwd 2>/dev/null
fi

#all root accounts (uid 0)
superman=`grep -v -E "^#" /etc/passwd 2>/dev/null| awk -F: '$3 == 0 { print $1}' 2>/dev/null`
if [ "$superman" ]; then
  _echo -e "[-] Super user account(s):\n$superman"
  _echo -e "\n"
fi

#pull out vital sudoers info
sudoers=`grep -v -e '^$' /etc/sudoers 2>/dev/null |grep -v "#" 2>/dev/null`
if [ "$sudoers" ]; then
  _echo -e "[-] Sudoers configuration (condensed):$sudoers"
  _echo -e "\n"
fi

if [ "$export" ] && [ "$sudoers" ]; then
  mkdir $format/etc-export/ 2>/dev/null
  cp /etc/sudoers $format/etc-export/sudoers 2>/dev/null
fi

#can we sudo without supplying a password
sudoperms=`echo '' | sudo -S -l -k 2>/dev/null`
if [ "$sudoperms" ]; then
  _echo -e "[+] We can sudo without supplying a password!\n$sudoperms"
  _echo -e "\n"
fi

#check sudo perms - authenticated
if [ "$sudopass" ]; then
    if [ "$sudoperms" ]; then
      :
    else
      sudoauth=`echo $userpassword | sudo -S -l -k 2>/dev/null`
      if [ "$sudoauth" ]; then
        _echo -e "[+] We can sudo when supplying a password!\n$sudoauth"
        _echo -e "\n"
      fi
    fi
fi

##known 'good' breakout binaries (cleaned to parse /etc/sudoers for comma separated values) - authenticated
if [ "$sudopass" ]; then
    if [ "$sudoperms" ]; then
      :
    else
      sudopermscheck=`echo $userpassword | sudo -S -l -k 2>/dev/null | xargs -n 1 2>/dev/null|sed 's/,*$//g' 2>/dev/null | grep -w $binarylist 2>/dev/null`
      if [ "$sudopermscheck" ]; then
        _echo -e "[-] Possible sudo pwnage!\n$sudopermscheck"
        _echo -e "\n"
      fi
    fi
fi

#known 'good' breakout binaries (cleaned to parse /etc/sudoers for comma separated values)
sudopwnage=`echo '' | sudo -S -l -k 2>/dev/null | xargs -n 1 2>/dev/null | sed 's/,*$//g' 2>/dev/null | grep -w $binarylist 2>/dev/null`
if [ "$sudopwnage" ]; then
  _echo -e "[+] Possible sudo pwnage!\n$sudopwnage"
  _echo -e "\n"
fi

#who has sudoed in the past
whohasbeensudo=`find /home -name .sudo_as_admin_successful 2>/dev/null`
if [ "$whohasbeensudo" ]; then
  _echo -e "[-] Accounts that have recently used sudo:\n$whohasbeensudo"
  _echo -e "\n"
fi

#checks to see if roots home directory is accessible
rthmdir=`ls -ahl /root/ 2>/dev/null`
if [ "$rthmdir" ]; then
  _echo -e "[+] We can read root's home directory!\n$rthmdir"
  _echo -e "\n"
fi

#displays /home directory permissions - check if any are lax
homedirperms=`ls -ahl /home/ 2>/dev/null`
if [ "$homedirperms" ]; then
  _echo -e "[-] Are permissions on /home directories lax:\n$homedirperms"
  _echo -e "\n"
fi

#looks for files we can write to that don't belong to us
if [ "$thorough" = "1" ]; then
  grfilesall=`find / -writable ! -user \`whoami\` -type f ! -path "/proc/*" ! -path "/sys/*" -exec ls -al {} \; 2>/dev/null`
  if [ "$grfilesall" ]; then
    _echo -e "[-] Files not owned by user but writable by group:\n$grfilesall"
    _echo -e "\n"
  fi
fi

#looks for files that belong to us
if [ "$thorough" = "1" ]; then
  ourfilesall=`find / -user \`whoami\` -type f ! -path "/proc/*" ! -path "/sys/*" -exec ls -al {} \; 2>/dev/null`
  if [ "$ourfilesall" ]; then
    _echo -e "[-] Files owned by our user:\n$ourfilesall"
    _echo -e "\n"
  fi
fi

#looks for hidden files
if [ "$thorough" = "1" ]; then
  hiddenfiles=`find / -name ".*" -type f ! -path "/proc/*" ! -path "/sys/*" -exec ls -al {} \; 2>/dev/null`
  if [ "$hiddenfiles" ]; then
    _echo -e "[-] Hidden files:\n$hiddenfiles"
    _echo -e "\n"
  fi
fi

#looks for world-reabable files within /home - depending on number of /home dirs & files, this can take some time so is only 'activated' with thorough scanning switch
if [ "$thorough" = "1" ]; then
wrfileshm=`find /home/ -perm -4 -type f -exec ls -al {} \; 2>/dev/null`
	if [ "$wrfileshm" ]; then
		_echo -e "[-] World-readable files within /home:\n$wrfileshm"
		_echo -e "\n"
	fi
fi

if [ "$thorough" = "1" ]; then
	if [ "$export" ] && [ "$wrfileshm" ]; then
		mkdir $format/wr-files/ 2>/dev/null
		for i in $wrfileshm; do cp --parents $i $format/wr-files/ ; done 2>/dev/null
	fi
fi

#lists current user's home directory contents
if [ "$thorough" = "1" ]; then
homedircontents=`ls -ahl ~ 2>/dev/null`
	if [ "$homedircontents" ] ; then
		_echo -e "[-] Home directory contents:\n$homedircontents"
		_echo -e "\n"
	fi
fi

#checks for if various ssh files are accessible - this can take some time so is only 'activated' with thorough scanning switch
if [ "$thorough" = "1" ]; then
sshfiles=`find / \( -name "id_dsa*" -o -name "id_rsa*" -o -name "known_hosts" -o -name "authorized_hosts" -o -name "authorized_keys" \) -exec ls -la {} 2>/dev/null \;`
	if [ "$sshfiles" ]; then
		_echo -e "[-] SSH keys/host information found in the following locations:\n$sshfiles"
		_echo -e "\n"
	fi
fi

if [ "$thorough" = "1" ]; then
	if [ "$export" ] && [ "$sshfiles" ]; then
		mkdir $format/ssh-files/ 2>/dev/null
		for i in $sshfiles; do cp --parents $i $format/ssh-files/; done 2>/dev/null
	fi
fi

#is root permitted to login via ssh
sshrootlogin=`grep "PermitRootLogin " /etc/ssh/sshd_config 2>/dev/null | grep -v "#" | awk '{print  $2}'`
if [ "$sshrootlogin" = "yes" ]; then
  _echo -e "[-] Root is allowed to login via SSH:" ; grep "PermitRootLogin " /etc/ssh/sshd_config 2>/dev/null | grep -v "#"
  _echo -e "\n"
fi
}

environmental_info()
{
_echo -e "ENVIRONMENTAL #######################################"

#env information
envinfo=`env 2>/dev/null | grep -v 'LS_COLORS' 2>/dev/null`
if [ "$envinfo" ]; then
  _echo -e "[-] Environment information:\n$envinfo"
  _echo -e "\n"
fi

#check if selinux is enabled
sestatus=`sestatus 2>/dev/null`
if [ "$sestatus" ]; then
  _echo -e "[-] SELinux seems to be present:\n$sestatus"
  _echo -e "\n"
fi

#phackt

#current path configuration
pathinfo=`echo $PATH 2>/dev/null`
if [ "$pathinfo" ]; then
  pathswriteable=`ls -ld $(echo $PATH | tr ":" " ")`
  _echo -e "[-] Path information:\n$pathinfo"
  _echo -e "$pathswriteable"
  _echo -e "\n"
fi

#lists available shells
shellinfo=`cat /etc/shells 2>/dev/null`
if [ "$shellinfo" ]; then
  _echo -e "[-] Available shells:\n$shellinfo"
  _echo -e "\n"
fi

#current umask value with both octal and symbolic output
umaskvalue=`umask -S 2>/dev/null & umask 2>/dev/null`
if [ "$umaskvalue" ]; then
  _echo -e "[-] Current umask value:\n$umaskvalue"
  _echo -e "\n"
fi

#umask value as in /etc/login.defs
umaskdef=`grep -i "^UMASK" /etc/login.defs 2>/dev/null`
if [ "$umaskdef" ]; then
  _echo -e "[-] umask value as specified in /etc/login.defs:\n$umaskdef"
  _echo -e "\n"
fi

#password policy information as stored in /etc/login.defs
logindefs=`grep "^PASS_MAX_DAYS\|^PASS_MIN_DAYS\|^PASS_WARN_AGE\|^ENCRYPT_METHOD" /etc/login.defs 2>/dev/null`
if [ "$logindefs" ]; then
  _echo -e "[-] Password and storage information:\n$logindefs"
  _echo -e "\n"
fi

if [ "$export" ] && [ "$logindefs" ]; then
  mkdir $format/etc-export/ 2>/dev/null
  cp /etc/login.defs $format/etc-export/login.defs 2>/dev/null
fi

#last logged on user information
lastlogedonusrs=`lastlog 2>/dev/null |grep -v "Never" 2>/dev/null`
if [ "$lastlogedonusrs" ]; then
  _echo -e "[-] Users that have previously logged onto the system:\n$lastlogedonusrs"
  _echo -e "\n"
fi
}

job_info()
{
_echo -e "JOBS/TASKS ##########################################"

# list systemd timers
systemdtimers="$(for line in `systemctl list-timers 2>/dev/null | grep -oE "[a-zA-Z0-9\-]+.service"`; do echo "/lib/systemd/system/$line"; done)"
if [ "$systemdtimers" ]; then
  _echo -e "[-] Systemd timers (use 'systemctl list-timers' to see the timings):\n$systemdtimers\n"
fi

#are there any cron jobs configured
cronjobs=`ls -la /etc/cron* 2>/dev/null`
if [ "$cronjobs" ]; then
  _echo -e "[-] Cron jobs:\n$cronjobs"
  _echo -e "\n"
fi

#can we manipulate these jobs in any way
cronjobwwperms=`find /etc/cron* -perm -0002 -type f -exec ls -la {} \; -exec cat {} 2>/dev/null \;`
if [ "$cronjobwwperms" ]; then
  _echo -e "[+] World-writable cron jobs and file contents:\n$cronjobwwperms"
  _echo -e "\n"
fi

#contab contents
crontabvalue=`cat /etc/crontab 2>/dev/null`
if [ "$crontabvalue" ]; then
  _echo -e "[-] Crontab contents:\n$crontabvalue"
  _echo -e "\n"
fi

crontabvar=`ls -la /var/spool/cron/crontabs 2>/dev/null`
if [ "$crontabvar" ]; then
  _echo -e "[-] Anything interesting in /var/spool/cron/crontabs:\n$crontabvar"
  _echo -e "\n"
fi

anacronjobs=`ls -la /etc/anacrontab 2>/dev/null; cat /etc/anacrontab 2>/dev/null`
if [ "$anacronjobs" ]; then
  _echo -e "[-] Anacron jobs and associated file permissions:\n$anacronjobs"
  _echo -e "\n"
fi

anacrontab=`ls -la /var/spool/anacron 2>/dev/null`
if [ "$anacrontab" ]; then
  _echo -e "[-] When were jobs last executed (/var/spool/anacron contents):\n$anacrontab"
  _echo -e "\n"
fi

#pull out account names from /etc/passwd and see if any users have associated cronjobs (priv command)
cronother=`cut -d ":" -f 1 /etc/passwd | xargs -n1 crontab -l -u 2>/dev/null`
if [ "$cronother" ]; then
  _echo -e "[-] Jobs held by all users:\n$cronother"
  _echo -e "\n"
fi
}

services_info()
{
_echo -e "SERVICES #############################################"

#anything 'useful' in inetd.conf
inetdread=`cat /etc/inetd.conf 2>/dev/null`
if [ "$inetdread" ]; then
  _echo -e "[-] Contents of /etc/inetd.conf:\n$inetdread"
  _echo -e "\n"
fi

if [ "$export" ] && [ "$inetdread" ]; then
  mkdir $format/etc-export/ 2>/dev/null
  cp /etc/inetd.conf $format/etc-export/inetd.conf 2>/dev/null
fi

#very 'rough' command to extract associated binaries from inetd.conf & show permisisons of each
inetdbinperms=`awk '{print $7}' /etc/inetd.conf 2>/dev/null |xargs -r ls -la 2>/dev/null`
if [ "$inetdbinperms" ]; then
  _echo -e "[-] The related inetd binary permissions:\n$inetdbinperms"
  _echo -e "\n"
fi

xinetdread=`cat /etc/xinetd.conf 2>/dev/null`
if [ "$xinetdread" ]; then
  _echo -e "[-] Contents of /etc/xinetd.conf:\n$xinetdread"
  _echo -e "\n"
fi

if [ "$export" ] && [ "$xinetdread" ]; then
  mkdir $format/etc-export/ 2>/dev/null
  cp /etc/xinetd.conf $format/etc-export/xinetd.conf 2>/dev/null
fi

xinetdincd=`grep "/etc/xinetd.d" /etc/xinetd.conf 2>/dev/null`
if [ "$xinetdincd" ]; then
  _echo -e "[-] /etc/xinetd.d is included in /etc/xinetd.conf - associated binary permissions are listed below:"; ls -la /etc/xinetd.d 2>/dev/null
  _echo -e "\n"
fi

#very 'rough' command to extract associated binaries from xinetd.conf & show permisisons of each
xinetdbinperms=`awk '{print $7}' /etc/xinetd.conf 2>/dev/null |xargs -r ls -la 2>/dev/null`
if [ "$xinetdbinperms" ]; then
  _echo -e "[-] The related xinetd binary permissions:\n$xinetdbinperms"
  _echo -e "\n"
fi

initdread=`ls -la /etc/init.d 2>/dev/null`
if [ "$initdread" ]; then
  _echo -e "[-] /etc/init.d/ binary permissions:\n$initdread"
  _echo -e "\n"
fi

#init.d files NOT belonging to root!
initdperms=`find /etc/init.d/ \! -uid 0 -type f 2>/dev/null |xargs -r ls -la 2>/dev/null`
if [ "$initdperms" ]; then
  _echo -e "[-] /etc/init.d/ files not belonging to root:\n$initdperms"
  _echo -e "\n"
fi

rcdread=`ls -la /etc/rc.d/init.d 2>/dev/null`
if [ "$rcdread" ]; then
  _echo -e "[-] /etc/rc.d/init.d binary permissions:\n$rcdread"
  _echo -e "\n"
fi

#init.d files NOT belonging to root!
rcdperms=`find /etc/rc.d/init.d \! -uid 0 -type f 2>/dev/null |xargs -r ls -la 2>/dev/null`
if [ "$rcdperms" ]; then
  _echo -e "[-] /etc/rc.d/init.d files not belonging to root:\n$rcdperms"
  _echo -e "\n"
fi

usrrcdread=`ls -la /usr/local/etc/rc.d 2>/dev/null`
if [ "$usrrcdread" ]; then
  _echo -e "[-] /usr/local/etc/rc.d binary permissions:\n$usrrcdread"
  _echo -e "\n"
fi

#rc.d files NOT belonging to root!
usrrcdperms=`find /usr/local/etc/rc.d \! -uid 0 -type f 2>/dev/null |xargs -r ls -la 2>/dev/null`
if [ "$usrrcdperms" ]; then
  _echo -e "[-] /usr/local/etc/rc.d files not belonging to root:\n$usrrcdperms"
  _echo -e "\n"
fi

initread=`ls -la /etc/init/ 2>/dev/null`
if [ "$initread" ]; then
  _echo -e "[-] /etc/init/ config file permissions:\n$initread"
  _echo -e "\n"
fi

# upstart scripts not belonging to root
initperms=`find /etc/init \! -uid 0 -type f 2>/dev/null |xargs -r ls -la 2>/dev/null`
if [ "$initperms" ]; then
   _echo -e "[-] /etc/init/ config files not belonging to root:\n$initperms"
   _echo -e "\n"
fi

systemdread=`ls -lthR /lib/systemd/ 2>/dev/null`
if [ "$systemdread" ]; then
  _echo -e "[-] /lib/systemd/* config file permissions:\n$systemdread"
  _echo -e "\n"
fi

# systemd files not belonging to root
systemdperms=`find /lib/systemd/ \! -uid 0 -type f 2>/dev/null |xargs -r ls -la 2>/dev/null`
if [ "$systemdperms" ]; then
   _echo -e "[+] /lib/systemd/* config files not belonging to root:\n$systemdperms"
   _echo -e "\n"
fi

#running processes
psaux=`ps -eo user,pid,tty,command --forest | grep -v '\[' 2>/dev/null`
if [ "$psaux" ]; then
  _echo -e "[-] Running processes:\n$psaux"
  _echo -e "\n"
fi

#lookup process binary path and permissisons
procperm=`ps aux | grep -v '\[' 2>/dev/null | awk '{print $11}'|xargs -r ls -la 2>/dev/null |awk '!x[$0]++' 2>/dev/null`
if [ "$procperm" ]; then
  _echo -e "[-] Process binaries and associated permissions (from above list):\n$procperm"
  _echo -e "\n"
fi

if [ "$export" ] && [ "$procperm" ]; then
procpermbase=`ps aux | grep -v '\[' 2>/dev/null | awk '{print $11}' | xargs -r ls 2>/dev/null | awk '!x[$0]++' 2>/dev/null`
  mkdir $format/ps-export/ 2>/dev/null
  for i in $procpermbase; do cp --parents $i $format/ps-export/; done 2>/dev/null
fi
}

software_configs()
{
_echo -e "SOFTWARE #############################################"

#sudo version - check to see if there are any known vulnerabilities with this
sudover=`sudo -V 2>/dev/null| grep "Sudo version" 2>/dev/null`
if [ "$sudover" ]; then
  _echo -e "[-] Sudo version:\n$sudover"
  _echo -e "\n"
fi

#mysql details - if installed
mysqlver=`mysql --version 2>/dev/null`
if [ "$mysqlver" ]; then
  _echo -e "[-] MYSQL version:\n$mysqlver"
  _echo -e "\n"
fi

#checks to see if root/root will get us a connection
mysqlconnect=`mysqladmin -uroot -proot version 2>/dev/null`
if [ "$mysqlconnect" ]; then
  _echo -e "[+] We can connect to the local MYSQL service with default root/root credentials!\n$mysqlconnect"
  _echo -e "\n"
fi

#mysql version details
mysqlconnectnopass=`mysqladmin -uroot version 2>/dev/null`
if [ "$mysqlconnectnopass" ]; then
  _echo -e "[+] We can connect to the local MYSQL service as 'root' and without a password!\n$mysqlconnectnopass"
  _echo -e "\n"
fi

#postgres details - if installed
postgver=`psql -V 2>/dev/null`
if [ "$postgver" ]; then
  _echo -e "[-] Postgres version:\n$postgver"
  _echo -e "\n"
fi

#checks to see if any postgres password exists and connects to DB 'template0' - following commands are a variant on this
postcon1=`psql -U postgres -w template0 -c 'select version()' 2>/dev/null | grep version`
if [ "$postcon1" ]; then
  _echo -e "[+] We can connect to Postgres DB 'template0' as user 'postgres' with no password!:\n$postcon1"
  _echo -e "\n"
fi

postcon11=`psql -U postgres -w template1 -c 'select version()' 2>/dev/null | grep version`
if [ "$postcon11" ]; then
  _echo -e "[+] We can connect to Postgres DB 'template1' as user 'postgres' with no password!:\n$postcon11"
  _echo -e "\n"
fi

postcon2=`psql -U pgsql -w template0 -c 'select version()' 2>/dev/null | grep version`
if [ "$postcon2" ]; then
  _echo -e "[+] We can connect to Postgres DB 'template0' as user 'psql' with no password!:\n$postcon2"
  _echo -e "\n"
fi

postcon22=`psql -U pgsql -w template1 -c 'select version()' 2>/dev/null | grep version`
if [ "$postcon22" ]; then
  _echo -e "[+] We can connect to Postgres DB 'template1' as user 'psql' with no password!:\n$postcon22"
  _echo -e "\n"
fi

#apache details - if installed
apachever=`apache2 -v 2>/dev/null; httpd -v 2>/dev/null`
if [ "$apachever" ]; then
  _echo -e "[-] Apache version:\n$apachever"
  _echo -e "\n"
fi

#what account is apache running under
apacheusr=`grep -i 'user\|group' /etc/apache2/envvars 2>/dev/null |awk '{sub(/.*\export /,"")}1' 2>/dev/null`
if [ "$apacheusr" ]; then
  _echo -e "[-] Apache user configuration:\n$apacheusr"
  _echo -e "\n"
fi

if [ "$export" ] && [ "$apacheusr" ]; then
  mkdir --parents $format/etc-export/apache2/ 2>/dev/null
  cp /etc/apache2/envvars $format/etc-export/apache2/envvars 2>/dev/null
fi

#installed apache modules
apachemodules=`apache2ctl -M 2>/dev/null; httpd -M 2>/dev/null`
if [ "$apachemodules" ]; then
  _echo -e "[-] Installed Apache modules:\n$apachemodules"
  _echo -e "\n"
fi

#htpasswd check
htpasswd=`find / -name .htpasswd -print -exec cat {} \; 2>/dev/null`
if [ "$htpasswd" ]; then
    _echo -e "[-] htpasswd found - could contain passwords:\n$htpasswd"
    _echo -e "\n"
fi

#anything in the default http home dirs (a thorough only check as output can be large)
if [ "$thorough" = "1" ]; then
  apachehomedirs=`ls -alhR /var/www/ 2>/dev/null; ls -alhR /srv/www/htdocs/ 2>/dev/null; ls -alhR /usr/local/www/apache2/data/ 2>/dev/null; ls -alhR /opt/lampp/htdocs/ 2>/dev/null`
  if [ "$apachehomedirs" ]; then
    _echo -e "[-] www home dir contents:\n$apachehomedirs"
    _echo -e "\n"
  fi
fi

}

interesting_files()
{
_echo -e "INTERESTING FILES ####################################"

#checks to see if various files are installed
_echo -e "[-] Useful file locations:" ; which nc 2>/dev/null ; which netcat 2>/dev/null ; which wget 2>/dev/null ; which nmap 2>/dev/null ; which gcc 2>/dev/null; which curl 2>/dev/null
_echo -e "\n"

#manual check - lists out sensitive files, can we read/modify etc.
_echo -e "[-] Can we read/write sensitive files:" ; ls -la /etc/passwd 2>/dev/null ; ls -la /etc/group 2>/dev/null ; ls -la /etc/profile 2>/dev/null; ls -la /etc/shadow 2>/dev/null ; ls -la /etc/master.passwd 2>/dev/null
_echo -e "\n"

#look for private keys - thanks djhohnstein
if [ "$thorough" = "1" ]; then
privatekeyfiles=`grep -rl "PRIVATE KEY-----" /home 2>/dev/null`
	if [ "$privatekeyfiles" ]; then
  		_echo -e "[+] Private SSH keys found!:\n$privatekeyfiles"
  		_echo -e "\n"
	fi
fi

#look for AWS keys - thanks djhohnstein
if [ "$thorough" = "1" ]; then
awskeyfiles=`grep -rli "aws_secret_access_key" /home 2>/dev/null`
	if [ "$awskeyfiles" ]; then
  		_echo -e "[+] AWS secret keys found!:\n$awskeyfiles"
  		_echo -e "\n"
	fi
fi

#look for git credential files - thanks djhohnstein
if [ "$thorough" = "1" ]; then
gitcredfiles=`find / -name ".git-credentials" 2>/dev/null`
	if [ "$gitcredfiles" ]; then
  		_echo -e "[+] Git credentials saved on the machine!:\n$gitcredfiles"
  		_echo -e "\n"
	fi
fi

#list all world-writable files excluding /proc and /sys
if [ "$thorough" = "1" ]; then
wwfiles=`find / ! -path "*/proc/*" ! -path "/sys/*" -perm -2 -type f -exec ls -la {} 2>/dev/null \;`
	if [ "$wwfiles" ]; then
		_echo -e "[-] World-writable files (excluding /proc and /sys):\n$wwfiles"
		_echo -e "\n"
	fi
fi

if [ "$thorough" = "1" ]; then
	if [ "$export" ] && [ "$wwfiles" ]; then
		mkdir $format/ww-files/ 2>/dev/null
		for i in $wwfiles; do cp --parents $i $format/ww-files/; done 2>/dev/null
	fi
fi

#are any .plan files accessible in /home (could contain useful information)
usrplan=`find /home -iname *.plan -exec ls -la {} \; -exec cat {} 2>/dev/null \;`
if [ "$usrplan" ]; then
  _echo -e "[-] Plan file permissions and contents:\n$usrplan"
  _echo -e "\n"
fi

if [ "$export" ] && [ "$usrplan" ]; then
  mkdir $format/plan_files/ 2>/dev/null
  for i in $usrplan; do cp --parents $i $format/plan_files/; done 2>/dev/null
fi

bsdusrplan=`find /usr/home -iname *.plan -exec ls -la {} \; -exec cat {} 2>/dev/null \;`
if [ "$bsdusrplan" ]; then
  _echo -e "[-] Plan file permissions and contents:\n$bsdusrplan"
  _echo -e "\n"
fi

if [ "$export" ] && [ "$bsdusrplan" ]; then
  mkdir $format/plan_files/ 2>/dev/null
  for i in $bsdusrplan; do cp --parents $i $format/plan_files/; done 2>/dev/null
fi

#are there any .rhosts files accessible - these may allow us to login as another user etc.
rhostsusr=`find /home -iname *.rhosts -exec ls -la {} 2>/dev/null \; -exec cat {} 2>/dev/null \;`
if [ "$rhostsusr" ]; then
  _echo -e "[+] rhost config file(s) and file contents:\n$rhostsusr"
  _echo -e "\n"
fi

if [ "$export" ] && [ "$rhostsusr" ]; then
  mkdir $format/rhosts/ 2>/dev/null
  for i in $rhostsusr; do cp --parents $i $format/rhosts/; done 2>/dev/null
fi

bsdrhostsusr=`find /usr/home -iname *.rhosts -exec ls -la {} 2>/dev/null \; -exec cat {} 2>/dev/null \;`
if [ "$bsdrhostsusr" ]; then
  _echo -e "[+] rhost config file(s) and file contents:\n$bsdrhostsusr"
  _echo -e "\n"
fi

if [ "$export" ] && [ "$bsdrhostsusr" ]; then
  mkdir $format/rhosts 2>/dev/null
  for i in $bsdrhostsusr; do cp --parents $i $format/rhosts/; done 2>/dev/null
fi

rhostssys=`find /etc -iname hosts.equiv -exec ls -la {} 2>/dev/null \; -exec cat {} 2>/dev/null \;`
if [ "$rhostssys" ]; then
  _echo -e "[+] Hosts.equiv file and contents: \n$rhostssys"
  _echo -e "\n"
fi

if [ "$export" ] && [ "$rhostssys" ]; then
  mkdir $format/rhosts/ 2>/dev/null
  for i in $rhostssys; do cp --parents $i $format/rhosts/; done 2>/dev/null
fi

#list nfs shares/permisisons etc.
nfsexports=`ls -la /etc/exports 2>/dev/null; cat /etc/exports 2>/dev/null`
if [ "$nfsexports" ]; then
  _echo -e "[-] NFS config details: \n$nfsexports"
  _echo -e "\n"
fi

if [ "$export" ] && [ "$nfsexports" ]; then
  mkdir $format/etc-export/ 2>/dev/null
  cp /etc/exports $format/etc-export/exports 2>/dev/null
fi

if [ "$thorough" = "1" ]; then
  #phackt
  #displaying /etc/fstab
  fstab=`cat /etc/fstab 2>/dev/null`
  if [ "$fstab" ]; then
    _echo -e "[-] NFS displaying partitions and filesystems - you need to check if exotic filesystems"
    _echo -e "$fstab"
    _echo -e "\n"
  fi
fi

#looking for credentials in /etc/fstab
fstab=`grep username /etc/fstab 2>/dev/null |awk '{sub(/.*\username=/,"");sub(/\,.*/,"")}1' 2>/dev/null| xargs -r echo username: 2>/dev/null; grep password /etc/fstab 2>/dev/null |awk '{sub(/.*\password=/,"");sub(/\,.*/,"")}1' 2>/dev/null| xargs -r echo password: 2>/dev/null; grep domain /etc/fstab 2>/dev/null |awk '{sub(/.*\domain=/,"");sub(/\,.*/,"")}1' 2>/dev/null| xargs -r echo domain: 2>/dev/null`
if [ "$fstab" ]; then
  _echo -e "[+] Looks like there are credentials in /etc/fstab!\n$fstab"
  _echo -e "\n"
fi

if [ "$export" ] && [ "$fstab" ]; then
  mkdir $format/etc-exports/ 2>/dev/null
  cp /etc/fstab $format/etc-exports/fstab done 2>/dev/null
fi

fstabcred=`grep cred /etc/fstab 2>/dev/null |awk '{sub(/.*\credentials=/,"");sub(/\,.*/,"")}1' 2>/dev/null | xargs -I{} sh -c 'ls -la {}; cat {}' 2>/dev/null`
if [ "$fstabcred" ]; then
    _echo -e "[+] /etc/fstab contains a credentials file!\n$fstabcred"
    _echo -e "\n"
fi

if [ "$export" ] && [ "$fstabcred" ]; then
  mkdir $format/etc-exports/ 2>/dev/null
  cp /etc/fstab $format/etc-exports/fstab done 2>/dev/null
fi

#use supplied keyword and cat *.conf files for potential matches - output will show line number within relevant file path where a match has been located
if [ "$keyword" = "" ]; then
  _echo -e "[-] Can't search *.conf files as no keyword was entered\n"
  else
    confkey=`find / -maxdepth 4 -name *.conf -type f -exec grep -Hn $keyword {} \; 2>/dev/null`
    if [ "$confkey" ]; then
      _echo -e "[-] Find keyword ($keyword) in .conf files (recursive 4 levels - output format filepath:identified line number where keyword appears):\n$confkey"
      _echo -e "\n"
     else
	_echo -e "[-] Find keyword ($keyword) in .conf files (recursive 4 levels):"
	_echo -e "'$keyword' not found in any .conf files"
	_echo -e "\n"
    fi
fi

if [ "$keyword" = "" ]; then
  :
  else
    if [ "$export" ] && [ "$confkey" ]; then
	  confkeyfile=`find / -maxdepth 4 -name *.conf -type f -exec grep -lHn $keyword {} \; 2>/dev/null`
      mkdir --parents $format/keyword_file_matches/config_files/ 2>/dev/null
      for i in $confkeyfile; do cp --parents $i $format/keyword_file_matches/config_files/ ; done 2>/dev/null
  fi
fi

#use supplied keyword and cat *.php files for potential matches - output will show line number within relevant file path where a match has been located
if [ "$keyword" = "" ]; then
  _echo -e "[-] Can't search *.php files as no keyword was entered\n"
  else
    phpkey=`find / -maxdepth 10 -name *.php -type f -exec grep -Hn $keyword {} \; 2>/dev/null`
    if [ "$phpkey" ]; then
      _echo -e "[-] Find keyword ($keyword) in .php files (recursive 10 levels - output format filepath:identified line number where keyword appears):\n$phpkey"
      _echo -e "\n"
     else
  _echo -e "[-] Find keyword ($keyword) in .php files (recursive 10 levels):"
  _echo -e "'$keyword' not found in any .php files"
  _echo -e "\n"
    fi
fi

if [ "$keyword" = "" ]; then
  :
  else
    if [ "$export" ] && [ "$phpkey" ]; then
    phpkeyfile=`find / -maxdepth 10 -name *.php -type f -exec grep -lHn $keyword {} \; 2>/dev/null`
      mkdir --parents $format/keyword_file_matches/php_files/ 2>/dev/null
      for i in $phpkeyfile; do cp --parents $i $format/keyword_file_matches/php_files/ ; done 2>/dev/null
  fi
fi

#use supplied keyword and cat *.log files for potential matches - output will show line number within relevant file path where a match has been located
if [ "$keyword" = "" ];then
  _echo -e "[-] Can't search *.log files as no keyword was entered\n"
  else
    logkey=`find / -maxdepth 4 -name *.log -type f -exec grep -Hn $keyword {} \; 2>/dev/null`
    if [ "$logkey" ]; then
      _echo -e "[-] Find keyword ($keyword) in .log files (recursive 4 levels - output format filepath:identified line number where keyword appears):\n$logkey"
      _echo -e "\n"
     else
	_echo -e "[-] Find keyword ($keyword) in .log files (recursive 4 levels):"
	_echo -e "'$keyword' not found in any .log files"
	_echo -e "\n"
    fi
fi

if [ "$keyword" = "" ];then
  :
  else
    if [ "$export" ] && [ "$logkey" ]; then
      logkeyfile=`find / -maxdepth 4 -name *.log -type f -exec grep -lHn $keyword {} \; 2>/dev/null`
	  mkdir --parents $format/keyword_file_matches/log_files/ 2>/dev/null
      for i in $logkeyfile; do cp --parents $i $format/keyword_file_matches/log_files/ ; done 2>/dev/null
  fi
fi

#use supplied keyword and cat *.ini files for potential matches - output will show line number within relevant file path where a match has been located
if [ "$keyword" = "" ];then
  _echo -e "[-] Can't search *.ini files as no keyword was entered\n"
  else
    inikey=`find / -maxdepth 4 -name *.ini -type f -exec grep -Hn $keyword {} \; 2>/dev/null`
    if [ "$inikey" ]; then
      _echo -e "[-] Find keyword ($keyword) in .ini files (recursive 4 levels - output format filepath:identified line number where keyword appears):\n$inikey"
      _echo -e "\n"
     else
	_echo -e "[-] Find keyword ($keyword) in .ini files (recursive 4 levels):"
	_echo -e "'$keyword' not found in any .ini files"
	_echo -e "\n"
    fi
fi

if [ "$keyword" = "" ];then
  :
  else
    if [ "$export" ] && [ "$inikey" ]; then
	  inikey=`find / -maxdepth 4 -name *.ini -type f -exec grep -lHn $keyword {} \; 2>/dev/null`
      mkdir --parents $format/keyword_file_matches/ini_files/ 2>/dev/null
      for i in $inikey; do cp --parents $i $format/keyword_file_matches/ini_files/ ; done 2>/dev/null
  fi
fi

#quick extract of .conf files from /etc - only 1 level
allconf=`find /etc/ -maxdepth 1 -name *.conf -type f -exec ls {} \; | tr '\n' ' ' 2>/dev/null`
if [ "$allconf" ]; then
  _echo -e "[-] All *.conf files in /etc (recursive 1 level):\n$allconf"
  _echo -e "\n"
fi

#extract any user history files that are accessible
usrhist=`ls -la ~/.*_history 2>/dev/null`
if [ "$usrhist" ]; then
  _echo -e "[-] Current user's history files:\n$usrhist"
  _echo -e "\n"
fi

if [ "$export" ] && [ "$usrhist" ]; then
  mkdir $format/history_files/ 2>/dev/null
  for i in $usrhist; do cp --parents $i $format/history_files/; done 2>/dev/null
fi

#can we read roots *_history files - could be passwords stored etc.
roothist=`ls -la /root/.*_history 2>/dev/null`
if [ "$roothist" ]; then
  _echo -e "[+] Root's history files are accessible!\n$roothist"
  _echo -e "\n"
fi

if [ "$export" ] && [ "$roothist" ]; then
  mkdir $format/history_files/ 2>/dev/null
  cp $roothist $format/history_files/ 2>/dev/null
fi

#all accessible .bash_history files in /home
checkbashhist=`find /home -name .bash_history -print -exec tail -n 4 {} 2>/dev/null \;`
if [ "$checkbashhist" ]; then
  _echo -e "[-] Location (and possibly truncated contents) of .bash_history file(s):\n$checkbashhist"
  _echo -e "\n"
fi

#any .bak files that may be of interest
bakfiles=`find / -name *.bak -type f 2</dev/null`
if [ "$bakfiles" ]; then
  _echo -e "[-] Location and Permissions (if accessible) of .bak file(s):"
  for bak in `echo $bakfiles`; do ls -la $bak;done
  _echo -e "\n"
fi

#is there any mail accessible
readmail=`ls -la /var/mail 2>/dev/null`
if [ "$readmail" ]; then
  _echo -e "[-] Any interesting mail in /var/mail:\n$readmail"
  _echo -e "\n"
fi

#can we read roots mail
readmailroot=`head /var/mail/root 2>/dev/null`
if [ "$readmailroot" ]; then
  _echo -e "[+] We can read /var/mail/root! (snippet below)\n$readmailroot"
  _echo -e "\n"
fi

if [ "$export" ] && [ "$readmailroot" ]; then
  mkdir $format/mail-from-root/ 2>/dev/null
  cp $readmailroot $format/mail-from-root/ 2>/dev/null
fi

#lists all id's and respective group(s)
grpinfo=`for i in $(cut -d":" -f1 /etc/passwd 2>/dev/null);do id $i;done 2>/dev/null`
if [ "$grpinfo" ]; then
  _echo -e "[-] Group memberships:\n$grpinfo"
  _echo -e "\n"
fi
}

docker_checks()
{

#specific checks - check to see if we're in a docker container
dockercontainer=` grep -i docker /proc/self/cgroup  2>/dev/null; find / -name "*dockerenv*" -exec ls -la {} \; 2>/dev/null`
if [ "$dockercontainer" ]; then
  _echo -e "[+] Looks like we're in a Docker container:\n$dockercontainer"
  _echo -e "\n"
fi

#specific checks - check to see if we're a docker host
dockerhost=`docker --version 2>/dev/null; docker ps -a 2>/dev/null`
if [ "$dockerhost" ]; then
  _echo -e "[+] Looks like we're hosting Docker:\n$dockerhost"
  _echo -e "\n"
fi

#specific checks - are we a member of the docker group
dockergrp=`id | grep -i docker 2>/dev/null`
if [ "$dockergrp" ]; then
  _echo -e "[+] We're a member of the (docker) group - could possibly misuse these rights!\n$dockergrp"
  _echo -e "\n"
fi

#specific checks - are there any docker files present
dockerfiles=`find / -name Dockerfile -exec ls -l {} 2>/dev/null \;`
if [ "$dockerfiles" ]; then
  _echo -e "[-] Anything juicy in the Dockerfile:\n$dockerfiles"
  _echo -e "\n"
fi

#specific checks - are there any docker files present
dockeryml=`find / -name docker-compose.yml -exec ls -l {} 2>/dev/null \;`
if [ "$dockeryml" ]; then
  _echo -e "[-] Anything juicy in docker-compose.yml:\n$dockeryml"
  _echo -e "\n"
fi
}

lxc_container_checks()
{

#specific checks - are we in an lxd/lxc container
lxccontainer=`grep -qa container=lxc /proc/1/environ 2>/dev/null`
if [ "$lxccontainer" ]; then
  _echo -e "[+] Looks like we're in a lxc container:\n$lxccontainer"
  _echo -e "\n"
fi

#specific checks - are we a member of the lxd group
lxdgroup=`id | grep -i lxd 2>/dev/null`
if [ "$lxdgroup" ]; then
  _echo -e "[+] We're a member of the (lxd) group - could possibly misuse these rights!\n$lxdgroup"
  _echo -e "\n"
fi
}

footer()
{
_echo -e "SCAN COMPLETE ####################################"
}

call_each()
{
  system_info
  job_info
  user_info
  software_configs
  interesting_files
  docker_checks
  lxc_container_checks
  environmental_info
  services_info
  footer
}

while getopts "h:k:r:e:st" option; do
 case "${option}" in
    k) keyword=${OPTARG};;
    r) report=${OPTARG}"-"`date +"%d-%m-%y"`;;
    e) export=${OPTARG};;
    s) sudopass=1;;
    t) thorough=1;;
    h) usage; exit;;
    *) usage; exit;;
 esac
done

call_each | tee -a $report 2> /dev/null
#EndOfScript

export TIME_STYLE='locale'