## How to Install for smartos

### Recommend

TCP Wrapper should be enable.

```
# turn on if disable.
inetadm -M tcp_wrappers=true
```

### Apply patch

#### using git apply

```
git checkout 0.8.12
git apply 0.8.12_smartos.patch
```

#### using gpatch

```
# gpatch -p1 < 0.8.12_smartos.patch 
patching file fail2ban-client
patching file fail2ban-server
patching file files/solaris-fail2ban.xml
patching file files/solaris-svc-fail2ban
patching file setup.cfg
patching file setup.py
```

### Install

```
python setup.py install
svccfg import files/solaris-fail2ban.xml
mkdir /var/svc/method
cp files/solaris-svc-fail2ban /var/svc/method/svc-fail2ban
chmod +x /var/svc/method/svc-fail2ban
```

### enable service fail2ban

```
svcadm enable fail2ban
```

### Example

ban ssh by tcpwrapper.

```
# cat /etc/fail2ban/jail.local 

[ssh-tcpwrapper]

enabled = true
filter = sshd
action = hostsdeny[daemon_list=sshd]
logpath = /var/log/authlog
```

ban ssh by ipfilter.

```
# cat /etc/fail2ban/jail.local 

[ssh-ipfilter]

enabled = true
filter = sshd
action = ipfilter
logpath = /var/log/authlog
```

