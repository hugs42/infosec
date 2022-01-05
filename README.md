# infosec

### sheetcheat

| Action        | Command      |
| ------|-----|
| Show our IP address | ``ifconfig/ip a`` |
| Run nmap on an IP | `` nmap 10.129.42.253 `` |
| Run an nmap script scan on an IP | `` nmap -sV -sC -p- 10.129.42.253 `` |
| List various available nmap scripts | `` locate scripts/citrix	  `` |
| Run an nmap script on an IP | `` nmap --script smb-os-discovery.nse -p445 10.10.10.40 `` |
| Grab banner of an open port | `` netcat 10.10.10.10 22 `` |
| List SMB Shares | `` smbclient -N -L \\\\10.129.42.253 `` |
| Connect to an SMB share | `` smbclient \\\\10.129.42.253\\users `` |
| Scan SNMP on an IP | `` snmpwalk -v 2c -c public 10.129.42.253 1.3.6.1.2.1.1.5.0 `` |
