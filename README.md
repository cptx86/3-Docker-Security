## Docker Security
#### Docker Content Trust 
[Official Repositories on Docker Hub] https://docs.docker.com/docker-hub/official_repos/
#### Setup Docker to Run Without Requiring sudo
```sudo gpasswd -a `id -un` docker```
```
docker run hello-world
sudo service docker stop
sudo service docker start
sudo service docker restart
```
#### Modify Docker Daemon Configuration File with Log Level
```sudo vi /etc/default/docker```
```
DOCKER_OPTS="\
      --graph=/usr/local/docker \
      --dns 192.168.1.202 \
      --dns 8.8.8.8 \
      --dns 8.8.4.4 \
      --log-level error \
      "
```
```
sudo service docker restart
sudo cat /var/log/upstart/docker.log
```
#### Restrict Containers 'Linux Capabilities'
```docker run --help```
#### Seccomp Security Profiles for Docker
[Seccomp security profiles for Docker] https://github.com/docker/docker/blob/master/docs/security/seccomp.md
#### Encrypt Private Data Directory
[eCryptfs] https://help.ubuntu.com/12.04/serverguide/ecryptfs.html
#### Virtual Private Networking (VPN)
[OpenVPN] https://help.ubuntu.com/lts/serverguide/openvpn.html


#### Additional Reading about Securing Docker in a Linux System
[Docker Security] http://docs.docker.com/articles/security
https://docs.docker.com/engine/security/security/

[Docker Gets Serious About Security] http://www.eweek.com/security/docker-gets-serious-about-security.html

[Cross-Site Scripting (XSS)] https://www.owasp.org/index.php/Cross-site_Scripting_%28XSS%29

[Docker Bench for Security is a script that checks for dozens of common best-practices around deploying Docker containers in production:] https://github.com/docker/docker-bench-security

[Ubuntu Security] https://help.ubuntu.com/community/Security

[Ubuntu security notices] www.ubuntu.com/usn/

[Linux Kernel Security (SELinux vs AppArmor vs Grsecurity)] http://www.cyberciti.biz/tips/selinux-vs-apparmor-vs-grsecurity.html

[OpenSSL] https://help.ubuntu.com/community/OpenSSL

[Center for Internet Security Docker 1.6 Benchmark v1.0.0] https://benchmarks.cisecurity.org/downloads/show-single/index.cfm?file=docker16.100

[Subscribing to ubuntu-security-announce] https://lists.ubuntu.com/mailman/listinfo/ubuntu-security-announce

[Let’s Encrypt is a new Certificate Authority] https://letsencrypt.org/
### AppArmor
#### Install AppArmor Profiles, Documentation, and Utilities
```sudo apt-get install apparmor-utils apparmor-docs apparmor-profiles```
#### AppArmor Profiles
```cat /etc/apparmor.d/docker```
#### List the Current Status of AppArmor
```sudo apparmor_status```
#### Additional Reading about AppArmor
[Ubuntu AppArmor] https://help.ubuntu.com/14.04/serverguide/apparmor.html

[Ubuntu AppArmor] https://help.ubuntu.com/community/AppArmor

[AppArmor profile generator for Docker containers] https://github.com/jfrazelle/bane

[Ubuntu AppArmor Profiles] https://wiki.ubuntu.com/SecurityTeam/KnowledgeBase/AppArmorProfiles

[AppArmor security profiles for Docker] https://github.com/docker/docker/blob/master/docs/security/apparmor.md
### SSH
#### Version of OpenSSH
```
ssh -V
dpkg --list openssh\*
```
#### Make SSH a More Secure
```sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.org```
[Service Name and Transport Protocol Port Number Registry]  https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml?&page=1
```
sudo vi /etc/ssh/sshd_config
sudo service ssh restart
```
#### Copy SSH Public Key to Remote Host
```
ssh-copy-id three@192.168.1.203
ssh three@192.168.1.203
ssh -vvv three@192.168.1.203
```
#### Make SSH a More Secure
```
sudo vi /etc/ssh/sshd_config
sudo service ssh restart
```
#### Debug SSH
```ssh -vvv <user-name>@<IP-Address>```
#### Other Network Commands
```
nmap 192.168.1.202
nc -zv 127.0.0.1 22
sudo netstat -natp
ip a
ifconfig -a
ip a show eth0
ifconfig eth0
dig +short myip.opendns.com @resolver1.opendns.com
```
#### Additional Reading about SSH
[How SSH Works]  https://www.youtube.com/watch?v=zlv9dI-9g1U

[SSH Tutorial for Linux]  http://support.suso.com/supki/SSH_Tutorial_for_Linux

[Setting Up an SSH Key]  https://www.youtube.com/watch?v=-J9wUW5NhOQ

[SSH and SCP: Howto, tips & tricks]  https://linuxacademy.com/blog/linux/ssh-and-scp-howto-tips-tricks/


### Transport Layer Security (TLS)
[Transport Layer Protection Cheat Sheet]  https://www.owasp.org/index.php/Transport_Layer_Protection_Cheat_Sheet
#### Installation of TLS
```sudo apt-get install ssl-cert openssl ca-certificates```
#### Create Self-Signed Certificate Keys for Client and Server
```
mkdir -p $HOME/.docker/docker-certs
chmod 700 $HOME/.docker/docker-certs
cd $HOME/.docker/docker-certs
pwd
````
#### Create Self-Signed Certification Authority (CA) private and public keys
```
openssl genrsa -aes256 -out ca-key.pem 4096
openssl req -new -x509 -days 365 -key ca-key.pem -sha256 -out ca.pem
```
#### Create a server key and certificate signing request (CSR) for host two (two.cptx86.com).
```
openssl genrsa -out server-two-key.pem 4096
openssl req -subj "/CN=two.cptx86.com" -sha256 -new -key server-two-key.pem -out server-two.csr
```
Sign the public key with the digital certificate authority (CA)
```
echo subjectAltName = IP:192.168.1.202,IP:127.0.0.1 > extfile.txt
openssl x509 -req -days 365 -sha256 -in server-two.csr -CA ca.pem -CAkey ca-key.pem -CAcreateserial -out server-two-cert.pem -extfile extfile.txt
```
#### Create a client key and certificate signing request for client authentication
```
openssl genrsa -out key.pem 4096
openssl req -subj '/CN=client' -new -key key.pem -out client.csr
```
#### Create an extensions config file to make the key suitable for client authentication.
```
echo extendedKeyUsage = clientAuth > extfile.txt
openssl x509 -req -days 365 -sha256 -in client.csr -CA ca.pem -CAkey ca-key.pem -CAcreateserial -out cert.pem -extfile extfile.txt
```
#### Remove the two certificate signing requests (CSR) and set file permissions.
```
rm -v client.csr server-two.csr
chmod -v 0400 ca-key.pem key.pem server-key.pem
chmod -v 0444 ca.pem server-cert.pem cert.pem
sudo mkdir -p /etc/docker/certs.d/daemon
sudo chmod 700 /etc/docker/certs.d/daemon
sudo cp ca.pem /etc/docker/certs.d/daemon
sudo cp server-two-cert.pem /etc/docker/certs.d/daemon
sudo cp server-two-key.pem /etc/docker/certs.d/daemon
```










