#
# Violent Python Chapter #1
# Vuln Scanner
# By: Marin Alcaraz
#

import sys
import os
import socket

def retBanner(ip, port):
    try:
        socket.setdefaulttimeout(2)
        s = socket.socket()
        s.connect((ip, port))
        banner = s.recv(1024)
        return banner
    except Exception, e:
       return  str(e)

def checkFile(filename):
    try:
        if not os.path.isfile(filename):
            raise Exception("File doesn't exist")
            return -1
        if not os.access(filename, os.R_OK):
            raise Exception("Permission Denied")
        f = open(filename, 'r')
        return f
    except Exception, e:
        print str(e)
        return -1


def checkVulns(banner, filename):
    print "[+] Reading Vulnerable Banner list from: " + filename
    f = checkFile(filename)
    for line in f.readlines():
        print "[+] Checking for banner: " + line.strip('\n')
        if line.strip('\n') in banner:
            print "[+] Server is Vulnerable: " + banner.strip('\n')
        else:
            print '[-] FTP Server is not vulnerable'
    return

def main():
    portList = [21, 22, 25, 80, 110, 443]
    if (len(sys.argv) == 2):
        filename = sys.argv[1]
    else:
        filename = "vuln_banners.txt"
    for x in range(1, 255):
        ip = '192.168.95.' + str(x)
        for port in portList:
            banner = retBanner(ip, port)
            if banner:
                print '[+] ' + ip + ': ' + banner
                if (checkVulns(banner, filename) == -1):
                    return


if __name__ == '__main__':
    main()
