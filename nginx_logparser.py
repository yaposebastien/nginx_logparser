#!/usr/bin/env python3.6

from __future__ import absolute_import, division, print_function


import paramiko
import weakref
import os
import json
import signal
import subprocess


from dotenv import load_dotenv


load_dotenv()

#Les deux lignes suivantes permettent la non apparution a l'ecran des  messages d interruptions
signal.signal(signal.SIGPIPE, signal.SIG_DFL) # IOError for Broken Pipe
signal.signal(signal.SIGINT, signal.SIG_DFL) # Interruption de clavier

#Defining our class LogParser
class Logparser:
    def __init__(self, ipLogParser, countryLogParser):
        self.ipLogParser = ipLogParser
        self.countryLogParser = countryLogParser

    def parseLogWebServer(hostname, port, username, password):
       sshClient = paramiko.SSHClient()                                   # create SSHClient instance
       sshClient.set_missing_host_key_policy(paramiko.AutoAddPolicy())    # AutoAddPolicy automatically adding the hostname and new host key
       sshClient.load_system_host_keys()
       sshClient.connect(hostname, port, username, password)
       stdin, stdout, stderr = sshClient.exec_command('cat /var/log/nginx/access.log | cut -d "-" -f1 | uniq')
       
       #Defining a list to store each IP
       for ip in stdout:
           print(ip)
           print(subprocess.call(['/usr/bin/geoiplookup', str(ip)]))
       



if __name__ == '__main__':

    print(os.environ.get('WEBSERVER_USER'))
    print(os.environ.get('WEBSERVER_PASSWD'))
    print(os.environ.get('WEBSERVER_PORT'))
    print(os.environ.get('WEBSERVER_IP'))
   
    Logparser.parseLogWebServer(os.environ.get('WEBSERVER_IP'), os.environ.get('WEBSERVER_PORT'), 
                                        os.environ.get('WEBSERVER_USER'), os.environ.get('WEBSERVER_PASSWD'))
        
