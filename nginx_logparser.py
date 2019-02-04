#!/usr/bin/env python3.6

from __future__ import absolute_import, division, print_function
import paramiko
import os
import signal
import subprocess
from pymongo import MongoClient
from dotenv import load_dotenv
import re

load_dotenv()

#Les deux lignes suivantes permettent la non apparution a l'ecran des  messages d interruptions
signal.signal(signal.SIGPIPE, signal.SIG_DFL) # IOError for Broken Pipe
signal.signal(signal.SIGINT, signal.SIG_DFL) # Interruption de clavier

#Defining our class LogParser
class Logparser:
    def __init__(self, remote_addr, time_local, http_user_agent, countryLog):
        self.remote_addr = remote_addr
        self.time_local = time_local
        self.http_user_agent = http_user_agent
        self.countryLog = countryLog

    def extractSingleLog(hostname, port, username, password):
       sshClient = paramiko.SSHClient()                                   # create SSHClient instance
       sshClient.set_missing_host_key_policy(paramiko.AutoAddPolicy())    # AutoAddPolicy automatically adding the hostname and new host key
       sshClient.load_system_host_keys()
       sshClient.connect(hostname, port, username, password)
       stdin, stdout, stderr = sshClient.exec_command('cat /var/log/nginx/access.log | cut -d "-" -f 1,3,5| uniq') #Catch the IP, date and time
      
       #Defining a list to store each IP
       for singleLog in stdout:
           Logparser.extractRemoteAddress(singleLog)
           Logparser.extractCountry(singleLog)
           
           '''
           print('IP address: ' +str(singleLog))
           checkCountry = subprocess.Popen(['/usr/bin/geoiplookup', str(singleLog)], stdout=subprocess.PIPE)
           country = checkCountry.stdout.read()
           print('Country is:' + str(country))
            '''
    #Function to extract the remote IP address of the single line of log
    def extractRemoteAddress(Param_singleLog):
        remote_add_schema = re.compile('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
        find_remote_addr = remote_add_schema.findall(Param_singleLog)
        for iplog in find_remote_addr:
            print(iplog)

    #Function to extract the country of the remote IP address
    def extractCountry(Param_singleLog):
        checkCountry = subprocess.Popen(['/usr/bin/geoiplookup', str(Param_singleLog)], stdout=subprocess.PIPE)
        country = checkCountry.stdout.read()
        print('Country is:' + str(country))


    #def extractTimeLocal():

    #def extractHttpUserAgent():

    
    


if __name__ == '__main__':

    Logparser.extractSingleLog(os.environ.get('WEBSERVER_IP'), os.environ.get('WEBSERVER_PORT'), 
                                        os.environ.get('WEBSERVER_USER'), os.environ.get('WEBSERVER_PASSWD'))
    
   
    
        
