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
    def __init__(self, remote_addr, time_local, request, status, http_user_agent, countryLog):
        self.remote_addr = remote_addr
        self.time_local = time_local
        self.request = request
        self.status =  status
        self.http_user_agent = http_user_agent
        self.countryLog = countryLog

    def extractSingleLog(hostname, port, username, password):
       sshClient = paramiko.SSHClient()                                   # create SSHClient instance
       sshClient.set_missing_host_key_policy(paramiko.AutoAddPolicy())    # AutoAddPolicy automatically adding the hostname and new host key
       sshClient.load_system_host_keys()
       sshClient.connect(hostname, port, username, password)
       stdin, stdout, stderr = sshClient.exec_command('cat /var/log/nginx/access.log') #Catch the IP, date and time
      
       #Defining a list to store each IP
       for singleLog in stdout:
          
          
           Logparser.extractRemoteAddress(singleLog)
           Logparser.extractCountry(singleLog)
           Logparser.extractTimeLocal(singleLog)
           Logparser.extractRequest(singleLog)
           Logparser.extractStatus(singleLog)
           Logparser.extractHttpUserAgent(singleLog)

           print("Remote addr:" +str(Logparser.extractRemoteAddress(singleLog)))
           print("Remote country: " +str(Logparser.extractCountry(singleLog)))
           print("Remote time local: " +str(Logparser.extractTimeLocal(singleLog)))
           print("Request: " +str(Logparser.extractRequest(singleLog)))
           print("Status: " +str(Logparser.extractStatus(singleLog)))
           print("Http user agent: " +str(Logparser.extractHttpUserAgent(singleLog)))
           

           
    #Function to extract the remote IP address of the single line of log
    def extractRemoteAddress(Param_singleLog):
        remote_add_schema = re.compile('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
        find_remote_addr = remote_add_schema.findall(Param_singleLog)
        for iplog in find_remote_addr:
            return iplog

    #Function to extract the country of the remote IP address of Nginx
    def extractCountry(Param_singleLog):
        checkCountry = subprocess.Popen(['/usr/bin/geoiplookup', str(Param_singleLog)], stdout=subprocess.PIPE)
        country = checkCountry.stdout.read()
        return country[23:]

    #Function to extract the date and time of Nginx log
    def extractTimeLocal(Param_singleLog):
        time_local_schema = re.compile('\d{1,2}\/\D{3}\/\d{4}\:\d{2}\:\d{2}\:\d{2}')
        time_local = time_local_schema.findall(Param_singleLog)
        for time_local in time_local:
            return time_local

    #Function to extract the request of the log
    def extractRequest(Param_singleLog):
        request_schema = re.compile('"\D{3,}')
        request = request_schema.findall(Param_singleLog)
        for request in request:
            return request
    
    #Function to extract the status of the log
    def extractStatus(Param_singleLog):
        status_schema = re.compile(' \d{3}')
        status = status_schema.findall(Param_singleLog)
        for status in status:
            return status
       
    #Function to extract the user agent of the log
    def extractHttpUserAgent(Param_singleLog):
        http_agent_schema = re.compile(' "-"+ \D{2,}')
        http_agent = http_agent_schema.findall(Param_singleLog)
        for http_agent in http_agent:
            return http_agent


    #Save in object
    # Save into database
    # Get html page to read log
    # Filter    

if __name__ == '__main__':

    Logparser.extractSingleLog(os.environ.get('WEBSERVER_IP'), os.environ.get('WEBSERVER_PORT'), 
                                        os.environ.get('WEBSERVER_USER'), os.environ.get('WEBSERVER_PASSWD'))
    
   
    
        
