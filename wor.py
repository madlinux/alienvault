#!/usr/bin/env python
"""

Description     :

Version         : 1.0

"""

import subprocess
import os
import re
import string
import optparse
from netaddr import IPNetwork
import MySQLdb
import logging
import logging.handlers
from ConfigParser import SafeConfigParser
import socket, struct


class MySQLBase(object):
    ''' 
    Description 
                mysqlSQLBase Class 
                    connection   Method
                    print() refactored with logging()
                    Date    7 Jan 2021
                    TO Test all logging()  
    '''
    def __init__(self, stmt=None):
        #logging.debug("IN {0} OBJECT".format(self.__class__.__name__))
        #logging.basicConfig(filename='stmt.log', encoding='utf-8', level=logging.WARN)
        self.stmt = stmt
        self.template1="{0}"
        
    def set_stmt(self, stmt):
        self.stmt = stmt
        logging.error(self.template1.format("stmt val=" + str(self.stmt)))

    def connection(self,database):
        """Creates a database connection and returns the cursor.  Host is hardwired to 'localhost'."""
        #self.stmt="show databases"
        self.database=database
        try:
            self.mydb = MySQLdb.connect(user='readOnlyUser',passwd='UTrSrN8cDfrLtRsn',host="192.168.1.10",db=self.database)
            self.cur = self.mydb.cursor()
            logging.error(self.template1.format("DB CONNECTION OK"))
        except MySQLdb.Error:
            logging.error(self.template1.format("DB CONNECTION FAILED"))
            raise MySQLdb.Error
        except MySQLdb.Warning:
            pass

        try:
            self.results=self.cur.execute(self.stmt)
            logging.error(self.template1.format("stmt val=" + str(self.results)))
        except Exception:
            logging.error(self.template1.format("EXCEPTION IN CONNECTION METHOD"))

        with self.mydb.cursor() as cursor:
            cursor.execute(self.stmt)
            for x in cursor.fetchall():
                logging.error(self.template1.format(x))
            self.mydb.commit()

    def execute(self):
        logging.debug("DEBUG IN THE execute METHOD")
        try:
            logging.debug("THE STMT ==>"  + self.stmt)
            self.cur.execute(self.stmt)
            logging.error("DB STMT OK")
            logging.error("STMT RESULTS ==>"  + self.cur)
          #  self.mydb.disconnect()
        except MySQLdb.Error:
            logging.error(MySQLdb.Error)
            logging.error("EXCEPTION OCCURED")
        except MySQLdb.Warning:
            pass

    def _disconnect(self,var):
        self.mydb = var
        try:
            self.mydb.disconnect()
            logging.debug("DB CONNECTION CLOSED OK")
        except MySQLdb.Error:
            logging.debug(MySQLdb.Error)
            logging.debug("DB CONNECTION CLOSED FAILED")
            raise MySQLdb.Error

    def print_stmt(self,stmt):
        logging.debug("DEBUG in the print_stmt METHOD and the GENERIC STMT value ==>"  + stmt)

    def test(self):
        logging.debug("DEBUG YES the test METHOD OK")

class Base(object):

    def __init__(self):
        '''What'''
        #print("in the Base init")
        self.temp_val1="ERROR reading the wmi.config file\nPlease check the wmi.config file"
        self.temp_val2="{0}\n{1}\n{2}"
        self.temp_val3="{0}\n{1}\n{2}"
        self.temp_val4="{0}\n{1}\n{2}"
        self.template1="{0}"
        self.template2="{0} {1}"
        self.template3="{0} {1} {2}"
        logging.basicConfig(filename='exam.log', encoding='utf-8', level=logging.WARN)
        self.read_config_file()

    def decoding(self):
        '''What'''
        #print("Base.decoding()")
        #logging.error("Base.decoding()")
        self.credentials = self.cred
        #logging.error(self.credentials)
        self.cmd = "echo " + "'" + str(self.credentials) + "'" + " | openssl enc -aes-256-cbc -a -d -salt -pass pass:saltyLake"
        #logging.error(self.cmd)
        try:
                l  = subprocess.Popen(self.cmd,shell=True,stdout=subprocess.PIPE)
                output=l.stdout.readlines()
                #print(self.template1.format("output value type --> " + str(type(output))))
                #print(self.template1.format("output lenght --> " + str(len(output))))
                self.plaintext=str(output[0])

        except Exception:
                logging.error(self.template2.format("ERROR  on line 129 trying to readlines in decoding()",Exception))
    
    def read_config_file(self):
        self.cfg = SafeConfigParser()
        try:
            self.cfg.read('wmi.config')
            self.cred=self.cfg.get('dev', 'cred')
            self.debug=self.cfg.get('dev', 'debug')
            self.level=self.cfg.get('dev', 'level')
            self.log_dir=self.cfg.get('dev', 'level')
            #self.get_values()
        except Exception:
            #print(self.temp_val1)
            logging.error(" on line 143" + self.temp_val1)
            os._exit(0)
            
    def get_values(self):
        print(self.temp_val2.format("DEBUG cred value ==>" + self.cred, 
                "DEBUG debug value ==>" + self.debug, 
                "DEBUG level value ==>" + self.level))
        logging.error("DEBUG cred value ==>" + self.cred)
        logging.error("DEBUG debug value ==>" + self.debug)
        logging.error("DEBUG level value ==>" + self.level)

class WmiChildClass(Base):

        def __init__(self, network=None, credentials=None):
                Base.__init__(self)
                self.template1="{0}"
                self.template2="{0}\n{1}"
                self.template3="{0}\n{1}\n{2}"
                '''IF THE DEBUG is SET TO on in the wmi.config FILE'''
                logging.error('error IS SET TO logfile IN THE WMI_CHILD_CLASS')
                self.av_dbconnection=MySQLBase()
                self.network = network
                self.outfile = "/opt/customScripts/output/"
                self.out_file=""
                self.credentials = credentials
                self.network=network
                self.constant1="DEBUG:outfile value ==>"
                self.constant2="DEBUG:{0}::"
                self.read_config_file()
                self.output=""
                self.name=""
                self.bootdevice=""
                
        def set_cmd(self,cmd):
                #logging.error("in set_cmd method")
                self.cmd = cmd
                #logging.debug(cmd)

        def wmiscan_no_debug(self, overload=None, val_tmp=None):
                '''WHAT
                DESCRIPTION: to refactor the wmiscan methods
                '''
                for ip in IPNetwork(self.network):
                        self.data=""
                        self.YES=True
                        response = os.system("ping -c 1 " + str(ip))
                        if response == 0:
                            #outfile = str(ip) + ".txt"
                            outfile = self.outfile + "update_records.csv"
                            '''note :   refactor -U to variable'''
                            self.wmi = 'wmic -U ' + self.plaintext.strip() + ' //' + str(ip) + ' "SELECT BootDevice,Name FROM Win32_OperatingSystem"'
                            l  = subprocess.Popen(self.wmi,shell=True,stdout=subprocess.PIPE)
                            output = l.stdout.readlines()
                            self.out_put = output[2].strip()
                            
                            ''' here is the problem'''
                            logging.error(self.template1.format("LINE 198 out_put val=" + str(self.out_put) + " for readlines"))
                            
                            for val in self.out_put:
                                logging.error(self.template1.format("LINE 198 the val=" + val.strip() + " for output loop"))
                            
                            try:
                                all_val = self.out_put.decode('utf-8')
                                all_val = (self.out_put).split("|")
                                self.bootdevice = (all_val[0])
                                #logging.error(self.template1.format("LINE 200 bootdevice val=" + str(self.bootdevice)))
                            except Exception:
                                logging.error("EXCEPTION on LINE 203 output[2] doesnot exist " + str(Exception))

                            try:
                                #logging.error(self.template1.format("" + ))
                                self.name=all_val[1]
                                logging.error(self.template1.format("LINE 213 name val=" + str(self.name)))
                                #name = (all_val).split("|")
                                #self.name=name[0]
                                #logging.error(self.template1.format("LINE 207 name val=" + str(self.name)))
                            except Exception:
                                logging.error("EXCEPTION on line 209 output[3] doesnot exist " + str(Exception))
                            
                        
                            #self.data=self.bootdevice
                            self.data=self.bootdevice + "," + self.name + '\n'
                            logging.error(self.template1.format("LINE_NUM=232 data val=" + self.data))
                            if re.findall(r"ERROR", self.data):
                                self.YES=False
                                logging.error(self.template1.format("LINE_NUM=235 error found in data val=" + self.data))
                            else:
                                self.YES=True

                            if len(output) > 2 and self.YES:
                                ''' self.Write() refactor to csv FILE with ALL data values'''
                                #self.Write(outfile,OS)
                                self.Write(outfile,self.data)
                                outfile=""
                                self.data=None
                                try:
                                    self.av_dbconnection.test()
                                except Exception:
                                    logging.debug("DEBUG EXCEPTION in self.av_dbconnection.test()")
                                
                                '''SQL BACKUP STMT'''
                                stmt = """SELECT INET6_NTOA(i.ip), p.value from host_ip i, host_properties p WHERE HEX(i.host_id) = HEX(p.host_id) and INET6_NTOA(ip) = "%s" """ % (ip)
                                self.av_dbconnection.set_stmt(stmt)
                                self.av_dbconnection.connection("alienvault")
                        else:
                            OS = ""
                os.system('clear')
        
        def Write(self,outfile,data):
                '''What'''
                self.data=data
                logging.error(self.template1.format("LINE_NUM=259 in Write() data val=" + self.data + " before appending"))
                #logging.debug("in the Write method outfile value >>"  + outfile)
                try:
                    text_file = open(outfile,"a+")
                except Exception:
                    logging.error("ERROR in Write() opening file"  + outfile)
                text_file.write(self.data)
                text_file.close()
                self.data=None
                logging.error(self.template1.format("LINE_NUM=267 in Write() AFTER appending data val=" + str(self.data)))



                

        def get_credentials(self):
                """Call Base.dencoding"""
                #print("IN wmiChildClass.get_credentials()")
                #logging.error(self.template1.format("IN wmiChildClass.get_credentials()"))
                self.decoding()


def main():
        
        cidr=str(input("Please enter Network Address in CIDR format\ne.g 192.168.1.0/24\n"))

        
        '''
        tmp_list=cidr.split("/")
        ip=tmp_list[0]
        net=tmp_list[1]
        print("ip val=" + ip + ",net val=" + net)

        address = dottedQuadToNum('"' + str(ip) + '"')
        networka = networkMask("10.0.0.0",24)
        networkb = networkMask("192.168.0.0",24)
        print (address,networka,networkb)
        print addressInNetwork(address,networka)
        print addressInNetwork(address,networkb)
        '''

        ''' READ THE CONFIG FILE FOR DEBUG VALUE'''
        #logging.error('Debug ON network val=' + cidr)
        obj1 = WmiChildClass(cidr,None)
        obj1.get_credentials()
        obj1.wmiscan_no_debug()

        
if __name__ == "__main__":
    main()

