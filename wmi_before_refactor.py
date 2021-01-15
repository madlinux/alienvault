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
import socket
import struct
import inspect
import csv


class Base(object):

    def __init__(self):
        '''
        Description     
                        template1 = logging.error(self.template1.format())
        '''

        #print("in the Base init")
        self.temp_val1 = "ERROR reading the wmi.config file\nPlease check the wmi.config file"
        self.temp_val2 = ""
        self.temp_val3 = ""
        self.temp_val4 = ""
        self.template1 = "{0}"
        self.template2 = "LINE_NUM={0} {1}"
        self.template3 = "LINE#{0} CLASS={1} METHOD={2} MSG={3} INFO={4} ERROR={5}"
        logging.basicConfig(filename='debug.log',
                            encoding='utf-8', level=logging.WARN)
        #self.line_info(class_name='Base', msg='just for INFO testing', info='Testing the Log Template', error='JUST a TEST')
        self.read_config_file()

    def line_info(self, class_name=None, msg=None, info=None, error=None):
        f = inspect.currentframe()
        i = inspect.getframeinfo(f.f_back)
        self.fr_line = str(i.lineno)
        self.fr_func = str(i.function)
        logging.error(self.template3.format(
            self.fr_line, class_name, self.fr_func, msg, info, error))

    def decoding(self):
        '''What'''
        # print("Base.decoding()")
        # logging.error("Base.decoding()")
        self.credentials = self.cred
        # logging.error(self.credentials)
        self.cmd = "echo " + "'" + \
            str(self.credentials) + "'" + \
            " | openssl enc -aes-256-cbc -a -d -salt -pass pass:saltyLake"
        # logging.error(self.cmd)
        try:
            l = subprocess.Popen(self.cmd, shell=True, stdout=subprocess.PIPE)
            output = l.stdout.readlines()
            #print(self.template1.format("output value type --> " + str(type(output))))
            #print(self.template1.format("output lenght --> " + str(len(output))))
            self.plaintext = str(output[0])

        except Exception:
            self.line_info(
                class_name='Base', msg="trying to readlines in decoding()", error=str(Exception))
            #logging.error(self.template2.format("ERROR  on line 129 trying to readlines in decoding()",Exception))

    def read_config_file(self):
        self.cfg = SafeConfigParser()
        try:
            self.cfg.read('wmi.config')
            self.cred = self.cfg.get('dev', 'cred')
            self.debug = self.cfg.get('dev', 'debug')
            self.level = self.cfg.get('dev', 'level')
            #self.line_info(msg="line 85 test Message")
            #self.log_dir=self.cfg.get('dev', 'level')
            # self.get_values()
        except Exception:
            # print(self.temp_val1)
            self.line_info(class_name='Base', msg="Exception on line 90")
            #logging.error("fdsfsdfsdf inb line 87")
            os._exit(0)

    def get_values(self):
        #print(self.temp_val2.format("DEBUG cred value ==>" + self.cred, "DEBUG debug value ==>" + self.debug, "DEBUG level value ==>" + self.level))
        logging.error(self.fr_line, self.fr_func)
        logging.error("DEBUG cred value ==>" + self.cred)
        logging.error("DEBUG debug value ==>" + self.debug)
        logging.error("DEBUG level value ==>" + self.level)


class MySQLBase(Base):

    def __init__(self, stmt=None):
        Base.__init__(self)
        self.line_info(class_name='MySQLBase',msg='ERROR DEBUG INFO WARN WARNING', info='INFO ERROR')
        self.stmt = stmt
        self.list_1 = []
        self.list = []
        self.outfile = '/opt/customScripts/wmi_project/output/backup.csv'
        self.val2 = ''

    def set_stmt(self, stmt):
        self.stmt = stmt
        self.line_info(class_name='MySQLBase',
                       msg="stmt val", info=str(self.stmt))
        #logging.error(self.template1.format("LIN_NUM=41 stmt val=" + str(self.stmt)))

    def connection(self, database):
        list_2 = []
        """Creates a database connection and returns the cursor.  Host is hardwired to 'localhost'."""
        self.database = database
        try:
            self.mydb = MySQLdb.connect(
                user='readOnlyUser', passwd='UTrSrN8cDfrLtRsn', host="192.168.1.10", db=self.database)
            self.cur = self.mydb.cursor()
        except MySQLdb.Error:
            self.line_info(class_name='MySQLBase',
                           error="DB CONNECTION FAILED")
            #logging.error(self.template1.format("DB CONNECTION FAILED"))
            raise MySQLdb.Error
        except MySQLdb.Warning:
            pass

        try:
            self.results = self.cur.execute(self.stmt)
            self.line_info(class_name='MySQLBase',
                           msg="stmt val=", info=str(self.results))
        except Exception as e:
            self.line_info(class_name='MySQLBase', error=e.args,
                           info='in cursor.exe try block')

        with self.mydb.cursor() as cursor:
            cursor.execute(self.stmt)
            for all_records in cursor.fetchall():
                self.line_info(class_name='MySQLBase',
                               msg="all_records val=" + str(all_records))
                ''' Description     :       call Write_Backup() here '''
                self.Write_Backup(all_records)
                list_2.append(all_records)
            self.mydb.commit()
        #self.line_info(msg="list_2 val=" + str(list_2))
        self.list_1.append(list_2)
        #self.line_info(msg="self.list_1 val=" + str(self.list_1))
        return self.list_1

    def execute(self):
        #logging.debug("DEBUG IN THE execute METHOD")
        try:
            #logging.error("LINE_NUM=78 stmt val="  + self.stmt)
            self.cur.execute(self.stmt)
            #logging.error("LINE_NUM=80 DB STMT OK")
            # logging.error(self.template1.format(se))

            #logging.error("STMT RESULTS ==>"  + self.cur)
          #  self.mydb.disconnect()
        except MySQLdb.Error:
            self.line_info(class_name='MySQLBase',
                           error=MySQLdb.Error, info='in cursor exe try block')
            # logging.error(MySQLdb.Error)
            #logging.error("EXCEPTION OCCURED")
        except MySQLdb.Warning:
            pass

    def _disconnect(self, var):
        self.mydb = var
        try:
            self.mydb.disconnect()
            #logging.debug("DB CONNECTION CLOSED OK")
        except MySQLdb.Error:
            self.line_info(class_name='MySQLBase', error=MySQLdb.Error,
                           info='in db disconnect try block')
            #logging.debug("DB CONNECTION CLOSED FAILED")
            raise MySQLdb.Error

    def Write_Backup(self, data):
        self.data_type = type(data)
        self.data_len = len(data)
        self.data_val = str(data)
        self.list = list(data)
        self.line_info(class_name='MySQLBase',info='val data in list=', msg=str(self.list))
        self.line_info(class_name='MySQLBase', info="self.data_val=" + self.data_val,msg="self.data_type=" + str(self.data_type) + "self.data_type=" + str(self.data_type))
        ''' del the self.outfile'''
        try:
            with open(self.outfile, 'a+') as csvfile:
                try:
                    self.writer = csv.writer(csvfile, delimiter=',')
                except Exception as e:
                    self.line_info(class_name='MySQLBase', error=e.args,info='creating a csv writer to file', msg=self.outfile)

                try:
                    #self.writer.writerow(['192.168.1.15', 'Windows 2012'])
                    self.writer.writerow(self.list)
                    self.line_info(class_name='MySQLBase',info='opening file=', msg=self.outfile + " OK")
                except IOError as e:
                    self.line_info(class_name='MySQLBase', error=e.args,info='writerow to file=', msg=self.outfile + " ERROR")
        except Exception as e:
            self.line_info(class_name='MySQLBase', error=e.args,info=' opening file=', msg=self.outfile)

    def print_stmt(self, stmt):
        self.line_info(class_name='MySQLBase', info='stmt val=', msg=stmt)
        #logging.debug("DEBUG in the print_stmt METHOD and the GENERIC STMT value ==>"  + stmt)


class WmiChildClass(Base):

        def __init__(self, network=None, credentials=None):
                Base.__init__(self)
                '''IF THE DEBUG is SET TO on in the wmi.config FILE'''
                #msg='error IS SET TO logfile IN THE WMI_CHILD_CLASS'
                self.line_info(class_name="WmiChildClass",msg='constructor initialized')
                self.cidr=network
                '''call function to return ip address'''
                self.return_ip_val=self.return_ip_val(self.cidr)
                self.av_dbconnection = MySQLBase()
                self.network = network
                self.outfile = "/opt/customScripts/wmi_project/output/"
                self.out_file = ""
                self.credentials = credentials
                self.read_config_file()
                self.output = ""
                self.name = ""
                tmp_val=self.bool_ip_in_prefix(self.return_ip_val, self.network)
                if tmp_val:
                    self.line_info(msg='YES INFO YES')
                else:
                    self.line_info(msg='NO ERROR NO')
                        
        def set_cmd(self, cmd):
                #logging.error("in set_cmd method")
                self.cmd = cmd
                # logging.debug(cmd)

        def wmiscan_no_debug(self, overload=None, val_tmp=None):
                for ip in IPNetwork(self.cidr):
                        self.ip_in_for_loop = str(ip)
                        self.data = ""
                        self.YES = True
                        response = os.system("ping -c 1 " + str(ip))
                        if response == 0:
                            outfile = "/opt/customScripts/wmi_project/output/update.csv"
                            #self.outfile = outfile
                            ''' Description :   Iteration 1 '''
                            self.wmi = 'wmic -U ' + self.plaintext.strip() + ' //' + str(ip) + ' "SELECT CSName,Caption,BuildNumber FROM Win32_OperatingSystem"'
                            l = subprocess.Popen(self.wmi, shell=True,
                            stdout=subprocess.PIPE)
                            output = l.stdout.readlines()
                            wmi_output_len = len(output)

                            if wmi_output_len > 2:
                                self.out_put = output[2].strip()
                                self.line_info(class_name='WmiChildClass', msg="wmi_output_len > 2 and len=" + str(wmi_output_len) + " out_put val=" + str(self.out_put) + " ip val=" + self.ip_in_for_loop + " in if")
                                self.out_put = str(self.out_put) + '|' + self.ip_in_for_loop
                                self.line_info(class_name='WmiChildClass',info=self.out_put)
                            else:
                                self.line_info(class_name='WmiChildClass',info="wmic scan results = less than 3 lines")

                            ''' here is the problem'''
                            self.line_info(class_name="WmiChildClass", msg="out_put val=" + str(self.out_put) + " for readlines()", info='ip val=' + self.ip_in_for_loop)

                            if re.findall(r"ERROR", self.out_put):
                                self.YES = False
                                self.line_info(class_name='WmiChildClass', msg="ERROR found in self.out_put val=" + str(self.out_put) + " ip val=" + self.ip_in_for_loop)
                            else:
                               self.YES = True

                            if len(output) > 2 and self.YES:
                                ''' self.Write() refactor to csv FILE with ALL data values'''
                                self.Write_Update(outfile, self.out_put)
                                outfile = ""
                                self.data = None
                                try:
                                    self.av_dbconnection.test()
                                except Exception as e:
                                    self.line_info(class_name='WmiChildClass', error=e.args)

                                '''SQL BACKUP STMT'''
                                stmt = """SELECT INET6_NTOA(i.ip), p.value from host_ip i, host_properties p WHERE HEX(i.host_id) = HEX(p.host_id) and INET6_NTOA(ip) = "%s" """ % (ip)
                                self.av_dbconnection.set_stmt(stmt)
                                self.av_dbconnection.connection("alienvault")
                        else:
                            OS = ""
                os.system('clear')

        def Get_Values(self, data):
                for x in data:                    
                    self.line_info(class_name='WmiChildClass',msg=" for x in data " + str(data[x]))

        def Write_Update(self, outfile, data):
                '''What'''
                self.data = data
                self.outfile = outfile
                self.line_info(class_name='WmiChildClass',info="data val=" + str(self.data) + " before appending",msg='outfile=' + str(self.outfile))
                ''' del the file here'''
                #self.Check_File(self.outfile)

                try:
                    text_file = open(self.outfile, "a+")
                    self.line_info(class_name='WmiChildClass',info="OK opening", msg=self.outfile)
                except Exception as e:
                    self.line_info(class_name='WmiChildClass',error=e.args, info="ERROR opening", msg=self.outfile)

                text_file.write(self.data + '\n')
                text_file.close()
                self.data = self.data.strip()
                self.data = str(self.data)
                self.line_info(class_name='WmiChildClass',msg="data val=", info=self.data + " after appending")
                #logging.error(self.template1.format("LINE_NUM=267 in Write() AFTER appending data val=" + str(self.data)))

        def get_credentials(self):
                """Call Base.dencoding"""
                self.decoding()

        def Check_File(self, file):
            
                self.outfile = file
                if os.path.exists(self.outfile):
                    self.line_info(info='os.path.exists for', msg=self.outfile)
                    '''
                    try:
                    os.remove(self.output)
                    '''
                else:
                    self.line_info(info='os.path does not exists for', msg=self.outfile)
                    
        def ip_to_binary(self,ip):
                self.ip=ip
                self.line_info(class_name=str(self.__class__,), info='ip val=' + str(self.ip))
                self.octet_list_int = self.ip.split(".")
                self.octet_list_bin = [format(int(i), '08b') for i in self.octet_list_int]
                self.binary = ("").join(self.octet_list_bin)
                return self.binary

        def get_addr_network(self,address, net_size):
                self.address=address
                self.net_size=net_size
                self.line_info(class_name=str(self.__class__,), info='address val=' + str(self.address), msg='net_size val=' + str(self.net_size))
                
                #Convert ip address to 32 bit binary
                self.ip_bin = self.ip_to_binary(self.address)
                
                #Extract Network ID from 32 binary
                self.network = self.ip_bin[0:32-(32-self.net_size)]
                self.line_info(class_name=str(self.__class__,), info='network val=' + str(self.network), msg='ip_bin val=' + str(self.ip_bin))
                return self.network
    
        def bool_ip_in_prefix(self, ip_address , prefix):
                '''docstring returns a boolean'''
                self.prefix = prefix
                self.ip_address=ip_address
                self.line_info(class_name=str(self.__class__,), info='prefix val=' + str(self.prefix), msg='ip_address val=' + str(self.ip_address))
                
                #CIDR based separation of address and network size
                #[self.prefix_address, self.net_size] = self.prefix.split('/')
                self.tmp_val = self.prefix.split('/')
                self.line_info(info='tmp_val= ' + str(self.tmp_val) + ' list len=' + str(len(self.tmp_val)))
                
                self.prefix_address = self.tmp_val[0]
                self.net_size = self.tmp_val[1]
                
                #Convert string to int
                self.net_int = int(self.net_size)
                self.line_info(info='net_int val=' +str(self.net_int))

                #Get the network ID of both prefix and ip based net size
                self.prefix_network = self.get_addr_network(self.prefix_address, self.net_int)
                self.line_info(info='self.prefix_network=',msg=self.prefix_network)
                
                self.ip_network = self.get_addr_network(self.ip_address, self.net_int)
                #self.line_info(info='self.ip_network=', msg=self.ip_network)

                self.line_info(class_name=str(self.__class__), info='net_size val=' + str(self.net_size) 
                    + 'prefix_network val=' + str(self.prefix_network)  + 'ip_network val=' + str(self.ip_network))
                
                return self.ip_network == self.prefix_network

        def return_ip_val(self,prefix):
                self.prefix=prefix.split('/')
                self.line_info(class_name=str(self.__class__,), info='prefix val=' + str(self.prefix))
                return self.prefix[0]


def main():
        cidr = str(raw_input("Please enter Network Address in CIDR format\ne.g 192.168.1.0/24\n"))
        obj1 = WmiChildClass(cidr, None)
        obj1.get_credentials()
        obj1.wmiscan_no_debug()


if __name__ == "__main__":
    main()
