#!/usr/bin/env python3
'''

VERSION         :   1.0
DESCRIPTION     :   MAJOR REL 1.0

'''
#from os import strerror
import re
import sys
import logging
import logging.handlers
import datetime
# Set up logging (in this case to terminal OUTPUT)
log = logging.getLogger(__name__)
log.root.setLevel(logging.DEBUG)
log_formatter = logging.Formatter('%(levelname)s %(message)s')
log_handler = logging.StreamHandler()
log_handler.setFormatter(log_formatter)
log.addHandler(log_handler)

#
def epoch_convertor(data):
    
    #print(int((data)))

    epoch_time = int(data)
    return datetime.datetime.fromtimestamp(epoch_time)
            
#
def test(data):

    reasonDict = {
                    "0xc0000064":"user name does not exist",
                    "0xc000006a":"user name is correct but the password is wrong",
                    "0xc0000234":"user is currently locked out",
                    "0xc0000072":"account is currently disabled",
                    "0xc000006f":"user tried to logon outside his day of week or time of day restrictions",
                    "0xc0000070":"workstation restriction, or Authentication Policy Silo violation (look for event ID 4820 on domain controller)",
                    "0xc0000193":"account expiration",
                    "0xc0000071":"expired password",
                    "0xc0000133":"clocks between DC and other computer too far out of sync",
                    "0xc0000224":"user is required to change password at next logon",
                    "0xc0000225":"evidently a bug in Windows and not a risk",
                    "0xc000015b":"The user has not been granted the requested logon type (aka logon right) at this machine",
                    "0xc000005e":"There are currently no logon servers available to service the logon request.",
                    "0xc0000064":"User logon with misspelled or bad user account",
                    "0xc000006a":"User logon with misspelled or bad password",
                    "0xc000006d":"The cause is either a bad username or authentication information",
                    "0xc000006e":"Indicates a referenced user name and authentication information are valid, but some user account restriction has prevented successful authentication (such as time-of-day restrictions).",
                    "0xc000006f":"User logon outside authorized hours",
                    "0xc0000070":"User logon from unauthorized workstation",
                    "0xc0000071":"User logon with expired password",
                    "0xc0000072":"User logon to account disabled by administrator",
                    "0xc00000dc":"Indicates the Sam Server was in the wrong state to perform the desired operation.",
                    "0xc0000133":"Clocks between DC and other computer too far out of sync",
                    "0xc000015b":"The user has not been granted the requested logon type (also called the logon right) at this machine",
                    "0xc000018c":"The logon request failed because the trust relationship between the primary domain and the trusted domain failed.",
                    "0xc0000192":"An attempt was made to logon, but the Netlogon service was not started.",
                    "0xc0000193":"User logon with expired account",
                    "0xc0000224":"User is required to change password at next logon",
                    "0xc0000225":"Evidently a bug in Windows and not a risk",
                    "0xc0000234":"User logon with account locked",
                    "0xc00002ee":"Failure Reason: An Error occurred during Logon",
                    "0xc0000413":"Logon Failure: The machine you are logging on to is protected by an authentication firewall. The specified account is not allowed to authenticate to the machine.",
                    "0x0"       :"Status OK."

                }
    
    dictKEY = reasonDict.keys()
    dictVal = reasonDict.values()

    if data in dictKEY:
        print(str(reasonDict[data]))
    #reasonVal = reasonDict.keys()

    #if str(data) in str(dictKEY):
        #print(str(dictKEY) +  str(dictVal))
        #print(dictVal)
    
    
    #print(data)    


def read_file(file_name):
    try:
        with open(file_name, 'rt', newline='') as f:
            lineA = [ lineX for lineX in f.readlines() ]
            for line in lineA:
                
                if "Binary" in line:
                    #strList = re.split(r"[;|,|\']", line)
                    #print(line)
                    varX = None
                elif "userdata8" in line:
                    strList = re.split(r"[;|,|\']", line)
                
                '''
                    8 COLUMNS     
                7   = unixtime                  0
                13  = src_ip                    1
                15  = dst_ip                    2
                30  = RC                        3
                35  = EVENT                     4
                60  = EVENT_ID                  5
                66  = Failure Reason ??         6
                70  = CALLER COMPUTER NAME      7

                    10 COLUMNS
                9   = Status
                10  = Sub-Status
                The IDX 62 Will be processed for 
                Status and Sub-Status 
                ''' 
                indexes =   {
                            7,13,15,30,35,60,66,70
                            }
                    
                final = (
                        [val for idx, val in enumerate(strList) 
                                if idx in indexes]
                                
                        )
                var_event=final[4]
                #print(type(var_event))
                
                varTEMP = var_event.split()
                ''' THE LOGIC
                ##################
                55 Status:
                56 0xc000006d
                57 Sub
                58 Status:
                59 0xc0000064

                56 0xc000006d
                59 0xc0000064
                55 0xc000006d
                    
                    if 55 == Status:
                        then use 56
                    else:
                        use 55
                    if 58 == Status:
                        then use 59
                    else
                        use 58


                58 0xc0000064

                56 0xc000006d
                59 0xc0000064
                #########################
                
                      THE UNIXTIME method
                try:
                    var_tmp = epoch_convertor(final[0])
                except Exception as e:
                    print(e.args)
                '''
                '''
                0   =   unixtime
                1   =   src
                2   =   ds
                3   =   EVENT NAME

                4   =   EVENT PAYLOAD
                
                5   =   EVENT_ID
                6   =   FAILURE REASON
                7   =   USERNAME
                8   =   CALLER COMPUTER NAME
                

                
                '''
                print("" str())
                print("" str())
                print("" str())
                print("" str())
                print("" str())
                print("" str())
                print("" str())
                print("" str())
                print("" str())
                print("" str())


                print("CALLER COMPUTER NANME:" +str(final[7]))

                '''
                for x in range(len(varTEMP)):
                    if x == 55 and str(varTEMP[x]) == "Status:":
                        #print(str(varTEMP[56]))
                        #call a METHOD to return the description
                        test(str(varTEMP[56]))
                    elif x == 55 and str(varTEMP[x]) != "Status:":
                        #print(str(varTEMP[55]))
                        #call a METHOD to return the description
                        test(str(varTEMP[55]))
                    
                    if x == 58 and str(varTEMP[x]) == "Status:":
                        #print(str(varTEMP[59]))
                        #call a METHOD to return the description
                        test(str(varTEMP[59]))

                    elif x == 58 and str(varTEMP[x]) != "Status:":    
                        #print(str(varTEMP[58]))
                        test(str(varTEMP[58]))
                        #call a METHOD to return the description
                ''' 

    except Exception as e:
        logging.error(str(e))
#

def main():
    FILE_NAME = str(sys.argv[1])
    try:
        read_file(FILE_NAME)
    except Exception as e:
        logging.info(e.args)

if __name__ == "__main__":
    main()