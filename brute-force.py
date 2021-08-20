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
def statusSplit(data):
    #print(type(data))
    #dictTest= {}

    #dictTest = {    "0xc000006d":"The cause is either a bad username or authentication information",
    #                "0x0":"TEST DESCRIPTION"
    #           }
    
    data = data.split(sep=" ")
    # a list
    return data
    
    
    for idx in range(len(data)):
        if idx == 81:
            
            status=data[idx].strip()
            return status
            #if status in dictTest.keys():
            #    print(str(dictTest.keys()) + str(dictTest.values()) + "\n")
        elif idx == 86:
            status=data[idx].strip()
            return status
         
            
#
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
                7   = unixtime              0
                13  = src_ip                1
                15  = dst_ip                2
                30  = RC                    3
                35  = EVENT                 4
                60  = EVENT_ID              5
                66  = Failure Reason ??     6
                70  = Account Name          7
                    10 COLUMNS
                9   = Status
                10  = Sub-Status
                The IDX 62 Will be processed for 
                Status and Sub-Status 
                ''' 

                dictTest = {    "0xc000006d":"The cause is either a bad username or authentication information",
                                "0x0":"TEST DESCRIPTION"
                            }
    
                indexes =   {
                            7,13,15,30,35,60,66,70
                            }
                    
                final = (
                        [val for idx, val in enumerate(strList) 
                                if idx in indexes]
                                
                        )
                
                '''
                CALL epoch_convertor(final[0])
                '''
                
                #print(final)
                
                #for x in range(len(final)):
                #        print("HERE=> " + str(x) + " " + str(final[x]))


                var_event=final[4]
                statusList=statusSplit(var_event)
                
                #for x in range(len(statusList)):
                #    print(str(x) + str(statusList[x]))

                
                
                for idx in range(len(statusList)):
                    if idx == 78:
                        print(statusList[idx])

                    #elif idx == 84:
                    #    print("84")
                
                
                
                
                #print(statusList)




                ''' CALL statusSplit()'''
                #
                # print(statusSplit(var_event))

                
                
                
                
                
                #print(final[4])

                #try:
                #    var_tmp = epoch_convertor(final[0])
                #except Exception as e:
                #    print(e.args)
                
                #print(var_tmp)
                

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