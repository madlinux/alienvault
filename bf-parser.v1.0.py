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

    dictTest = {    "0xc000006d":"The cause is either a bad username or authentication information",
                    "0x0":"TEST DESCRIPTION"
               }
    dictTest_keys=dictTest.keys()
    print(dictTest_keys)



    dictTest_val=dictTest.values()
    print(dictTest_val)


    #print(type(dictTest))

    data = data.split(sep=" ")
    #print(data)
    #print("IDX=" + str(x) + "VAL=" + str(data[x]))

    
    for idx in range(len(data)):
        if idx == 81:
            #print("IDX=" + str(idx) + "STATUS=" + str(data[idx]))
            
            # status is a list
            
            status= data[idx].strip()
            
            #print(status)

            #for key,val in dictTest:
            #print(dictTest.items())

            #print(dictTest[])




            # indexes is a dictionary with key and val
            # id the key is matched print the value
            
            #indexes =   {
            #                "0xc000006d":"The cause is either a bad username or authentication information",
            #                "0x0":"TEST DESCRIPTION"
            #print(indexes["0x0"])

            #final = (
            #            [key for key in enumerate(status) 
            #                    if key in indexes]
            #                    
            #            )
            #print(final)               
            
        #elif idx == 86:
        #    print("IDX=" + str(idx) + "SUB STATUS=" + str(data[idx]))
        
        #print("IDX=" + str(x) + "VAL=" + str(data[x]))
    #print("===========================\n")

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
                
                var_event=final[4]
                
                

                #print(type(var_event))
                varTEMP = var_event.split()
                for x in range(len(varTEMP)):
                    print(str(x) + " " + str(varTEMP[x]))
                
                
                '''
                try:
                    var_tmp = epoch_convertor(final[0])
                except Exception as e:
                    print(e.args)
                '''
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