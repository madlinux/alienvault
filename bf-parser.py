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
'''
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
'''         
            
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
                '''

                for x in range(len(varTEMP)):
                    if x == 55 and str(varTEMP[x]) == "Status:":
                        print(str(varTEMP[56]))
                        
                        '''
                        if str(varTEMP[x]) == "Status:":
                            print(str(varTEMP[56]))
                        '''
                    elif x==55 and str(varTEMP[x]) != "Status:":
                            print(str(varTEMP[55]))
                        
                    
                    if x == 58 and str(varTEMP[x]) == "Status:":
                        print(str(varTEMP[59]))
                    
                    elif x == 58 and str(varTEMP[x]) != "Status:":    
                        print(str(varTEMP[58]))
                    

                ''' THE UNIXTIME method
                try:
                    var_tmp = epoch_convertor(final[0])
                except Exception as e:
                    print(e.args)
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