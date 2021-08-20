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

def epoch_convertor(data):
    epoch_time = data
    return datetime.datetime.fromtimestamp(epoch_time)


def read_file(file_name):
    counter = 0
    newlist=[]
    listB=[]
    listC=[]
    eventListA=[]
    listEVENTS=[]
    #str = re.split(r';|,|\.', str) 
                
    try:
        with open(file_name, 'rt', newline='') as f:
            lineA = [ lineX for lineX in f.readlines() ]
            for x in lineA:
                strList = re.split(r"[;|,|\']", x)
                strLen = len(strList)
                if  strLen == 74: 
                    
                    try:
                        strList.insert(57, "NULL")
                        strList.insert(28, "NULL")
                    except Exception as e:
                        logging.info(e.args)
                
                indexes =   {

                            }
                    
                final = (
                    [
                    val 
                    for idx, val in enumerate(strList) 
                        if idx not in indexes
                    ]
                        )
                
                for x in range(len(final)):
                    print("HERE=> " + str(x) + " " + str())


                #print(final)
                
                #logging.info(final)    
                #print(epoch_convertor(int(final[0])))

    except Exception as e:
        logging.error(str(e))

def main():
    FILE_NAME = str(sys.argv[1])
    try:
        read_file(FILE_NAME)
    except Exception as e:
        logging.info(e.args)

if __name__ == "__main__":
    main()