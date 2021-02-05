import os
import logging
import serial
import sys
import time
import shutil
import traceback
import time
import subprocess
sys.path.append('.\\Function')
import Function.Parameter as api
from Function.MmiOperate import Common
# from PtsFileConverter import PtsFileConverter
import json

# region Set Looger
logger = logging.getLogger(os.path.basename(__file__))
logger.setLevel(logging.INFO)
DisplayHandle = logging.StreamHandler()
DisplayHandle.setLevel(logging.INFO)
formatter = logging.Formatter("[%(name)s][%(levelname)s]%(message)s")
DisplayHandle.setFormatter(formatter)
logger.addHandler(DisplayHandle)
# endregion

if __name__ == '__main__':
    try:
        '''
        com = serial.Serial('com4', 115200, timeout=8, parity=serial.PARITY_NONE, rtscts=0)

        ixit_str = json.load(open('TestSet.json','r'))['GAP']
        ixit = dict()
        for k in ixit_str:
            ixit[k.encode()] = [i.encode() for i in ixit_str[k]]

        Common(com,'GAP','GAP/DISC/GENM/BV-01-C',b'001BDC08E5BD',ixit).iut_initial(True)

        # print(Common(com, 'GAP', 'GAP/BROB/OBSV/BV-05-C', b'001BDC08E5BD', ixit).iut_get_device_name())
        '''

        a = b'D:\\PycharmProjects\\PTS\\AutoPTS'
        b = os.getcwd().encode()
        print(a)
        print(b)
        if a == b:
            print('Y')


    except(OSError, serial.SerialException):
        print('Please checked the comport has release ')

    except:
        cl, exc, tb = sys.exc_info()
        for lastCallStack in traceback.extract_tb(tb):
            errMessage =''.join(['\n######################## Error Message #############################\n'
                                 '    Error class        : {}\n'.format(cl),
                                 '    Error info         : {}\n'.format(exc),
                                 '    Error fileName     : {}\n'.format(lastCallStack[0]),
                                 '    Error fileLine     : {}\n'.format(lastCallStack[1]),
                                 '    Error fileFunction : {}'.format(lastCallStack[2])])
            logger.error(errMessage)