import os
import sys
import json
import logging
import serial.tools.list_ports

# region Set Looger
logger = logging.getLogger(os.path.basename(__file__))
logger.setLevel(logging.INFO)
DisplayHandle = logging.StreamHandler()
DisplayHandle.setLevel(logging.DEBUG)
formatter = logging.Formatter("[%(name)s][%(levelname)s]".ljust(30)+"%(message)s")
DisplayHandle.setFormatter(formatter)
logger.addHandler(DisplayHandle)
# endregion

class Setting:
    def __init__(self,settingPath):
        if not self.checkSetfile(settingPath):
            logger.error(f'{settingPath} not found, please check it .. ')
            sys.exit()
        self.config = json.load(open(settingPath,'r'))
        self.comport = str.upper(self.config["Comport"])

    def checkSetfile(self,path):
        if os.path.isfile(path):
            return True
        else: return False

    def bleonly(self):
        ble = str.upper(self.config["BleOnly"])
        if len(ble) < 1 or ble == 'N' or ble == 'NO' or ble == '0':
            ble = None

        return ble

    def captureUart(self):
        capture = str.upper(self.config["Capture_Uart"])
        if len(capture) < 1 or capture == 'N' or capture == 'NO' or capture == '0':
            return
        else:
            return True


    def testProfile(self):
        TestProfiles = {}
        for key,val in self.config["Profile"].items():
            if val != 0:
                TestProfiles[key] = val
        return TestProfiles

    def ComportSet(self):
        comlist = serial.tools.list_ports.comports()
        ComportList = []
        for list in comlist:
            str(list)
            ComportList.append(list[0])
        if self.comport not in ComportList:
            logger.error('Comport not found , Please Check Setting file')
            sys.exit()
        else:
            try:
                Com = serial.Serial(self.comport, 115200, timeout=5, parity=serial.PARITY_NONE, rtscts=0)
                if Com.isOpen() == False:
                    logger.error('Com Port Connect fail , Please Check the Port status')
                    sys.exit()
                return Com
            except(OSError, serial.SerialException):
                logger.error(f'Please checked {self.comport} has release or not')
                sys.exit()

    def GenConfigs(self,ProfileName,ConfigPath):
        ICS, IXIT = {}, {}
        Profile = os.path.join(ConfigPath ,f'{ProfileName}.json')

        if not os.path.isfile(Profile):
            logger.error(f'No Such {Profile} file , Please check PICS.pts file')
            return False

        data = json.load(open(Profile,'r'))

        ICSORG = data['ics']
        for key,val in ICSORG.items():
            ICS[str.encode(key)] = str.encode(val)

        ixit = self.config[ProfileName]
        IXITORG = data['ixit']
        for key in IXITORG:
            if key not in ixit:
                IXIT[str.encode(key)] = str.encode(IXITORG[key][0]),str.encode(IXITORG[key][1])
            elif IXITORG[key][1] != ixit[key][1]:
                IXIT[str.encode(key)] = str.encode(ixit[key][0]),str.encode(ixit[key][1])
            else:
                IXIT[str.encode(key)] = str.encode(IXITORG[key][0]),str.encode(IXITORG[key][1])
        return ICS, IXIT
