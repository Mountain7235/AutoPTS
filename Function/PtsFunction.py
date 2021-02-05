import os
import sys
import time
import ctypes
import logging
import subprocess
from ctypes import *

# region Set Looger
logger = logging.getLogger(os.path.basename(__file__))
logger.setLevel(logging.DEBUG)
DisplayHandle = logging.StreamHandler()
DisplayHandle.setLevel(logging.DEBUG)
formatter = logging.Formatter("[%(name)s][%(levelname)s]".ljust(30) + '%(message)s')
DisplayHandle.setFormatter(formatter)
logger.addHandler(DisplayHandle)
# endregion

class PtsFunction:
    def __init__(self,profile,ics,ixit):
        self.ptsbindir     = 'C:\\Program Files (x86)\\Bluetooth SIG\\Bluetooth PTS\\bin'
        self.dll            = None
        self.profile_b     = profile.encode()
        self.ics           = ics
        self.ixit          = ixit

        self.VERDICT        = 'VERDICT/'
        self.RESULT_PASS    = 'PASS'
        self.RESULT_FAIL    = 'FAIL'
        self.RESULT_INCONC  = 'INCONC'
        self.RESULT_INCOMP  = 'INCOMP'
        self.RESULT_NONE    = 'NONE'
        self.SNIFFER_READY  = 'SNIFFER/Save and clear complete'

        self.test_result    = self.RESULT_INCOMP
        self.mmi            = ''
        self.descript       = ''
        self.imlicit_res    = None
        self.testcase_str   = None
        self.timeout        = 0

        # region LOG_TYPE
        self.LOG_TYPE_GENERAL_TEXT			= 0
        self.LOG_TYPE_FIRST					= 1 # first log type that may be toggled by user
        self.LOG_TYPE_START_TEST_CASE		= 1
        self.LOG_TYPE_TEST_CASE_ENDED		= 2
        self.LOG_TYPE_START_DEFAULT			= 3
        self.LOG_TYPE_DEFAULT_ENDED			= 4
        self.LOG_TYPE_FINAL_VERDICT			= 5
        self.LOG_TYPE_PRELIMINARY_VERDICT	= 6
        self.LOG_TYPE_TIMEOUT				= 7
        self.LOG_TYPE_ASSIGNMENT		    = 8
        self.LOG_TYPE_START_TIMER			= 9
        self.LOG_TYPE_STOP_TIMER			= 10
        self.LOG_TYPE_CANCEL_TIMER			= 11
        self.LOG_TYPE_READ_TIMER			= 12
        self.LOG_TYPE_ATTACH				= 13
        self.LOG_TYPE_IMPLICIT_SEND			= 14
        self.LOG_TYPE_GOTO					= 15
        self.LOG_TYPE_TIMED_OUT_TIMER		= 16
        self.LOG_TYPE_ERROR					= 17
        self.LOG_TYPE_CREATE				= 18
        self.LOG_TYPE_DONE					= 19
        self.LOG_TYPE_ACTIVATE				= 20
        self.LOG_TYPE_MESSAGE				= 21
        self.LOG_TYPE_LINE_MATCHED			= 22
        self.LOG_TYPE_LINE_NOT_MATCHED		= 23
        self.LOG_TYPE_SEND_EVENT			= 24
        self.LOG_TYPE_RECEIVE_EVENT			= 25
        self.LOG_TYPE_OTHERWISE_EVENT		= 26
        self.LOG_TYPE_RECEIVED_ON_PCO		= 27
        self.LOG_TYPE_MATCH_FAILED			= 28
        self.LOG_TYPE_COORDINATION_MESSAGE	= 29
        # endregion

        # region Define callback functions
        self.USEAUTOIMPLSENDFUNC = CFUNCTYPE(c_bool)
        self.use_auto_impl_send_func = self.USEAUTOIMPLSENDFUNC(self.UseAutoImplicitSend)

        self.DONGLE_MSG_FUNC = CFUNCTYPE(c_bool, c_char_p)
        self.dongle_msg_func = self.DONGLE_MSG_FUNC(self.DongleMsg)

        self.DEVICE_SEARCH_MSG_FUNC = CFUNCTYPE(c_bool, c_char_p, c_char_p, c_char_p)
        self.dev_search_msg_func = self.DEVICE_SEARCH_MSG_FUNC(self.DeviceSearchMsg)

        self.LOGFUNC = CFUNCTYPE(c_bool, c_char_p, c_char_p, c_char_p, c_int, c_void_p)
        self.log_func = self.LOGFUNC(self.Log)

        self.ONIMPLSENDFUNC = CFUNCTYPE(c_char_p, c_char_p, c_int)
        self.onimplsend_func = self.ONIMPLSENDFUNC(self.ImplicitSend)
        # endregion

        self.__init()

    def __init(self):
        os.chdir(self.ptsbindir)

        self.dll = self.loadDLL()

        self.RunPrepare()

    def loadDLL(self):
        os.chdir(self.ptsbindir)
        dll = os.path.join(self.ptsbindir,'ETSManager.dll')

        return cdll.LoadLibrary(dll)

    def unloadDLL(self):
        del self.dll

    def reixit(self,ptsaddress):
        if b'TSPX_bd_addr_PTS' in self.ixit.keys():
            val = self.ixit[b'TSPX_bd_addr_PTS'][0]
            self.ixit[b'TSPX_bd_addr_PTS'] = val, ptsaddress
        return self.ixit

    def print_found_devices(self,arg):
        step = 2
        duration = arg
        global devices
        while duration > 0:
            while len(devices) > 0:
                logger.info(devices[0])
                del devices[0]
            time.sleep(step)
            duration -= step

    def snifferPrepare(self):
        errcount = 0
        self.dll.SnifferIsConnectedEx.restype = ctypes.c_bool
        while ctypes.c_bool(self.dll.SnifferIsConnectedEx()).value == False:
            time.sleep(1)
            errcount+=1
            if errcount == 10:
                logger.error("Sniffer is not connected")
                return False
        # logger.info("Sniffer is connected")
        self.dll.SnifferIsRunningEx.restype = ctypes.c_bool
        while ctypes.c_bool(self.dll.SnifferIsRunningEx()).value == False:
            time.sleep(1)
            errcount+=1
            if errcount == 10:
                logger.error("Sniffer is not running")
                return False
        # logger.info("Sniffer is running")
        self.dll.SnifferCanSaveEx.restype = ctypes.c_bool
        while ctypes.c_bool(self.dll.SnifferCanSaveEx()).value == False:
            time.sleep(1)
            errcount+=1
            if errcount == 10:
                logger.error("Sniffer is not an save")
                return False
        # logger.info("Sniffer can save")
        self.dll.SnifferCanClearEx.restype = ctypes.c_bool
        while ctypes.c_bool(self.dll.SnifferCanClearEx()).value == False:
            time.sleep(1)
            errcount+=1
            if errcount == 10:
                logger.error("Sniffer is not clear")
                return False
        # logger.info("Sniffer can clear")
        self.dll.SnifferClearEx()

    def snifferSave(self,casename_b,logpathDir):
        self.dll.SnifferIsRunningEx.restype = ctypes.c_bool

        while ctypes.c_bool(self.dll.SnifferIsRunningEx()).value == False:
            time.sleep(1)

        self.dll.SnifferCanSaveEx.restype = ctypes.c_bool
        while ctypes.c_bool(self.dll.SnifferCanSaveEx()).value == False:
            time.sleep(1)

        filename = (f"{casename_b.decode().replace('/', '_').replace('-', '_')}"
                    f"{time.strftime('_%Y_%m_%d_%H_%M_%S')}.cfa")

        filename = os.path.join(logpathDir,filename).encode()

        self.dll.SnifferSaveEx.argtypes = [c_char_p]
        self.dll.SnifferSaveEx(filename)
        # self.dll.SnifferSaveAndClearEx.argtypes = [c_char_p]
        # self.dll.SnifferSaveAndClearEx(path)
        time.sleep(3)

    def snifferRunning(self):
        prog = [line.split() for line in subprocess.check_output("tasklist").splitlines()]
        [prog.pop(e) for e in [0,1,2]] #useless

        for task in prog:
            task_name = task[0].decode("utf-8",errors='ignore')

            if task_name == "Fts.exe":
                logger.debug("FTS is Running")
                time.sleep(1)

                return True

        return False

    def snifferStart(self):
        args = ['C:\Program Files (x86)\Bluetooth SIG\Bluetooth Protocol Viewer\Executables\Core\FTS.exe',
                '/PTS Protocol Viewer=Generic',
                '/OEMTitle=Bluetooth Protocol Viewer',
                '/OEMKey=Virtual']

        subprocess.Popen(args)

    def getPtsAddress(self):
        self.dll.GetDongleBDAddress.restype = ctypes.c_ulonglong
        pts_address = self.dll.GetDongleBDAddress()
        pts_address_str = "{0:012X}".format(pts_address)

        return pts_address_str.encode("utf-8")

    def UseAutoImplicitSend(self):
        return True

    def DongleMsg(self,msg_str):
        msg = (ctypes.c_char_p(msg_str).value).decode("utf-8",errors='ignore')
        # logger.info(msg)
        time.sleep(1)
        global sniffer_ready
        if self.SNIFFER_READY in msg:
            sniffer_ready = True
        return True

    def DeviceSearchMsg(self,addr_str, name_str, cod_str):
        addr = (ctypes.c_char_p(addr_str).value).decode("utf-8",errors='ignore')
        name = (ctypes.c_char_p(name_str).value).decode("utf-8",errors='ignore')
        cod = (ctypes.c_char_p(cod_str).value).decode("utf-8",errors='ignore')
        global devices
        devices.append("Device address = {0:s} name = {1:s} cod = {2:s}".format(addr, name, cod))
        return True

    def Log(self,log_time_str, log_descr_str, log_msg_str, log_type, project):
        log_time = (ctypes.c_char_p(log_time_str).value).decode("utf-8",errors='ignore')
        log_descr = (ctypes.c_char_p(log_descr_str).value).decode("utf-8",errors='ignore')
        log_msg = (ctypes.c_char_p(log_msg_str).value).decode("utf-8",errors='ignore')
        log_msg = log_descr + log_msg
        # print(log_time+log_msg)
        if ctypes.c_int(log_type).value == self.LOG_TYPE_FINAL_VERDICT:
            indx = log_msg.find(self.VERDICT)
            if indx == 0:
                logger.debug("Final verdict has been  received")
                if self.test_result == self.RESULT_INCOMP:
                    if self.RESULT_INCONC in log_msg:
                        self.test_result = self.RESULT_INCONC
                    elif self.RESULT_FAIL in log_msg:
                        self.test_result = self.RESULT_FAIL
                    elif self.RESULT_PASS in log_msg:
                        self.test_result = self.RESULT_PASS
                    elif self.RESULT_NONE in log_msg:
                        self.test_result = self.RESULT_NONE
        return True

    def ImplicitSend(self,description, style):
        descript   = (ctypes.c_char_p(description).value).decode("utf-8",errors='ignore')
        time_guard = int(bytes.decode(self.ixit[b'TSPX_time_guard'][1], "utf-8", errors='ignore'))
        indx       = descript.find('}')
        TestCase = ''

        if indx != -1:
            self.descript    = descript[(indx + 1):]
            implicitSendInfo = descript[1:(indx)]
            items = implicitSendInfo.split(',')
            self.mmi = items[0]
            TestCase = items[1]

        while self.imlicit_res == None:
            if self.timeout > time_guard:
                logger.error(f'... {TestCase} test timeout .. ')
                return False
            else:
                self.timeout += 1
            time.sleep(1)

        if self.imlicit_res == True:
            try:
                self.imlicit_res = None
                return b'OK'
            finally:
                time.sleep(1)
                self.timeout = 0

        elif self.imlicit_res == False:
            try:
                self.imlicit_res = None
                return 0
            finally:
                time.sleep(1)
                self.timeout = 0

        elif self.imlicit_res != True and \
             self.imlicit_res != False and \
             self.imlicit_res != None:
            if len(self.imlicit_res) > 6:
                try:
                    imlicit_res = self.imlicit_res
                    self.imlicit_res = None
                    return imlicit_res
                finally:
                    time.sleep(1)
                    self.timeout = 0
            else:
                try:
                    return self.imlicit_res
                finally:
                    time.sleep(1)
                    self.imlicit_res = None
                    self.timeout     = 0

    def RunPrepare(self):
        self.dll.InitGetDevInfoWithCallbacks.argtypes = [c_char_p,
                                                         self.DEVICE_SEARCH_MSG_FUNC,
                                                         self.DONGLE_MSG_FUNC]
        self.dll.InitGetDevInfoWithCallbacks.restype  = c_bool
        res = self.dll.InitGetDevInfoWithCallbacks(str.encode(self.ptsbindir+'\\'),
                                                   self.dev_search_msg_func,
                                                   self.dongle_msg_func)
        if res != True:
            logger.error('GetDevInfo initialized fail')
            return False

        self.dll.InitSniffer()

        # Obtain the list of available radio devices
        self.dll.GetDeviceList.restype = ctypes.c_char_p
        res = self.dll.GetDeviceList()

        sDeviceList = res.decode("utf-8")
        if len(sDeviceList) < 1:
            logger.error(f'Cannot find a device to connect')
            exit()

        aDeviceList = sDeviceList.split(';')
        # logger.info(f"Device List: {sDeviceList}")

        deviceToConnect = None

        # look at each device
        for sDevice in aDeviceList:
            # parse each device data
            # e.g.
            # COM format -> 'COM7'
            # USB format -> 'USB:Free:6&10EF065E&3&1' ('Free' or 'InUse')
            aInfo = sDevice.split(':')
            if (not ('USB:InUse' in aInfo[0])):
                deviceToConnect = aInfo[len(aInfo) - 1]
                break

        if deviceToConnect is None:
            logger.error("[ptsAutomation] none of the returned device was available for usage")
            exit()

        # logger.info(f"Connecting to {deviceToConnect}")
        self.dll.SetPTSDevice.argtypes = [ctypes.c_char_p]
        self.dll.SetPTSDevice(deviceToConnect.encode("utf-8"))

        # self.dll.VerifyDongleEx.restype = c_bool
        res = self.dll.VerifyDongleEx()
        if res != 0:
            logger.error('PTS dongle initialized fail')
            sys.exit()

        self.dll.RegisterProfileWithCallbacks.argtypes = [c_char_p,
                                                          self.USEAUTOIMPLSENDFUNC,
                                                          self.ONIMPLSENDFUNC,
                                                          self.LOGFUNC,
                                                          self.DEVICE_SEARCH_MSG_FUNC,
                                                          self.DONGLE_MSG_FUNC]
        self.dll.RegisterProfileWithCallbacks.restype = c_bool
        res = self.dll.RegisterProfileWithCallbacks(self.profile_b,
                                                    self.use_auto_impl_send_func,
                                                    self.onimplsend_func,
                                                    self.log_func,
                                                    self.dev_search_msg_func,
                                                    self.dongle_msg_func)
        if res != True:
            logger.error("Profile registered fail in Profile init")
            sys.exit()

        rescount = 0
        self.dll.SnifferInitializeEx()
        res = self.snifferRunning()

        if res == False:
            logger.info("Starting Protocol Viewer")

            self.snifferStart()

            while res == False:
                rescount+=1

                if rescount==10:
                    logger.error('Starting Protocol Viewer Failure')
                    return False

                time.sleep(10)
                res = self.snifferRunning()

        self.dll.SnifferRegisterNotificationEx()
        return True

    def SetIcsIxitParemeter(self,ptsaddress):
        self.dll.SetParameterEx.argtypes = [c_char_p, c_char_p, c_char_p, c_char_p]
        for ics_name in self.ics:
            self.dll.SetParameterEx.restypes = c_bool
            res = self.dll.SetParameterEx(ics_name, b'BOOLEAN', self.ics[ics_name], self.profile_b)
            if res != True:
                logger.error(f"Setting ICS {str(ics_name)} value failed")
                return False

        ixit = self.reixit(ptsaddress)
        for ixit_name in ixit:
            self.dll.SetParameterEx.restypes = c_bool
            res = self.dll.SetParameterEx(ixit_name, (ixit[ixit_name])[0], (ixit[ixit_name])[1], self.profile_b)
            if res != True:
                logger.error(f"Setting IXIT {str(ixit_name)} value failed")
                return False
        return True

    def InitStackETS(self,ptsaddress,workDirectory):
        self.dll.InitEtsEx.argtypes = [c_char_p, c_char_p, c_char_p, c_char_p]
        self.dll.InitEtsEx.restypes = c_bool
        res = self.dll.InitEtsEx(self.profile_b, workDirectory.encode(),
                                 str.encode(os.path.join(self.ptsbindir , 'implicit_send3.dll')), ptsaddress)
        if res != True:
            logger.error("ETS initialized fail in Profile init")
            return res

        self.dll.InitStackEx.argtypes = [c_char_p]
        self.dll.InitStackEx.restypes = c_bool
        res = self.dll.InitStackEx(self.profile_b)
        if res == False:
            logger.error("Profile Stack initialized fail")
            return res

        self.dll.SetPostLoggingEx.argtypes = [c_bool, c_char_p]
        self.dll.SetPostLoggingEx(True, self.profile_b)
        return True

    def ReInitEts(self):
        self.dll.ReinitEtsEx.argtypes = [c_char_p]
        self.dll.ReinitEtsEx.restypes = c_bool
        res = self.dll.ReinitEtsEx(self.profile_b)

        if res != True:
            logger.error("ETS Reinitialized fail ..")
            return res

        self.dll.InitStackEx.argtypes = [c_char_p]
        self.dll.InitStackEx.restypes = c_bool
        res = self.dll.InitStackEx(self.profile_b)
        if res != True:
            logger.error("Profile Stack initialized fail")
            return res

    def UnInitStackETS(self):
        self.dll.ExitStackEx.argtypes = [c_char_p]
        self.dll.ExitStackEx(self.profile_b)
        self.dll.UnregisterProfileEx.argtypes = [c_char_p]
        self.dll.UnregisterProfileEx(self.profile_b)
        self.dll.UnRegisterGetDevInfoEx()
        self.dll.SnifferTerminateEx()

    def stoptest(self,testcase):
        self.dll.StopTestCaseEx.argtypes = [c_char_p, c_char_p]
        self.dll.StopTestCaseEx.restype = c_bool
        res = self.dll.StopTestCaseEx(testcase,self.profile_b)
        if not res:
            logger.error('stop test function failure ...')
        return

    def runtest(self,operate,logpath):
        self.testcase_str = operate.casename_b.decode()
        self.snifferPrepare()

        self.dll.StartTestCaseEx.argtypes = [c_char_p, c_char_p, c_bool]
        self.dll.StartTestCaseEx.restype = c_bool
        res = self.dll.StartTestCaseEx(operate.casename_b, self.profile_b, True)

        start_count = 1

        while res != True:
            self.stoptest(operate.casename_b)
            time.sleep(5)
            if start_count == 10:
                break

            self.dll.StartTestCaseEx.argtypes = [c_char_p, c_char_p, c_bool]
            self.dll.StartTestCaseEx.restype = c_bool

            res = self.dll.StartTestCaseEx(operate.casename_b, self.profile_b, True)

            print(f'start_count = {start_count} ,res = {res}')

            start_count += 1

        if res == True:
            logger.info(f"***  Test case {self.testcase_str} has been started    ***")
            self.test_result = self.RESULT_INCOMP
            self.mmi = ''

        else:
            logger.info(f"Test case {self.testcase_str} not started")
            self.test_result = self.RESULT_FAIL
            logger.info(f"Test case {self.testcase_str} test result: {self.test_result}")

            return self.test_result

        mmi = None
        mmi_count = 0

        while self.test_result == self.RESULT_INCOMP:
            mmi_operate_str = f'mmi{self.mmi}'
            logger.debug(f'mmi operate id : {mmi_operate_str}')

            if hasattr(operate, mmi_operate_str):
                if mmi == None and self.mmi == '':
                    res = getattr(operate,mmi_operate_str)(self.descript)

                    logger.debug(f'{mmi_operate_str} operate res : {res}')
                    self.imlicit_res = res

                    mmi , self.mmi = '',''

                if mmi != self.mmi:
                    mmi_count = 0
                    mmi = self.mmi
                    res = getattr(operate,mmi_operate_str)(self.descript)
                    if type(res) == list:
                        if res[1] == 'mmi':
                            mmi      = None
                            self.mmi = ''

                        logger.debug(f'{mmi_operate_str} operate res : {res[0]}')
                        self.imlicit_res = res[0]

                    else:
                        logger.debug(f'{mmi_operate_str} operate res : {res}')
                        self.imlicit_res = res

                if mmi == self.mmi:
                    mmi_count += 1
                    if mmi_count == 20:
                        logger.debug(f'... {self.testcase_str} mmi_operate failure ...')
                        self.stoptest(operate.casename_b)
                        time.sleep(2)
                        break
            else:
                mmi_count += 1
                if mmi_count == 20:
                    logger.debug(f'... {self.testcase_str} mmi_operate failure ...')
                    self.stoptest(operate.casename_b)
                    time.sleep(2)
                    break

            time.sleep(2)

        self.snifferSave(operate.casename_b,logpath)
        self.dll.TestCaseFinishedEx.argtypes = [c_char_p, c_char_p]
        res = self.dll.TestCaseFinishedEx(operate.casename_b, self.profile_b)

        if res == True:
            result = self.test_result
            self.test_result = self.RESULT_INCOMP
            self.imlicit_res = None
            self.mmi         = ''
            self.timeout     = 0
            self.stoptest(operate.casename_b)
            return result