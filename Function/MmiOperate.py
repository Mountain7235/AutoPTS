import time
import logging
import Parameter as api

# region Set Looger
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
DisplayHandle = logging.StreamHandler()
DisplayHandle.setLevel(logging.DEBUG)
formatter = logging.Formatter("[%(name)s][%(levelname)s]".ljust(30) + '%(message)s')
DisplayHandle.setFormatter(formatter)
logger.addHandler(DisplayHandle)
# endregion

class uartHandle:
    def __init__(self,comport):
        self.comport = comport

    def writeCommand(self,COMMAND):
        self.comport.flushInput()
        self.comport.flushOutput()

        if type(COMMAND) == bytes:
            self.comport.write(COMMAND)

        elif type(COMMAND) != list and type(COMMAND) != bytes:
            self.comport.write(COMMAND.value)

        elif type(COMMAND) == list:
            if type(COMMAND[0]) == bytes:
                cmdlayerid = COMMAND[0]
            else:
                cmdlayerid = COMMAND[0].value

            if type(COMMAND[1]) == bytes:
                cmdid      = COMMAND[1]
            else:
                cmdid      = COMMAND[1].value

            if type(COMMAND[2]) == bytes:
                cmdaction  = COMMAND[2]
            else:
                cmdaction  = COMMAND[2].value

            CmdOpt = b''.join([b'\x40', cmdlayerid, cmdid, cmdaction])

            Cmd    = b''.join([b'\xAA', len(CmdOpt).to_bytes(2,'big'), CmdOpt, b'\xFF'])

            send_command_str = Cmd.hex().upper()
            send_command_str = ' '.join([send_command_str[i:i+2] for i in range(0,len(send_command_str),2)])
            logger.debug(f'Send Command:{send_command_str}')
            self.comport.write(Cmd)

    def readEvent(self):
        NonCount = 0
        while 1:
            head = self.comport.read(1)
            if len(head) == 0:
                NonCount+=1
                if NonCount == 5:
                    return False
                else:
                    continue
            if head != b'\xAA':
                NonCount = 0
                continue
            else:
                length  = int(bytes.hex(self.comport.read(2)),16)
                payload = self.comport.read(length)
                tail    = self.comport.read(2)
                if payload[0:1] != b'\x50' or  tail != b'\xFF\xFF':
                    continue
                else:
                    rev_event     = b''.join([head,length.to_bytes(2,'big'),
                                          payload,tail]).hex().upper()

                    rev_event_str =' '.join([rev_event[i:i+2] for i in range(0,len(rev_event),2)])

                    logger.debug(''.join(['Received:'.ljust(13),
                                          rev_event_str]))
                    return payload[1:]

    def CommandRW(self,COMMAND=None,EVENT=None,back=None):
        try:
            if COMMAND:
                self.writeCommand(COMMAND)

            if EVENT:
                if type(EVENT) == int:
                    event = self.comport.read(EVENT)

                    if event == False:
                        return False

                    else:
                        return event

                Event = None
                evtcnt = 0

                if type(EVENT) == bytes:
                    Event = EVENT

                elif type(EVENT) == list:
                    if type(EVENT[0]) == bytes:
                        eventlayerid = EVENT[0]
                    else:
                        eventlayerid = EVENT[0].value

                    if type(EVENT[1]) == bytes:
                        eventid      = EVENT[1]
                    else:
                        eventid      = EVENT[1].value

                    if type(EVENT[2]) == bytes:
                        eventaction  = EVENT[2]
                    else:
                        eventaction  = EVENT[2].value

                    Event = eventlayerid + eventid + eventaction

                while 1:
                    event = self.readEvent()

                    if event == False:
                        return False

                    if evtcnt == 50:
                        logger.error('Over 50 uart event.No received need event inside')
                        logger.error(''.join(['Last Event : ' ,event.hex().upper()]))
                        logger.error(''.join(['Need Event : '.ljust(10) + Event.hex().upper()]))
                        return False

                    if Event[:3] == event[0:3]:
                        if back:
                            return event

                        if event[0] == api.Layer_ID.EVENT_COMMAND_COMPLETE.value:
                            status = event[-2:]

                            if status != api.MBA_RES.SUCCESS.value:
                                for result in api.MBA_RES:
                                    if status == result.value:
                                        logger.error('Command Complete Status: ' + result.name)
                                return False
                        else:
                            return True

                    else:
                        evtcnt += 1

        except(OSError):
            logger.error('Command W/R Fail in System Error')
            return False

class Common(uartHandle):
    def __init__(self,comport,profile,casename,ptsaddress_b,ixit,bleonly):
        uartHandle.__init__(self,comport)
        self.ixit          = ixit
        self.profile_b     = profile.encode()
        self.casename_b    = casename.encode()
        self.pts_address_b = ptsaddress_b
        self.bleonly       = bleonly
        self.iut_address_b = self.ixit[b'TSPX_bd_addr_iut'][1]
        self.iut_name      = b''.join([b'AutoPTS_' , self.profile_b])

    def iut_sw_reset(self):
        if not self.CommandRW(COMMAND = [api.Layer_ID.BT_GAP,
                                         api.BT_GAP_CMD_ID.RESET,
                                         b''],
                              EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                         api.Layer_ID.UTILITY,
                                         api.UTILITY_CMD_ID.INIT_DONE]):
            logger.error('...software reset failure ...')
            return False
        else:
            return True

    def iut_write_address(self,bleonly=None):
        if bleonly:
            ble_address = b''.join([api.BLE_GAP_ADDR_TYPE.PUBLIC.value,
                                    bytes.fromhex(self.iut_address_b.decode())[::-1]])

            if self.CommandRW(COMMAND = [api.Layer_ID.BLE_GAP,
                                        api.BLE_GAP_CMD_ID.SET_ADDR,
                                        ble_address],
                              EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                         api.Layer_ID.BLE_GAP,
                                         api.BLE_GAP_CMD_ID.SET_ADDR]):
                return True

            else:
                logger.error('...write iut address in BLE mode failure...')
                return False

        if self.CommandRW(COMMAND = [api.Layer_ID.BT_GAP,
                                     api.BT_GAP_CMD_ID.WRITE_BT_ADDR,
                                     bytes.fromhex(self.iut_address_b.decode())[::-1]],
                          EVENT   = [api.Layer_ID.BT_GAP,
                                     api.BT_GAP_Event_ID.COMMAND_COMPLETE,
                                     api.BT_GAP_Cmd_Complete_ID.WRITE_BT_ADDR]):
            return True

        else:
            logger.error('...write iut address in BT mode failure...')
            return False

    def iut_read_address(self):
        iut_address_bytes_hex = self.CommandRW(COMMAND = [api.Layer_ID.BT_GAP,
                                                          api.BT_GAP_CMD_ID.READ_BD_ADDR,
                                                          b''],
                                               EVENT    = [api.Layer_ID.BT_GAP,
                                                           api.BT_GAP_Event_ID.COMMAND_COMPLETE,
                                                           api.BT_GAP_Cmd_Complete_ID.READ_BD_ADDR],
                                               back     =  True)
        if not iut_address_bytes_hex:
            logger.error('...read iut address failure...')
            return False
        else:
            return iut_address_bytes_hex[4:][::-1]

    def iut_write_local_name(self):
        if not self.CommandRW(COMMAND = [api.Layer_ID.BT_GAP,
                                         api.BT_GAP_CMD_ID.WRITE_LOCAL_NAME,
                                         b''.join([len(self.iut_name).to_bytes(1,'big'),self.iut_name])],
                              EVENT   = [api.Layer_ID.BT_GAP,
                                         api.BT_GAP_Event_ID.COMMAND_COMPLETE,
                                         api.BT_GAP_Cmd_Complete_ID.WRITE_LOCAL_NAME]):
            logger.error('...write iut local name failure...')
            return False
        return True

    def iut_read_local_name(self):
        iut_local_name_bytes_hex = self.CommandRW(COMMAND = [api.Layer_ID.BT_GAP,
                                                             api.BT_GAP_CMD_ID.READ_LOCAL_NAME,
                                                             b''],
                                                  EVENT    = [api.Layer_ID.BT_GAP,
                                                              api.BT_GAP_Event_ID.COMMAND_COMPLETE,
                                                              api.BT_GAP_Cmd_Complete_ID.READ_LOCAL_NAME],
                                                  back     =  True)
        if not iut_local_name_bytes_hex:
            logger.error('...read iut local name failure...')
            return False
        else:
            return iut_local_name_bytes_hex[4:]

    def iut_set_device_name(self):
        if not self.CommandRW(COMMAND = [api.Layer_ID.BLE_GAP,
                                         api.BLE_GAP_CMD_ID.SET_DEV_NAME,
                                         b''.join([len(self.iut_name).to_bytes(1,'big'),self.iut_name])],
                              EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                         api.Layer_ID.BLE_GAP,
                                         api.BLE_GAP_CMD_ID.SET_DEV_NAME]):
            logger.error('...set iut local name failure...')
            return False
        return True

    def iut_get_device_name(self):
        iut_device_name_bytes_hex = self.CommandRW(COMMAND = [api.Layer_ID.BLE_GAP,
                                                              api.BLE_GAP_CMD_ID.GET_DEV_NAME,
                                                              b''],
                                                   EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                                              api.Layer_ID.BLE_GAP,
                                                              api.BLE_GAP_CMD_ID.GET_DEV_NAME],
                                                   back    = True)
        if not iut_device_name_bytes_hex:
            logger.error('...get iut local name failure...')
            return False
        else:
            return iut_device_name_bytes_hex[5:]

    def iut_erase_all_paired_device(self):
        if not self.CommandRW(COMMAND = [api.Layer_ID.RTU,
                                         api.RTU_CMD_ID.ERASE_ALL_PAIRED_DEVICE,
                                         b''],
                              EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                         api.Layer_ID.RTU,
                                         api.RTU_CMD_ID.ERASE_ALL_PAIRED_DEVICE]):
            logger.error('...erase all paired device failure...')
            return False
        else:
            return True

    def iut_register_callback(self):
        if self.profile_b == b'AVDTP':
            if not self.CommandRW(COMMAND = [api.Layer_ID.AVDTP,
                                             api.AVDTP_CMD_ID.REGISTER_CALLBACK,
                                             b''],
                                  EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                             api.Layer_ID.AVDTP,
                                             api.AVDTP_CMD_ID.REGISTER_CALLBACK]):

                logger.error(f'...register {self.profile_b.decode()} callback failure in AVDTP...')
                return False
            else:
                return True

        elif self.profile_b == b'AVCTP':
            if not self.CommandRW(COMMAND = [api.Layer_ID.AVCTP,
                                             api.AVCTP_CMD_ID.REGISTER_CALLBACK,
                                             b''],
                                  EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                             api.Layer_ID.AVCTP,
                                             api.AVCTP_CMD_ID.REGISTER_CALLBACK]):
                logger.error(f'...register {self.profile_b.decode()} callback failure in AVCTP...')
                return False
            else:
                return True

        elif self.profile_b == b'GAVDP':
            if not self.CommandRW(COMMAND = [api.Layer_ID.AVDTP,
                                             api.AVDTP_CMD_ID.REGISTER_CALLBACK,
                                             b''],
                                  EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                             api.Layer_ID.AVDTP,
                                            api.AVDTP_CMD_ID.REGISTER_CALLBACK]):
                logger.error(f'...register {self.profile_b.decode()} callback failure in GAVDTP...')
                return False
            else:
                return True

        elif self.profile_b == b'AVRCP':
            if not self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                             api.AVRCP_CMD_ID.EVENT_REGISTERATION,
                                             b''],
                                  EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                             api.Layer_ID.AVRCP,
                                             api.AVRCP_CMD_ID.EVENT_REGISTERATION]):
                logger.error(f'...register {self.profile_b.decode()} callback failure in AVRCP...')
                return False
            else:
                return True
        else:
            return True

    def iut_initial(self,bleonly):
        logger.info(' ... start iut initial  ...')

        if not self.iut_sw_reset():
            return False

        if not bleonly:
            if not self.iut_write_local_name():
                return False

        if not self.iut_write_address(bleonly):
            return False

        if not self.iut_set_device_name():
            return False

        if not self.iut_erase_all_paired_device():
            return False

        if not self.iut_register_callback():
            return False

        logger.info(' ... iut initial complete ...\n')

        return True

    def iut_white_list_init(self,listAddress = None):
        if not self.CommandRW(COMMAND = [api.Layer_ID.BLE_GAP,
                                         api.BLE_GAP_CMD_ID.CLEAR_WHITE_LIST,
                                         b''],
                              EVENT =   [api.Layer_ID.BLE_GAP,
                                         api.BLE_GAP_Event_ID.COMMAND_COMPLETE,
                                         api.BLE_GAP_Cmd_Complete_ID.CLEAR_WHITE_LIST]):
            logger.error('...clear iut white list failure...')
            return False

        white_list = [api.BLE_GAP_ADDR_TYPE.PUBLIC.value + bytes.fromhex(self.pts_address_b.decode())[::-1]]

        if listAddress:
            if type(listAddress) == bytes:
                if len(listAddress) == 6:
                    white_list.append(api.BLE_GAP_ADDR_TYPE.PUBLIC.value+listAddress)
                elif len(listAddress) == 12:
                    white_list.append(api.BLE_GAP_ADDR_TYPE.PUBLIC.value
                                      + bytes.fromhex(listAddress.decode())[::-1])
                else:
                    logger.error(f'... {listAddress} length error ...')
                    return False

            elif type(listAddress) == str:
                if len(listAddress) != 12:
                    logger.error(f'... {listAddress} length error ...')
                    return False
                white_list.append(api.BLE_GAP_ADDR_TYPE.PUBLIC.value
                                  + bytes.fromhex(listAddress)[::-1])

            elif type(listAddress) == list:
                for address in listAddress:
                    if type(address) == bytes:
                        if len(address) == 6:
                            white_list.append(api.BLE_GAP_ADDR_TYPE.PUBLIC.value + address)
                        elif len(address) == 12:
                            white_list.append(api.BLE_GAP_ADDR_TYPE.PUBLIC.value
                                              + bytes.fromhex(address.decode())[::-1])
                        else:
                            logger.error(f'... {address} length error ...')
                            return False

                    elif type(address) == str:
                        if len(address) != 12:
                            logger.error(f'... {address} length error ...')
                            return False
                        white_list.append(api.BLE_GAP_ADDR_TYPE.PUBLIC.value + bytes.fromhex(address)[::-1])

            else:
                logger.error(f'... {listAddress} type error ...')
                return False

        for address_hex in white_list:
            if not self.CommandRW(COMMAND = [api.Layer_ID.BLE_GAP,
                                             api.BLE_GAP_CMD_ID.ADD_WHITE_LIST,
                                             address_hex],
                                  EVENT   = [api.Layer_ID.BLE_GAP,
                                             api.BLE_GAP_Event_ID.COMMAND_COMPLETE,
                                             api.BLE_GAP_Cmd_Complete_ID.ADD_WHITE_LIST]):
                logger.error('... add iut white list failure...')
                return False

        return True

    def get_connetion_info(self):
        evtcnt = 0
        while 1:
            event = self.readEvent()

            if not event:
                logger.error('... get connection info failure ...')
                logger.error('... connection failure...')
                return False

            if evtcnt == 50:
                logger.error('over 50 uart event.No received connection event inside')
                logger.error('... get connection info failure ...')
                logger.error('... connection failure...')
                return False

            if event[0:2] == api.Layer_ID.BT_GAP.value + api.BT_GAP_Event_ID.CONNECTED.value or \
               event[0:2] == api.Layer_ID.BLE_GAP.value + api.BLE_GAP_Event_ID.CONNECTED.value:
                conn_info = dict()

                if event[0:1] == api.Layer_ID.BT_GAP.value:
                    conn_info['layer']       = event[0:1]
                    conn_info['status']      = event[2:3]
                    conn_info['connhandle']  = event[3:5]
                    conn_info['pts_address'] = event[5:11]
                    conn_info['linktype']    = event[11:12]
                    conn_info['encryption']  = event[12:]

                else:
                    conn_info['layer']            = event[0:1]
                    conn_info['connhandle']       = event[2:4]
                    conn_info['role']             = event[4:5]
                    conn_info['bonded']           = event[5:6]
                    conn_info['pts_address_type'] = event[6:7]
                    conn_info['pts_address_h']    = event[7:13]
                    conn_info['iut_address_type'] = event[13:14]
                    conn_info['iut_address_h']    = event[14:20]
                    conn_info['connpara']         = event[20:]

                logger.debug('\n')
                logger.debug('Connection Information')

                for key in conn_info:
                    logger.debug(f'{key} = {conn_info[key].hex().upper()}')

                logger.debug('\n')

                return conn_info

            evtcnt+=1

    def create_connection(self,layer):
        if layer == 'BT':
            PktType      = b'\xCC\x1A'
            PgeScnMode   = b'\x02'
            ClkOffRole   = b'\x00\x00\x01'
            CntAction    = b''.join([bytes.fromhex(self.pts_address_b.decode())[::-1],
                                     PktType,
                                     PgeScnMode,
                                     ClkOffRole])

            if self.CommandRW(COMMAND = [api.Layer_ID.BT_GAP,
                                         api.BT_GAP_CMD_ID.CREATE_CONNECTION,
                                         CntAction]) == False:
                logger.error('...send BT create connection command failure...')
                return False
            else:
                return self.get_connetion_info()

        elif layer == 'BLE':
            CntAction = b''.join([api.BLE_GAP_ADDR_TYPE.PUBLIC.value,
                                  bytes.fromhex(self.pts_address_b.decode())[::-1]])
            if self.CommandRW(COMMAND = [api.Layer_ID.BLE_GAP,
                                         api.BLE_GAP_CMD_ID.CREATE_CONNECTION,
                                         CntAction]) == False:
                logger.error('...send BLE create connection command failure...')
                return False
            else:
                  return self.get_connetion_info()

        else:
            logger.error(f'... {layer} not right ...')
            return False

    def advertising(self,advData = None, advParam = None, EnDisable = None):
        if not advData and not advParam and not EnDisable:
            logger.error('... no any advertising data or parameter in argv .. ')
            return False

        if advData:
            if not self.CommandRW(COMMAND = [api.Layer_ID.BLE_GAP,
                                             api.BLE_GAP_CMD_ID.SET_ADV_DATA,
                                             advData],
                                  EVENT   = [api.Layer_ID.BLE_GAP,
                                             api.BLE_GAP_Event_ID.COMMAND_COMPLETE,
                                             api.BLE_GAP_Cmd_Complete_ID.SET_ADVERTISING_DATA]):
                logger.error('...set advertising data failure...')
                return False

        if advParam:
            if not self.CommandRW(COMMAND = [api.Layer_ID.BLE_GAP,
                                             api.BLE_GAP_CMD_ID.SET_ADV_PARAM,
                                             advParam],
                                  EVENT   = [api.Layer_ID.BLE_GAP,
                                             api.BLE_GAP_Event_ID.COMMAND_COMPLETE,
                                             api.BLE_GAP_Cmd_Complete_ID.SET_ADVERTISING_PARAMS]):
                logger.error('...set advertising parameter failure...')
                return False

        if EnDisable:
            if not self.CommandRW(COMMAND = [api.Layer_ID.BLE_GAP,
                                             api.BLE_GAP_CMD_ID.ADV_ENABLE,
                                             EnDisable],
                                  EVENT   = [api.Layer_ID.BLE_GAP,
                                             api.BLE_GAP_Event_ID.COMMAND_COMPLETE,
                                             api.BLE_GAP_Cmd_Complete_ID.SET_ADVERTISING_ENABLE]):
                logger.error('...set advertising EnDisable failure...')
                return False

        return True

    def set_scanning(self,scanParam = None, scanMode = None):
        if scanParam:
            if not self.CommandRW(COMMAND = [api.Layer_ID.BLE_GAP,
                                             api.BLE_GAP_CMD_ID.SET_SCANNING_PARAM,
                                             scanParam],
                                  EVENT   = [api.Layer_ID.BLE_GAP,
                                             api.BLE_GAP_Event_ID.COMMAND_COMPLETE,
                                             api.BLE_GAP_Cmd_Complete_ID.SET_SCAN_PARAMS]):
                logger.error('...set scan parameter failure...')
                return False

        if scanMode:
            if not self.CommandRW(COMMAND = [api.Layer_ID.BLE_GAP,
                                             api.BLE_GAP_CMD_ID.SET_SCANNING_ENABLE,
                                             scanMode],
                                  EVENT   = [api.Layer_ID.BLE_GAP,
                                             api.BLE_GAP_Event_ID.COMMAND_COMPLETE,
                                             api.BLE_GAP_Cmd_Complete_ID.SET_SCAN_ENABLE]):
                logger.error('...set scan mode failure...')
                return False

        return True

    def adv_report_paser(self,advreport):
        report = dict()
        report['evtType']    = advreport[2:3]
        report['addrType']   = advreport[3:4]
        report['address']    = advreport[4:10]
        report['dataLength'] = int(bytes.hex(advreport[10:11]),16)
        locate               = 11 + int(bytes.hex(api.BLE_GAP_ADV.MAX_LENGTH.value),16)
        report['advData']    = advreport[11:locate]
        report['rssi']       = advreport[locate:locate+1]
        report['connPara']   = advreport[locate+1:locate+11]
        report['bonded']     = advreport[locate+11:locate+12]
        return report

class A2DP(Common):
    def __init__(self,comport,profile,casename,ptsaddress_b,ixit,bleonly):
        Common.__init__(self,comport,profile,casename,ptsaddress_b,ixit,bleonly)
        self.id       = b'\x00'
        self.conninfo = None

    def mmi(self,descript):
        return

    def mmi6(self,descript):
        logger.info(f'\n{descript}\n')
        return [True,'mmi']

    def mmi10(self,descript):
        logger.info(''.join(['\n', descript,'\n']))
        if 'Audio SNK' in descript or 'MCHP' in descript:
            return self.iut_erase_all_paired_device()

    def mmi11(self,descript):
        logger.info(''.join(['\n', descript,'\n']))
        if 'Value: 0x0003' in descript:
            return self.iut_erase_all_paired_device()

    def mmi12(self,descript):
        logger.info(f'\n{descript}\n')
        return True

    def mmi13(self,descript):
        logger.info(f'\n{descript}\n')
        return True

    def mmi1002(self, descript):
        logger.info(f'\n{descript}\n')

        conninfo = self.get_connetion_info()

        if not conninfo:
            return False

        self.conninfo = conninfo

        return

    def mmi1008(self,descript):
        logger.info(f'\n{descript}\n')
        return True

    def mmi1013(self,descript):
        logger.info(''.join(['\n', descript,'\n']))
        if self.CommandRW(EVENT = [api.Layer_ID.A2DP,
                                   api.A2DP_Event_ID.CONNECT_CFM,
                                   self.id]):
            if self.CommandRW(EVENT = [api.Layer_ID.A2DP,
                                       api.A2DP_Event_ID.START_IND,
                                       self.id]):
                return True
            else:
                return False
        else:
            return False

    def mmi1015(self,descript):
        logger.info(''.join(['\n', descript,'\n']))
        avdtpId = b'\x00'
        acpSeid = b'\x01'
        req     = b''.join([avdtpId,acpSeid])
        if self.CommandRW(COMMAND = [api.Layer_ID.AVDTP,
                                     api.AVDTP_CMD_ID.CLOSE_REQ,
                                     req],
                          EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                     api.Layer_ID.AVDTP,
                                     api.AVDTP_CMD_ID.CLOSE_REQ]):
            return
        else:
            return False

    def mmi1016(self,descript):
        logger.info(''.join(['\n', descript,'\n']))
        if self.casename_b == b'IOPT/CL/A2DP-SNK/SFC/BV-02-I':
            if not self.CommandRW(COMMAND = [api.Layer_ID.AVDTP,
                                             api.AVDTP_CMD_ID.REGISTER_CALLBACK,
                                             b''],
                                  EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                             api.Layer_ID.AVDTP,
                                             api.AVDTP_CMD_ID.REGISTER_CALLBACK]):
                return False

        conninfo = self.create_connection('BT')

        if not conninfo:
            return False

        self.conninfo = conninfo

        avdtpId = b'\x00'
        mtu     = bytes(2)
        connect_req = b''.join([self.conninfo['connhandle'],mtu])
        if self.CommandRW(COMMAND = [api.Layer_ID.AVDTP,
                                     api.AVDTP_CMD_ID.CONNECT_REQ,
                                     connect_req],
                          EVENT   = [api.Layer_ID.AVDTP,
                                     api.AVDTP_Event_ID.CONNECT_COMPLETE_CFM,
                                     avdtpId]):
            return
        else:
            return False

    def mmi1020(self,descript):
        logger.info(''.join(['\n', descript,'\n']))
        if self.CommandRW(COMMAND = [api.Layer_ID.AVDTP,
                                     api.AVDTP_CMD_ID.REGISTER_CALLBACK,
                                     b''],
                          EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                     api.Layer_ID.AVDTP,
                                     api.AVDTP_CMD_ID.REGISTER_CALLBACK]):
            avdtpId        = b'\x00'
            acpSeid        = b'\x01'
            intSeid        = b'\x02'
            NonDelayReport = b'\x00'
            config         = b''.join([avdtpId, acpSeid, intSeid, NonDelayReport])
            if self.CommandRW(COMMAND = [api.Layer_ID.AVDTP,
                                         api.AVDTP_CMD_ID.SETCONFIGURATION_REQ,
                                         config],
                              EVENT   = [api.Layer_ID.AVDTP,
                                         api.AVDTP_Event_ID.SET_CONFIGURATION_CFM,
                                         avdtpId]):
                req = b''.join([avdtpId,acpSeid])
                if self.CommandRW(COMMAND = [api.Layer_ID.AVDTP,
                                             api.AVDTP_CMD_ID.OPEN_REQ,
                                             req],
                                  EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                             api.Layer_ID.AVDTP,
                                             api.AVDTP_CMD_ID.OPEN_REQ]):
                    return
                else:
                    return False
            else:
                return False
        else:
            return False

    def mmi1029(self,descript):
        logger.info(f'\n{descript}\n')
        if self.CommandRW(COMMAND = [api.Layer_ID.BT_GAP,
                                     api.BT_GAP_CMD_ID.DISCONNECT,
                                     self.conninfo['connhandle']],
                          EVENT   = [api.Layer_ID.BT_GAP,
                                     api.BT_GAP_Event_ID.DISCONNECTED,
                                     api.BT_GAP_Status_ID.SUCCESS]):
            return
        else:
            return False

    def mmi1031(self,descript):
        logger.info(''.join(['\n', descript,'\n']))
        if self.CommandRW(COMMAND = [api.Layer_ID.AVDTP,
                                     api.AVDTP_CMD_ID.REGISTER_CALLBACK,
                                     b''],
                          EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                     api.Layer_ID.AVDTP,
                                     api.AVDTP_CMD_ID.REGISTER_CALLBACK]):
            avdtpId        = b'\x00'
            acpSeid        = b'\x01'
            intSeid        = b'\x02'
            NonDelayReport = b'\x00'
            config         = b''.join([avdtpId, acpSeid, intSeid, NonDelayReport])
            if self.CommandRW(COMMAND = [api.Layer_ID.AVDTP,
                                         api.AVDTP_CMD_ID.SETCONFIGURATION_REQ,
                                         config],
                              EVENT   = [api.Layer_ID.AVDTP,
                                         api.AVDTP_Event_ID.SET_CONFIGURATION_CFM,
                                         avdtpId]):
                return
            else:
                return False
        else:
            return False

    def mmi1032(self,descript):
        logger.info(''.join(['\n', descript,'\n']))
        avdtpId = b'\x00'
        acpSeid = b'\x01'
        req = b''.join([avdtpId, acpSeid])
        if self.casename_b == b'A2DP/SNK/SET/BV-06-I':
            if not self.CommandRW(COMMAND = [api.Layer_ID.AVDTP,
                                             api.AVDTP_CMD_ID.REGISTER_CALLBACK,
                                             b''],
                                  EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                             api.Layer_ID.AVDTP,
                                             api.AVDTP_CMD_ID.REGISTER_CALLBACK]):
                return False
            else:
                avdtpId        = b'\x00'
                acpSeid        = b'\x01'
                intSeid        = b'\x02'
                NonDelayReport = b'\x00'
                config         = b''.join([avdtpId, acpSeid, intSeid, NonDelayReport])
                if not self.CommandRW(COMMAND = [api.Layer_ID.AVDTP,
                                             api.AVDTP_CMD_ID.SETCONFIGURATION_REQ,
                                             config],
                                  EVENT   = [api.Layer_ID.AVDTP,
                                             api.AVDTP_Event_ID.SET_CONFIGURATION_CFM,
                                             avdtpId]):
                    return False


        if self.CommandRW(COMMAND = [api.Layer_ID.AVDTP,
                                     api.AVDTP_CMD_ID.OPEN_REQ,
                                     req],
                          EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                     api.Layer_ID.AVDTP,
                                     api.AVDTP_CMD_ID.OPEN_REQ]):
            time.sleep(2)
            if self.CommandRW(COMMAND = [api.Layer_ID.AVDTP,
                                         api.AVDTP_CMD_ID.START_REQ,
                                         req],
                              EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                         api.Layer_ID.AVDTP,
                                         api.AVDTP_CMD_ID.START_REQ]):
                return
            else:
                return False
        else:
            return False

    def mmi1034(self,descript):
        logger.info(''.join(['\n', descript,'\n']))
        if self.CommandRW(COMMAND = [api.Layer_ID.AVDTP,
                                     api.AVDTP_CMD_ID.REGISTER_CALLBACK,
                                     b''],
                          EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                     api.Layer_ID.AVDTP,
                                     api.AVDTP_CMD_ID.REGISTER_CALLBACK]):
            avdtpId = b'\x00'
            acpSeid = b'\x01'
            req = b''.join([avdtpId, acpSeid])
            if self.CommandRW(COMMAND = [api.Layer_ID.AVDTP,
                                         api.AVDTP_CMD_ID.SUSPEND_REQ,
                                         req],
                              EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                         api.Layer_ID.AVDTP,
                                         api.AVDTP_CMD_ID.SUSPEND_REQ]):
                return
            else:
                return False
        else:
            return False

class AVCTP(Common):
    def __init__(self,comport,profile,casename,ptsaddress_b,ixit,bleonly):
        Common.__init__(self,comport,profile,casename,ptsaddress_b,ixit,bleonly)
        self.id       = b'\x00'
        self.conninfo = None

    def mmi(self,descript):
        return

    def mmi2(self,descript):
        logger.info(f'\n{descript}\n')
        mtu = bytes(2)
        connect_req = b''.join([self.conninfo['connhandle'],mtu])
        if not self.CommandRW(COMMAND = [api.Layer_ID.AVCTP,
                                         api.AVCTP_CMD_ID.CONNECT_REQ,
                                         connect_req],
                              EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                         api.Layer_ID.AVCTP,
                                         api.AVCTP_CMD_ID.CONNECT_REQ]):
            return True
        else:
            return False

    def mmi10(self,descript):
        logger.info(f'\n{descript}\n')
        conninfo = self.create_connection('BT')
        if not conninfo:
            return False
        else:
            self.conninfo = conninfo
            return True

    def mmi11(self,descript):
        logger.info(f'\n{descript}\n')
        return True

    def mmi12(self,descript):
        logger.info(f'\n{descript}\n')
        return True

    def mmi13(self,descript):
        logger.info(f'\n{descript}\n')
        if self.CommandRW(EVENT = [api.Layer_ID.AVCTP,
                                   api.AVCTP_Event_ID.CONNECT_COMPLETE_CFM,
                                   self.id]):
            return True
        else:
            return False

    def mmi14(self,descript):
        logger.info(f'\n{descript}\n')
        return True

    def mmi15(self,descript):
        logger.info(f'\n{descript}\n')
        if self.CommandRW(EVENT = [api.Layer_ID.AVCTP,
                                   api.AVCTP_Event_ID.CONNECT_COMPLETE_CFM,
                                   self.id]):
            if self.CommandRW(COMMAND = [api.Layer_ID.AVCTP,
                                         api.AVCTP_CMD_ID.SEND_SINGLE_COMMAND_MESSAGE,
                                         self.id],
                              EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                         api.Layer_ID.AVCTP,
                                         api.AVCTP_CMD_ID.SEND_SINGLE_COMMAND_MESSAGE]):
                return True
            else:
                return False
        else:
            return False

    def mmi16(self,descript):
        logger.info(f'\n{descript}\n')
        mtu = bytes(2)
        connect_req = b''.join([self.conninfo['connhandle'],mtu])
        if self.CommandRW(COMMAND = [api.Layer_ID.AVCTP,
                                     api.AVCTP_CMD_ID.CONNECT_REQ,
                                     connect_req]) != False:
            return
        else:
            return False

    def mmi18(self,descript):
        logger.info(''.join(['\n', descript,'\n']))
        if self.CommandRW(COMMAND = [api.Layer_ID.AVCTP,
                                     api.AVCTP_CMD_ID.DISCONNECT_REQ,
                                     self.id],
                          EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                     api.Layer_ID.AVCTP,
                                     api.AVCTP_CMD_ID.DISCONNECT_REQ]):
            return
        else:
            return False

    def mmi19(self,descript):
        logger.info(''.join(['\n', descript,'\n']))
        if self.CommandRW(COMMAND = [api.Layer_ID.AVCTP,
                                     api.AVCTP_CMD_ID.SEND_SINGLE_COMMAND_MESSAGE,
                                     self.id],
                          EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                     api.Layer_ID.AVCTP,
                                     api.AVCTP_CMD_ID.SEND_SINGLE_COMMAND_MESSAGE]):
            return
        else:
            return False

    def mmi21(self,descript):
        logger.info(''.join(['\n', descript,'\n']))
        if self.CommandRW(COMMAND = [api.Layer_ID.AVCTP,
                                     api.AVCTP_CMD_ID.SEND_FRAGMENT_COMMAND_MESSAGE,
                                     self.id],
                          EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                     api.Layer_ID.AVCTP,
                                     api.AVCTP_CMD_ID.SEND_FRAGMENT_COMMAND_MESSAGE]):
            return
        else:
            return False

    def mmi23(self, descript):
        logger.info(f'\n{descript}\n')
        if self.CommandRW(EVENT = [api.Layer_ID.AVCTP,
                                   api.AVCTP_Event_ID.MESSAGE_REC_IND,
                                   self.id]):
            return True
        else:
            return False

    def mmi24(self,descript):
        logger.info(f'\n{descript}\n')
        if self.CommandRW(EVENT = [api.Layer_ID.AVCTP,
                                   api.AVCTP_Event_ID.MESSAGE_REC_IND,
                                   self.id]):
            return True
        else:
            return False

    def mmi25(self,descript):
        logger.info(f'\n{descript}\n')
        if self.CommandRW(EVENT = [api.Layer_ID.AVCTP,
                                   api.AVCTP_Event_ID.MESSAGE_REC_IND,
                                   self.id]):
            return True
        else:
            return False

    def mmi26(self,descript):
        logger.info(f'\n{descript}\n')
        if self.CommandRW(EVENT = [api.Layer_ID.AVCTP,
                                   api.AVCTP_Event_ID.CONNECT_COMPLETE_CFM,
                                   self.id]):
            return True
        else:
            return False

    def mmi27(self,descript):
        logger.info(f'\n{descript}\n')
        if self.CommandRW(EVENT = [api.Layer_ID.AVCTP,
                                   api.AVCTP_Event_ID.CONNECT_COMPLETE_CFM,
                                   self.id]):
            return True
        else:
            return False

    def mmi28(self,descript,):
        logger.info(f'\n{descript}\n')
        if self.CommandRW(EVENT = [api.Layer_ID.AVCTP,
                                   api.AVCTP_Event_ID.DISCONNECT_CFM,
                                   self.id]):
            return True
        else:
            return False

    def mmi29(self,descript):
        logger.info(f'\n{descript}\n')
        if self.CommandRW(EVENT = [api.Layer_ID.AVCTP,
                                   api.AVCTP_Event_ID.DISCONNECT_IND,
                                   self.id]):
            return True
        else:
            return False

    def mmi30(self,descript):
        logger.info(f'\n{descript}\n')
        if self.CommandRW(EVENT = [api.Layer_ID.AVCTP,
                                   api.AVCTP_Event_ID.MESSAGE_REC_IND,
                                   self.id]):
            return True
        else:
            return False

    def mmi32(self,descript):
        logger.info(f'\n{descript}\n')
        if self.CommandRW(EVENT = [api.Layer_ID.AVCTP,
                                   api.AVCTP_Event_ID.MESSAGE_REC_IND,
                                   self.id]):
            return True
        else:
            return False

    def mmi33(self,descript):
        logger.info(f'\n{descript}\n')
        if self.CommandRW(EVENT = [api.Layer_ID.AVCTP,
                                   api.AVCTP_Event_ID.MESSAGE_REC_IND,
                                   self.id]):
            return True
        else:
            return False

    def mmi34(self,descript):
        logger.info(f'\n{descript}\n')
        if self.CommandRW(EVENT = [api.Layer_ID.AVCTP,
                                   api.AVCTP_Event_ID.MESSAGE_REC_IND,
                                   self.id]):
            return True
        else:
            return False

    def mmi35(self,descript):
        logger.info(f'\n{descript}\n')
        return True

    def mmi36(self,descript):
        logger.info(f'\n{descript}\n')
        if self.CommandRW(EVENT = [api.Layer_ID.AVCTP,
                                   api.AVCTP_Event_ID.MESSAGE_REC_IND,
                                   self.id]):
            return True
        else:
            return False

    def mmi37(self,descript):
        logger.info(f'\n{descript}\n')
        if self.CommandRW(EVENT = [api.Layer_ID.AVCTP,
                                   api.AVCTP_Event_ID.MESSAGE_REC_IND,
                                   self.id]):
            return True
        else:
            return False

    def mmi1016(self,descript):
        logger.info(''.join(['\n', descript,'\n']))
        if self.CommandRW(COMMAND = [api.Layer_ID.AVDTP,
                                     api.AVDTP_CMD_ID.REGISTER_CALLBACK,
                                     b''],
                          EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                     api.Layer_ID.AVDTP,
                                     api.AVDTP_CMD_ID.REGISTER_CALLBACK]):
            avdtpId = b'\x00'
            mtu = bytes(2)
            connect_req = b''.join([self.conninfo['connhandle'], mtu])
            if self.CommandRW(COMMAND = [api.Layer_ID.AVDTP,
                                         api.AVDTP_CMD_ID.CONNECT_REQ,
                                         connect_req],
                              EVENT   = [api.Layer_ID.AVDTP,
                                         api.AVDTP_Event_ID.CONNECT_COMPLETE_CFM,
                                         avdtpId]):
                return
            else:
                return False
        else:
            return False

class AVDTP(Common):
    def __init__(self,comport,profile,casename,ptsaddress_b,ixit,bleonly):
        Common.__init__(self,comport,profile,casename,ptsaddress_b,ixit,bleonly)
        self.id       = b'\x00'
        self.conninfo = None

    def mmi(self,descript):
        return

    def mmi9(self,descript):
        logger.info(''.join(['\n', descript,'\n']))
        acpSeid    = b'\x01'
        Delay      = b'\x00\x05'
        req        = b''.join([self.id, acpSeid,Delay])
        if self.CommandRW(COMMAND = [api.Layer_ID.AVDTP,
                                     api.AVDTP_CMD_ID.DELAYREPORT_REQ,
                                     req],
                          EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                     api.Layer_ID.AVDTP,
                                     api.AVDTP_CMD_ID.DELAYREPORT_REQ]):
            return
        else:
            return False

    def mmi16(self,descript):
        logger.info(''.join(['\n', descript,'\n']))
        acpSeid        = b'\x01'
        intSeid        = b'\x02'
        DelayReport    = b'\x01'
        config         = b''.join([self.id, acpSeid, intSeid, DelayReport])
        if self.CommandRW(COMMAND = [api.Layer_ID.AVDTP,
                                     api.AVDTP_CMD_ID.SETCONFIGURATION_REQ,
                                     config],
                          EVENT   = [api.Layer_ID.AVDTP,
                                     api.AVDTP_Event_ID.SET_CONFIGURATION_CFM,
                                     self.id]):
            return
        else:
            return False

    def mmi17(self,descript):
        logger.info(''.join(['\n', descript,'\n']))
        acpSeid        = b'\x01'
        intSeid        = b'\x02'
        DelayReport    = b'\x01'
        Delay          = b'\x00\x05'
        config         = b''.join([self.id, acpSeid, intSeid, DelayReport])
        req            = b''.join([self.id, acpSeid, Delay])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVDTP,
                                     api.AVDTP_CMD_ID.SETCONFIGURATION_REQ,
                                     config],
                          EVENT   = [api.Layer_ID.AVDTP,
                                     api.AVDTP_Event_ID.SET_CONFIGURATION_CFM,
                                     self.id]):
            if self.CommandRW(COMMAND = [api.Layer_ID.AVDTP,
                                         api.AVDTP_CMD_ID.DELAYREPORT_REQ,
                                         req],
                              EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                         api.Layer_ID.AVDTP,
                                         api.AVDTP_CMD_ID.DELAYREPORT_REQ]):
                return
            else:
                return False
        else:
            return False

    def mmi29(self,descript):
        logger.info(f'\n{descript}\n')
        return True

    def mmi30(self,descript):
        logger.info(''.join(['\n', descript,'\n']))
        if self.CommandRW(EVENT = [api.Layer_ID.AVDTP,
                                   api.AVDTP_Event_ID.GET_ALL_CAPABILITIES_CFM,
                                   self.id]):
                return True
        else:
            return False

    def mmi1002(self, descript):
        logger.info(f'\n{descript}\n')
        conninfo = self.get_connetion_info()
        if not conninfo:
            return False
        else:
            self.conninfo = conninfo
            return

    def mmi1013(self,descript):
        logger.info(''.join(['\n', descript,'\n']))
        if self.CommandRW(EVENT = [api.Layer_ID.AVDTP,
                                   api.AVDTP_Event_ID.CONNECT_COMPLETE_CFM,
                                   self.id]):
                return True
        else:
            return False

    def mmi1014(self,descript):
        logger.info(''.join(['\n', descript,'\n']))
        acpSeid = b'\x01'
        req     = b''.join([self.id, acpSeid])
        if self.CommandRW(COMMAND = [api.Layer_ID.AVDTP,
                                     api.AVDTP_CMD_ID.ABORT_REQ,
                                     req],
                          EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                     api.Layer_ID.AVDTP,
                                     api.AVDTP_CMD_ID.ABORT_REQ]):
            return
        else:
            return False

    def mmi1015(self,descript):
        logger.info(''.join(['\n', descript,'\n']))
        acpSeid        = b'\x01'
        req            = b''.join([self.id, acpSeid])
        if self.casename_b == b'AVDTP/SRC/INT/SIG/SMG/BV-19-C':
            if self.CommandRW(COMMAND = [api.Layer_ID.AVDTP,
                                         api.AVDTP_CMD_ID.STOP_MEDIA_PACKET,
                                         b'']) == False:
                return False

        if self.CommandRW(COMMAND = [api.Layer_ID.AVDTP,
                                     api.AVDTP_CMD_ID.CLOSE_REQ,
                                     req],
                          EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                     api.Layer_ID.AVDTP,
                                     api.AVDTP_CMD_ID.CLOSE_REQ]):
            return
        else:
            return False

    def mmi1018(self,descript):
        logger.info(''.join(['\n', descript,'\n']))
        if self.CommandRW(COMMAND = [api.Layer_ID.AVDTP,
                                     api.AVDTP_CMD_ID.DISCOVER_REQ,
                                     self.id],
                          EVENT   = [api.Layer_ID.AVDTP,
                                     api.AVDTP_Event_ID.DISCOVER_CFM,
                                     self.id]):
            return
        else:
            return False

    def mmi1019(self,descript):
        logger.info(''.join(['\n', descript,'\n']))
        acpSeid = b'\x01'
        req     = b''.join([self.id, acpSeid])
        if self.CommandRW(COMMAND = [api.Layer_ID.AVDTP,
                                     api.AVDTP_CMD_ID.GETCAPABILITIES_REQ,
                                     req],
                          EVENT   = [api.Layer_ID.AVDTP,
                                     api.AVDTP_Event_ID.GET_CAPABILITIES_CFM,
                                     self.id]):
            return
        else:
            return False

    def mmi1020(self,descript):
        logger.info(''.join(['\n', descript,'\n']))
        acpSeid        = b'\x01'
        intSeid        = b'\x02'
        NonDelayReport = b'\x00'
        config         = b''.join([self.id, acpSeid, intSeid, NonDelayReport])
        req            = b''.join([self.id, acpSeid])
        if self.CommandRW(COMMAND = [api.Layer_ID.AVDTP,
                                     api.AVDTP_CMD_ID.SETCONFIGURATION_REQ,
                                     config],
                          EVENT   = [api.Layer_ID.AVDTP,
                                     api.AVDTP_Event_ID.SET_CONFIGURATION_CFM,
                                     self.id]):
            if self.CommandRW(COMMAND = [api.Layer_ID.AVDTP,
                                         api.AVDTP_CMD_ID.OPEN_REQ,
                                         req],
                              EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                         api.Layer_ID.AVDTP,
                                         api.AVDTP_CMD_ID.OPEN_REQ]):
                return
            else:
                return False
        else:
            return False

    def mmi1030(self,descript):
        logger.info(''.join(['\n', descript,'\n']))
        acpSeid = b'\x01'
        req     = b''.join([self.id, acpSeid])
        if self.CommandRW(COMMAND = [api.Layer_ID.AVDTP,
                                     api.AVDTP_CMD_ID.RECONFIGURATION_REQ,
                                     req],
                          EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                     api.Layer_ID.AVDTP,
                                     api.AVDTP_CMD_ID.RECONFIGURATION_REQ]):
            return
        else:
            return False

    def mmi1031(self,descript):
        logger.info(''.join(['\n', descript,'\n']))
        acpSeid        = b'\x01'
        intSeid        = b'\x02'
        NonDelayReport = b'\x00'
        config         = b''.join([self.id, acpSeid, intSeid, NonDelayReport])
        if self.CommandRW(COMMAND = [api.Layer_ID.AVDTP,
                                     api.AVDTP_CMD_ID.SETCONFIGURATION_REQ,
                                     config],
                          EVENT   = [api.Layer_ID.AVDTP,
                                     api.AVDTP_Event_ID.SET_CONFIGURATION_CFM,
                                     self.id]):
            return
        else:
            return False

    def mmi1032(self,descript):
        logger.info(''.join(['\n', descript,'\n']))
        acpSeid        = b'\x01'
        intSeid        = b'\x02'
        NonDelayReport = b'\x00'
        config         = b''.join([self.id, acpSeid, intSeid, NonDelayReport])
        req            = b''.join([self.id, acpSeid])
        if self.casename_b == b'AVDTP/SNK/INT/SIG/SMG/BV-19-C' or \
           self.casename_b == b'AVDTP/SRC/INT/SIG/SMG/BV-17-C' or \
           self.casename_b == b'AVDTP/SRC/INT/SIG/SMG/BV-19-C' or \
           self.casename_b == b'AVDTP/SRC/INT/SIG/SMG/BV-21-C' or \
           self.casename_b == b'AVDTP/SRC/INT/TRA/BTR/BV-01-C':
            if self.CommandRW(COMMAND = [api.Layer_ID.AVDTP,
                                         api.AVDTP_CMD_ID.SETCONFIGURATION_REQ,
                                         config],
                              EVENT   = [api.Layer_ID.AVDTP,
                                         api.AVDTP_Event_ID.SET_CONFIGURATION_CFM,
                                         self.id]):
                time.sleep(1)
                if self.CommandRW(COMMAND = [api.Layer_ID.AVDTP,
                                             api.AVDTP_CMD_ID.OPEN_REQ,
                                             req],
                                  EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                             api.Layer_ID.AVDTP,
                                             api.AVDTP_CMD_ID.OPEN_REQ]):
                    time.sleep(1)
                else:
                    return False
            else:
                return False

        if self.CommandRW(COMMAND = [api.Layer_ID.AVDTP,
                                     api.AVDTP_CMD_ID.START_REQ,
                                     req],
                          EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                     api.Layer_ID.AVDTP,
                                     api.AVDTP_CMD_ID.START_REQ]):
            return

    def mmi1033(self,descript):
        logger.info(''.join(['\n', descript,'\n']))
        if self.CommandRW(COMMAND = [api.Layer_ID.AVDTP,
                                     api.AVDTP_CMD_ID.SEND_MEDIA_PACKET,
                                     b'']) != False:
            return
        else:
            return False

    def mmi1034(self,descript):
        logger.info(''.join(['\n', descript,'\n']))
        acpSeid = b'\x01'
        req     = b''.join([self.id, acpSeid])
        if self.casename_b == b'AVDTP/SRC/INT/SIG/SMG/BV-13-C' or \
           self.casename_b == b'AVDTP/SRC/INT/SIG/SMG/BV-21-C':
            if self.CommandRW(COMMAND = [api.Layer_ID.AVDTP,
                                         api.AVDTP_CMD_ID.STOP_MEDIA_PACKET,
                                         b'']) == False:
                return False

        if self.CommandRW(COMMAND = [api.Layer_ID.AVDTP,
                                     api.AVDTP_CMD_ID.SUSPEND_REQ,
                                     req],
                          EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                     api.Layer_ID.AVDTP,
                                     api.AVDTP_CMD_ID.SUSPEND_REQ]):
            return
        else:
            return False

    def mmi1035(self,descript):
        logger.info(''.join(['\n', descript,'\n']))
        acpSeid        = b'\x01'
        req            = b''.join([self.id, acpSeid])
        if self.CommandRW(COMMAND = [api.Layer_ID.AVDTP,
                                     api.AVDTP_CMD_ID.GETALLCAPABILITIES_REQ,
                                     req],
                          EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                     api.Layer_ID.AVDTP,
                                     api.AVDTP_CMD_ID.GETALLCAPABILITIES_REQ]):
            return
        else:
            return False

    def mmi1036(self,descript):
        logger.info(''.join(['\n', descript,'\n']))
        if self.CommandRW(COMMAND = [api.Layer_ID.AVDTP,
                                     api.AVDTP_CMD_ID.SEND_MEDIA_PACKET,
                                     b'']) != False:
            return
        else:
            return False

    def mmi1041(self,descript):
        logger.info(''.join(['\n', descript,'\n']))
        acpSeid = b'\x01'
        req     = b''.join([self.id, acpSeid])
        if self.CommandRW(COMMAND = [api.Layer_ID.AVDTP,
                                     api.AVDTP_CMD_ID.GETCONFIGURATION_REQ,
                                     req],
                          EVENT   = [api.Layer_ID.AVDTP,
                                     api.AVDTP_Event_ID.GET_CONFIGURATION_CFM,
                                     self.id]):
            return
        else:
            return False

    def mmi1046(self,descript):
        logger.info(''.join(['\n', descript,'\n']))
        if self.CommandRW(COMMAND = [api.Layer_ID.AVDTP,
                                     api.AVDTP_CMD_ID.SEND_MEDIA_PACKET,
                                     b'']) != False:
            return
        else:
            return False

class AVRCP(Common):
    def __init__(self,comport,profile,casename,ptsaddress_b,ixit,bleonly):
        Common.__init__(self,comport,profile,casename,ptsaddress_b,ixit,bleonly)
        self.id         = b'\x00'
        self.conninfo   = None
        self.uidcounter = None
        self.folderUid  = list()
        self.response   = None
        self.volume     = None

    def mmi(self,descript):
        if self.response == api.AVRCP_RESPONSE.CHANGED.value:
            startItem  = b'\x00\x00\x00\x00'
            endItem    = b'\xFF\xFF\xFF\xFF'
            attCount   = b'\x00'
            scope      = b''

            if self.casename_b == b'AVRCP/CT/MCN/CB/BV-05-I':
                scope = b''.join([self.id,
                                  api.AVRCP_SCOPE_MEDIA_PLAYER.VIRTUAL_FILESYSTEM.value,
                                  startItem,
                                  endItem,
                                  attCount])

            if self.casename_b == b'AVRCP/CT/MCN/NP/BV-04-I':
                scope = b''.join([self.id,
                                  api.AVRCP_SCOPE_MEDIA_PLAYER.NOW_PLAYING.value,
                                  startItem,
                                  endItem,
                                  attCount])

            if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                         api.AVRCP_CMD_ID.GET_FOLDER_ITEM,
                                         scope],
                              EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                         api.Layer_ID.AVRCP,
                                         api.AVRCP_CMD_ID.GET_FOLDER_ITEM]):
                return
            else:
                return False

        return

    def mmi3(self,descript):
        logger.info(''.join(['\n', descript,'\n']))

        folderUid = (len(self.folderUid) + 1).to_bytes(4,'big')*2
        item      = b''.join([self.id,
                              api.AVRCP_SCOPE_MEDIA_PLAYER.VIRTUAL_FILESYSTEM.value,
                              folderUid,
                              self.uidcounter])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PLAY_ITEM,
                                     item],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PLAY_ITEM,
                                     self.id]):
            return
        else:
            return False

    def mmi4(self,descript):
        logger.info(''.join(['\n', descript,'\n']))

        attrID  = b''.join([api.AVRCP_MEDIA_ATTR_ID.TITLE.value])
        element = b''.join([self.id,
                            api.AVRCP_ELEMENT_ID.PLAYING.value*8,
                            int(len(attrID)/4).to_bytes(1,'big'),
                            attrID])

        attrsRsp =  self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                              api.AVRCP_CMD_ID.GET_ELEMENT_ATTRS,
                                              element],
                                   EVENT   = [api.Layer_ID.AVRCP,
                                              api.AVRCP_Event_ID.GET_ELEMENT_ATTR,
                                              self.id],
                                   back    = True)

        if not attrsRsp:
            return False

        if self.casename_b == b'AVRCP/CT/RCR/BV-03-C':
            attr = b''.join([self.id,
                             api.AVRCP_PDU_ID.GET_ELEMENT_ATTRIBUTE.value])

            if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                         api.AVRCP_CMD_ID.ABOUT_CONT_RSP,
                                         attr],
                              EVENT   = [api.Layer_ID.AVRCP,
                                         api.AVRCP_Event_ID.ABORT_CONTINUE_RSP,
                                         self.id]):
                return
            else:
                return False

        end = attrsRsp[4:5]

        while end != b'\x01':
            attr = b''.join([self.id,
                             api.AVRCP_PDU_ID.GET_ELEMENT_ATTRIBUTE.value])

            attrsRsp =  self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                                  api.AVRCP_CMD_ID.REQUEST_CONT_RSP,
                                                  attr],
                                       EVENT   = [api.Layer_ID.AVRCP,
                                                  api.AVRCP_Event_ID.GET_ELEMENT_ATTR,
                                                  self.id],
                                       back    = True)

            if not attrsRsp:
                return False

            end = attrsRsp[4:5]

        return

    def mmi16(self,descript):
        logger.info(''.join(['\n', descript,'\n']))

        volume    = b'\x00'
        absVolume = b''.join([self.id,
                              api.AVRCP_RESPONSE.REJECT.value,
                              volume])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.SET_ABSOLUTE_VOLUME_RSP,
                                     absVolume],
                          EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                     api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.SET_ABSOLUTE_VOLUME_RSP]):
            return
        else:
            return False

    def mmi27(self,descript):
        logger.info(''.join(['\n', descript,'\n']))

        if self.response:
            return True
        else:
            return False

    def mmi28(self,descript):
        logger.info(''.join(['\n', descript,'\n']))

        if self.response == api.AVRCP_RESPONSE.CHANGED.value:
            return True
        else:
            return False

    def mmi32(self, descript):
        logger.info(f'\n{descript}\n')

        if self.uidcounter:
            return True
        else:
            return False

    def mmi34(self, descript):
        logger.info(f'\n{descript}\n')

        if self.response == api.AVRCP_RESPONSE.CHANGED.value:
            return True
        else:
            return False

    def mmi39(self,descript):
        logger.info(''.join(['\n', descript,'\n']))
        return True

    def mmi40(self, descript):
        logger.info(f'\n{descript}\n')

        if self.volume == True:
            return True
        else:
            return False

    def mmi79(self,descript):
        logger.info(''.join(['\n', descript,'\n']))
        return True

    def mmi81(self, descript):
        logger.info(f'\n{descript}\n')
        return True

    def mmi82(self,descript):
        logger.info(''.join(['\n', descript,'\n']))
        return True

    def mmi650(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_OPID.SELECT.value,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value])

        if self.CommandRW(EVENT=[api.Layer_ID.AVRCP,
                                 api.AVRCP_Event_ID.PASSTHROUGH_REQ,
                                 pressed]):

            released = b''.join([self.id,
                                 api.AVRCP_OPID.SELECT.value,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value])

            if self.CommandRW(EVENT=[api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_REQ,
                                     released]):
                return True
            else:
                return False

        else:
            return False

    def mmi651(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_OPID.SELECT.value,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value])

        if self.CommandRW(EVENT=[api.Layer_ID.AVRCP,
                                 api.AVRCP_Event_ID.PASSTHROUGH_REQ,
                                 pressed]):

            released = b''.join([self.id,
                                 api.AVRCP_OPID.SELECT.value,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value])

            if self.CommandRW(EVENT=[api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_REQ,
                                     released]):
                return True
            else:
                return False

        else:
            return False

    def mmi652(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_OPID.UP.value,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value])

        if self.CommandRW(EVENT=[api.Layer_ID.AVRCP,
                                 api.AVRCP_Event_ID.PASSTHROUGH_REQ,
                                 pressed]):

            released = b''.join([self.id,
                                 api.AVRCP_OPID.UP.value,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value])

            if self.CommandRW(EVENT=[api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_REQ,
                                     released]):
                return True
            else:
                return False

        else:
            return False

    def mmi653(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_OPID.DOWN.value,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value])

        if self.CommandRW(EVENT=[api.Layer_ID.AVRCP,
                                 api.AVRCP_Event_ID.PASSTHROUGH_REQ,
                                 pressed]):

            released = b''.join([self.id,
                                 api.AVRCP_OPID.DOWN.value,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value])

            if self.CommandRW(EVENT=[api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_REQ,
                                     released]):
                return True
            else:
                return False

        else:
            return False

    def mmi654(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_OPID.LEFT.value,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value])

        if self.CommandRW(EVENT=[api.Layer_ID.AVRCP,
                                 api.AVRCP_Event_ID.PASSTHROUGH_REQ,
                                 pressed]):

            released = b''.join([self.id,
                                 api.AVRCP_OPID.LEFT.value,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value])

            if self.CommandRW(EVENT=[api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_REQ,
                                     released]):
                return True
            else:
                return False

        else:
            return False

    def mmi655(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_OPID.RIGHT.value,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value])

        if self.CommandRW(EVENT=[api.Layer_ID.AVRCP,
                                 api.AVRCP_Event_ID.PASSTHROUGH_REQ,
                                 pressed]):

            released = b''.join([self.id,
                                 api.AVRCP_OPID.RIGHT.value,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value])

            if self.CommandRW(EVENT=[api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_REQ,
                                     released]):
                return True
            else:
                return False

        else:
            return False

    def mmi656(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_OPID.RIGHT_UP.value,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value])

        if self.CommandRW(EVENT=[api.Layer_ID.AVRCP,
                                 api.AVRCP_Event_ID.PASSTHROUGH_REQ,
                                 pressed]):

            released = b''.join([self.id,
                                 api.AVRCP_OPID.RIGHT_UP.value,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value])

            if self.CommandRW(EVENT=[api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_REQ,
                                     released]):
                return True
            else:
                return False

        else:
            return False

    def mmi657(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_OPID.RIGHT_DOWN.value,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value])

        if self.CommandRW(EVENT=[api.Layer_ID.AVRCP,
                                 api.AVRCP_Event_ID.PASSTHROUGH_REQ,
                                 pressed]):

            released = b''.join([self.id,
                                 api.AVRCP_OPID.RIGHT_DOWN.value,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value])

            if self.CommandRW(EVENT=[api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_REQ,
                                     released]):
                return True
            else:
                return False

        else:
            return False

    def mmi658(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_OPID.LEFT_UP.value,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value])

        if self.CommandRW(EVENT=[api.Layer_ID.AVRCP,
                                 api.AVRCP_Event_ID.PASSTHROUGH_REQ,
                                 pressed]):

            released = b''.join([self.id,
                                 api.AVRCP_OPID.LEFT_UP.value,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value])

            if self.CommandRW(EVENT=[api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_REQ,
                                     released]):
                return True
            else:
                return False

        else:
            return False

    def mmi659(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_OPID.LEFT_DOWN.value,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value])

        if self.CommandRW(EVENT=[api.Layer_ID.AVRCP,
                                 api.AVRCP_Event_ID.PASSTHROUGH_REQ,
                                 pressed]):

            released = b''.join([self.id,
                                 api.AVRCP_OPID.LEFT_DOWN.value,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value])

            if self.CommandRW(EVENT=[api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_REQ,
                                     released]):
                return True
            else:
                return False

        else:
            return False

    def mmi660(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_OPID.ROOT_MENU.value,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value])

        if self.CommandRW(EVENT=[api.Layer_ID.AVRCP,
                                 api.AVRCP_Event_ID.PASSTHROUGH_REQ,
                                 pressed]):

            released = b''.join([self.id,
                                 api.AVRCP_OPID.ROOT_MENU.value,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value])

            if self.CommandRW(EVENT=[api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_REQ,
                                     released]):
                return True
            else:
                return False

        else:
            return False

    def mmi661(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_OPID.SETUP_MENU.value,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value])

        if self.CommandRW(EVENT=[api.Layer_ID.AVRCP,
                                 api.AVRCP_Event_ID.PASSTHROUGH_REQ,
                                 pressed]):

            released = b''.join([self.id,
                                 api.AVRCP_OPID.SETUP_MENU.value,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value])

            if self.CommandRW(EVENT=[api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_REQ,
                                     released]):
                return True
            else:
                return False

        else:
            return False

    def mmi662(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_OPID.CONTENTS_MENU.value,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value])

        if self.CommandRW(EVENT=[api.Layer_ID.AVRCP,
                                 api.AVRCP_Event_ID.PASSTHROUGH_REQ,
                                 pressed]):

            released = b''.join([self.id,
                                 api.AVRCP_OPID.CONTENTS_MENU.value,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value])

            if self.CommandRW(EVENT=[api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_REQ,
                                     released]):
                return True
            else:
                return False

        else:
            return False

    def mmi663(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_OPID.FAVORITE_MENU.value,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value])

        if self.CommandRW(EVENT=[api.Layer_ID.AVRCP,
                                 api.AVRCP_Event_ID.PASSTHROUGH_REQ,
                                 pressed]):

            released = b''.join([self.id,
                                 api.AVRCP_OPID.FAVORITE_MENU.value,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value])

            if self.CommandRW(EVENT=[api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_REQ,
                                     released]):
                return True
            else:
                return False

        else:
            return False

    def mmi664(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_OPID.EXIT.value,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value])

        if self.CommandRW(EVENT=[api.Layer_ID.AVRCP,
                                 api.AVRCP_Event_ID.PASSTHROUGH_REQ,
                                 pressed]):

            released = b''.join([self.id,
                                 api.AVRCP_OPID.EXIT.value,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value])

            if self.CommandRW(EVENT=[api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_REQ,
                                     released]):
                return True
            else:
                return False

        else:
            return False

    def mmi665(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_OPID.B0.value,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value])

        if self.CommandRW(EVENT=[api.Layer_ID.AVRCP,
                                 api.AVRCP_Event_ID.PASSTHROUGH_REQ,
                                 pressed]):

            released = b''.join([self.id,
                                 api.AVRCP_OPID.B0.value,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value])

            if self.CommandRW(EVENT=[api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_REQ,
                                     released]):
                return True
            else:
                return False

        else:
            return False

    def mmi666(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_OPID.B1.value,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value])

        if self.CommandRW(EVENT=[api.Layer_ID.AVRCP,
                                 api.AVRCP_Event_ID.PASSTHROUGH_REQ,
                                 pressed]):

            released = b''.join([self.id,
                                 api.AVRCP_OPID.B1.value,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value])

            if self.CommandRW(EVENT=[api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_REQ,
                                     released]):
                return True
            else:
                return False

        else:
            return False

    def mmi667(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_OPID.B2.value,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value])

        if self.CommandRW(EVENT=[api.Layer_ID.AVRCP,
                                 api.AVRCP_Event_ID.PASSTHROUGH_REQ,
                                 pressed]):

            released = b''.join([self.id,
                                 api.AVRCP_OPID.B2.value,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value])

            if self.CommandRW(EVENT=[api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_REQ,
                                     released]):
                return True
            else:
                return False

        else:
            return False

    def mmi668(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_OPID.B3.value,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value])

        if self.CommandRW(EVENT=[api.Layer_ID.AVRCP,
                                 api.AVRCP_Event_ID.PASSTHROUGH_REQ,
                                 pressed]):

            released = b''.join([self.id,
                                 api.AVRCP_OPID.B3.value,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value])

            if self.CommandRW(EVENT=[api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_REQ,
                                     released]):
                return True
            else:
                return False

        else:
            return False

    def mmi669(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_OPID.B4.value,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value])

        if self.CommandRW(EVENT=[api.Layer_ID.AVRCP,
                                 api.AVRCP_Event_ID.PASSTHROUGH_REQ,
                                 pressed]):

            released = b''.join([self.id,
                                 api.AVRCP_OPID.B4.value,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value])

            if self.CommandRW(EVENT=[api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_REQ,
                                     released]):
                return True
            else:
                return False

        else:
            return False

    def mmi670(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_OPID.B5.value,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value])

        if self.CommandRW(EVENT=[api.Layer_ID.AVRCP,
                                 api.AVRCP_Event_ID.PASSTHROUGH_REQ,
                                 pressed]):

            released = b''.join([self.id,
                                 api.AVRCP_OPID.B5.value,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value])

            if self.CommandRW(EVENT=[api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_REQ,
                                     released]):
                return True
            else:
                return False

        else:
            return False

    def mmi671(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_OPID.B6.value,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value])

        if self.CommandRW(EVENT=[api.Layer_ID.AVRCP,
                                 api.AVRCP_Event_ID.PASSTHROUGH_REQ,
                                 pressed]):

            released = b''.join([self.id,
                                 api.AVRCP_OPID.B6.value,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value])

            if self.CommandRW(EVENT=[api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_REQ,
                                     released]):
                return True
            else:
                return False

        else:
            return False

    def mmi672(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_OPID.B7.value,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value])

        if self.CommandRW(EVENT=[api.Layer_ID.AVRCP,
                                 api.AVRCP_Event_ID.PASSTHROUGH_REQ,
                                 pressed]):

            released = b''.join([self.id,
                                 api.AVRCP_OPID.B7.value,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value])

            if self.CommandRW(EVENT=[api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_REQ,
                                     released]):
                return True
            else:
                return False

        else:
            return False

    def mmi673(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_OPID.B8.value,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value])

        if self.CommandRW(EVENT=[api.Layer_ID.AVRCP,
                                 api.AVRCP_Event_ID.PASSTHROUGH_REQ,
                                 pressed]):

            released = b''.join([self.id,
                                 api.AVRCP_OPID.B8.value,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value])

            if self.CommandRW(EVENT=[api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_REQ,
                                     released]):
                return True
            else:
                return False

        else:
            return False

    def mmi674(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_OPID.B9.value,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value])

        if self.CommandRW(EVENT=[api.Layer_ID.AVRCP,
                                 api.AVRCP_Event_ID.PASSTHROUGH_REQ,
                                 pressed]):

            released = b''.join([self.id,
                                 api.AVRCP_OPID.B9.value,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value])

            if self.CommandRW(EVENT=[api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_REQ,
                                     released]):
                return True
            else:
                return False

        else:
            return False

    def mmi675(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_OPID.DOT.value,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value])

        if self.CommandRW(EVENT=[api.Layer_ID.AVRCP,
                                 api.AVRCP_Event_ID.PASSTHROUGH_REQ,
                                 pressed]):

            released = b''.join([self.id,
                                 api.AVRCP_OPID.DOT.value,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value])

            if self.CommandRW(EVENT=[api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_REQ,
                                     released]):
                return True
            else:
                return False

        else:
            return False

    def mmi676(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_OPID.ENTER.value,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value])

        if self.CommandRW(EVENT=[api.Layer_ID.AVRCP,
                                 api.AVRCP_Event_ID.PASSTHROUGH_REQ,
                                 pressed]):

            released = b''.join([self.id,
                                 api.AVRCP_OPID.ENTER.value,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value])

            if self.CommandRW(EVENT=[api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_REQ,
                                     released]):
                return True
            else:
                return False

        else:
            return False

    def mmi677(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_OPID.CLEAR.value,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value])

        if self.CommandRW(EVENT=[api.Layer_ID.AVRCP,
                                 api.AVRCP_Event_ID.PASSTHROUGH_REQ,
                                 pressed]):

            released = b''.join([self.id,
                                 api.AVRCP_OPID.CLEAR.value,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value])

            if self.CommandRW(EVENT=[api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_REQ,
                                     released]):
                return True
            else:
                return False

        else:
            return False

    def mmi678(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_OPID.CHANNEL_UP.value,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value])

        if self.CommandRW(EVENT=[api.Layer_ID.AVRCP,
                                 api.AVRCP_Event_ID.PASSTHROUGH_REQ,
                                 pressed]):

            released = b''.join([self.id,
                                 api.AVRCP_OPID.CHANNEL_UP.value,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value])

            if self.CommandRW(EVENT=[api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_REQ,
                                     released]):
                return True
            else:
                return False

        else:
            return False

    def mmi679(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_OPID.CHANNEL_DOWN.value,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value])

        if self.CommandRW(EVENT=[api.Layer_ID.AVRCP,
                                 api.AVRCP_Event_ID.PASSTHROUGH_REQ,
                                 pressed]):

            released = b''.join([self.id,
                                 api.AVRCP_OPID.CHANNEL_DOWN.value,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value])

            if self.CommandRW(EVENT=[api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_REQ,
                                     released]):
                return True
            else:
                return False

        else:
            return False

    def mmi680(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_OPID.PREVIOUS_CHANNEL.value,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value])

        if self.CommandRW(EVENT=[api.Layer_ID.AVRCP,
                                 api.AVRCP_Event_ID.PASSTHROUGH_REQ,
                                 pressed]):

            released = b''.join([self.id,
                                 api.AVRCP_OPID.PREVIOUS_CHANNEL.value,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value])

            if self.CommandRW(EVENT=[api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_REQ,
                                     released]):
                return True
            else:
                return False

        else:
            return False

    def mmi681(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_OPID.SOUND_SELECT.value,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value])

        if self.CommandRW(EVENT=[api.Layer_ID.AVRCP,
                                 api.AVRCP_Event_ID.PASSTHROUGH_REQ,
                                 pressed]):

            released = b''.join([self.id,
                                 api.AVRCP_OPID.SOUND_SELECT.value,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value])

            if self.CommandRW(EVENT=[api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_REQ,
                                     released]):
                return True
            else:
                return False

        else:
            return False

    def mmi682(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_OPID.INPUT_SELECT.value,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value])

        if self.CommandRW(EVENT=[api.Layer_ID.AVRCP,
                                 api.AVRCP_Event_ID.PASSTHROUGH_REQ,
                                 pressed]):

            released = b''.join([self.id,
                                 api.AVRCP_OPID.INPUT_SELECT.value,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value])

            if self.CommandRW(EVENT=[api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_REQ,
                                     released]):
                return True
            else:
                return False

        else:
            return False

    def mmi683(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_OPID.DISPLAY_INFORMATION.value,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value])

        if self.CommandRW(EVENT=[api.Layer_ID.AVRCP,
                                 api.AVRCP_Event_ID.PASSTHROUGH_REQ,
                                 pressed]):

            released = b''.join([self.id,
                                 api.AVRCP_OPID.DISPLAY_INFORMATION.value,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value])

            if self.CommandRW(EVENT=[api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_REQ,
                                     released]):
                return True
            else:
                return False

        else:
            return False

    def mmi684(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_OPID.HELP.value,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value])

        if self.CommandRW(EVENT=[api.Layer_ID.AVRCP,
                                 api.AVRCP_Event_ID.PASSTHROUGH_REQ,
                                 pressed]):

            released = b''.join([self.id,
                                 api.AVRCP_OPID.HELP.value,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value])

            if self.CommandRW(EVENT=[api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_REQ,
                                     released]):
                return True
            else:
                return False

        else:
            return False

    def mmi685(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_OPID.PAGE_UP.value,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value])

        if self.CommandRW(EVENT=[api.Layer_ID.AVRCP,
                                 api.AVRCP_Event_ID.PASSTHROUGH_REQ,
                                 pressed]):

            released = b''.join([self.id,
                                 api.AVRCP_OPID.PAGE_UP.value,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value])

            if self.CommandRW(EVENT=[api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_REQ,
                                     released]):
                return True
            else:
                return False

        else:
            return False

    def mmi686(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_OPID.PAGE_DOWN.value,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value])

        if self.CommandRW(EVENT=[api.Layer_ID.AVRCP,
                                 api.AVRCP_Event_ID.PASSTHROUGH_REQ,
                                 pressed]):

            released = b''.join([self.id,
                                 api.AVRCP_OPID.PAGE_DOWN.value,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value])

            if self.CommandRW(EVENT=[api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_REQ,
                                     released]):
                return True
            else:
                return False

        else:
            return False

    def mmi687(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_OPID.POWER.value,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value])

        if self.CommandRW(EVENT=[api.Layer_ID.AVRCP,
                                 api.AVRCP_Event_ID.PASSTHROUGH_REQ,
                                 pressed]):

            released = b''.join([self.id,
                                 api.AVRCP_OPID.POWER.value,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value])

            if self.CommandRW(EVENT=[api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_REQ,
                                     released]):
                return True
            else:
                return False

        else:
            return False

    def mmi688(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_OPID.VOLUME_UP.value,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value])

        if self.CommandRW(EVENT=[api.Layer_ID.AVRCP,
                                 api.AVRCP_Event_ID.PASSTHROUGH_REQ,
                                 pressed]):

            released = b''.join([self.id,
                                 api.AVRCP_OPID.VOLUME_UP.value,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value])

            if self.CommandRW(EVENT=[api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_REQ,
                                     released]):
                return True
            else:
                return False

        else:
            return False

    def mmi689(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_OPID.VOLUME_DOWN.value,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value])

        if self.CommandRW(EVENT=[api.Layer_ID.AVRCP,
                                 api.AVRCP_Event_ID.PASSTHROUGH_REQ,
                                 pressed]):

            released = b''.join([self.id,
                                 api.AVRCP_OPID.VOLUME_DOWN.value,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value])

            if self.CommandRW(EVENT=[api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_REQ,
                                     released]):
                return True
            else:
                return False

        else:
            return False

    def mmi690(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_OPID.MUTE.value,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value])

        if self.CommandRW(EVENT=[api.Layer_ID.AVRCP,
                                 api.AVRCP_Event_ID.PASSTHROUGH_REQ,
                                 pressed]):

            released = b''.join([self.id,
                                 api.AVRCP_OPID.MUTE.value,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value])

            if self.CommandRW(EVENT=[api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_REQ,
                                     released]):
                return True
            else:
                return False

        else:
            return False

    def mmi691(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_OPID.PLAY.value,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value])

        if self.CommandRW(EVENT=[api.Layer_ID.AVRCP,
                                 api.AVRCP_Event_ID.PASSTHROUGH_REQ,
                                 pressed]):

            released = b''.join([self.id,
                                 api.AVRCP_OPID.PLAY.value,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value])

            if self.CommandRW(EVENT=[api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_REQ,
                                     released]):
                return True
            else:
                return False

        else:
            return False

    def mmi692(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_OPID.STOP.value,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value])

        if self.CommandRW(EVENT=[api.Layer_ID.AVRCP,
                                 api.AVRCP_Event_ID.PASSTHROUGH_REQ,
                                 pressed]):

            released = b''.join([self.id,
                                 api.AVRCP_OPID.STOP.value,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value])

            if self.CommandRW(EVENT=[api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_REQ,
                                     released]):
                return True
            else:
                return False

        else:
            return False

    def mmi693(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_OPID.PAUSE.value,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value])

        if self.CommandRW(EVENT=[api.Layer_ID.AVRCP,
                                 api.AVRCP_Event_ID.PASSTHROUGH_REQ,
                                 pressed]):

            released = b''.join([self.id,
                                 api.AVRCP_OPID.PAUSE.value,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value])

            if self.CommandRW(EVENT=[api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_REQ,
                                     released]):
                return True
            else:
                return False

        else:
            return False

    def mmi694(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_OPID.RECORD.value,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value])

        if self.CommandRW(EVENT=[api.Layer_ID.AVRCP,
                                 api.AVRCP_Event_ID.PASSTHROUGH_REQ,
                                 pressed]):

            released = b''.join([self.id,
                                 api.AVRCP_OPID.RECORD.value,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value])

            if self.CommandRW(EVENT=[api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_REQ,
                                     released]):
                return True
            else:
                return False

        else:
            return False

    def mmi695(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_OPID.REWIND.value,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value])

        if self.CommandRW(EVENT=[api.Layer_ID.AVRCP,
                                 api.AVRCP_Event_ID.PASSTHROUGH_REQ,
                                 pressed]):

            released = b''.join([self.id,
                                 api.AVRCP_OPID.REWIND.value,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value])

            if self.CommandRW(EVENT=[api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_REQ,
                                     released]):
                return True
            else:
                return False

        else:
            return False

    def mmi696(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_OPID.FAST_FORWARD.value,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value])

        if self.CommandRW(EVENT=[api.Layer_ID.AVRCP,
                                 api.AVRCP_Event_ID.PASSTHROUGH_REQ,
                                 pressed]):

            released = b''.join([self.id,
                                 api.AVRCP_OPID.FAST_FORWARD.value,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value])

            if self.CommandRW(EVENT=[api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_REQ,
                                     released]):
                return True
            else:
                return False

        else:
            return False

    def mmi697(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_OPID.EJECT.value,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value])

        if self.CommandRW(EVENT=[api.Layer_ID.AVRCP,
                                 api.AVRCP_Event_ID.PASSTHROUGH_REQ,
                                 pressed]):

            released = b''.join([self.id,
                                 api.AVRCP_OPID.EJECT.value,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value])

            if self.CommandRW(EVENT=[api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_REQ,
                                     released]):
                return True
            else:
                return False

        else:
            return False

    def mmi698(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_OPID.FORWARD.value,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value])

        if self.CommandRW(EVENT=[api.Layer_ID.AVRCP,
                                 api.AVRCP_Event_ID.PASSTHROUGH_REQ,
                                 pressed]):

            released = b''.join([self.id,
                                 api.AVRCP_OPID.FORWARD.value,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value])

            if self.CommandRW(EVENT=[api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_REQ,
                                     released]):
                return True
            else:
                return False

        else:
            return False

    def mmi699(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_OPID.BACKWARD.value,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value])

        if self.CommandRW(EVENT=[api.Layer_ID.AVRCP,
                                 api.AVRCP_Event_ID.PASSTHROUGH_REQ,
                                 pressed]):

            released = b''.join([self.id,
                                 api.AVRCP_OPID.BACKWARD.value,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value])

            if self.CommandRW(EVENT=[api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_REQ,
                                     released]):
                return True
            else:
                return False

        else:
            return False

    def mmi700(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_OPID.ANGLE.value,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value])

        if self.CommandRW(EVENT=[api.Layer_ID.AVRCP,
                                 api.AVRCP_Event_ID.PASSTHROUGH_REQ,
                                 pressed]):

            released = b''.join([self.id,
                                 api.AVRCP_OPID.ANGLE.value,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value])

            if self.CommandRW(EVENT=[api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_REQ,
                                     released]):
                return True
            else:
                return False

        else:
            return False

    def mmi701(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_OPID.SUBPICTURE.value,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value])

        if self.CommandRW(EVENT=[api.Layer_ID.AVRCP,
                                 api.AVRCP_Event_ID.PASSTHROUGH_REQ,
                                 pressed]):

            released = b''.join([self.id,
                                 api.AVRCP_OPID.SUBPICTURE.value,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value])

            if self.CommandRW(EVENT=[api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_REQ,
                                     released]):
                return True
            else:
                return False

        else:
            return False

    def mmi702(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_OPID.F1.value,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value])

        if self.CommandRW(EVENT=[api.Layer_ID.AVRCP,
                                 api.AVRCP_Event_ID.PASSTHROUGH_REQ,
                                 pressed]):

            released = b''.join([self.id,
                                 api.AVRCP_OPID.F1.value,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value])

            if self.CommandRW(EVENT=[api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_REQ,
                                     released]):
                return True
            else:
                return False

        else:
            return False

    def mmi703(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_OPID.F2.value,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value])

        if self.CommandRW(EVENT=[api.Layer_ID.AVRCP,
                                 api.AVRCP_Event_ID.PASSTHROUGH_REQ,
                                 pressed]):

            released = b''.join([self.id,
                                 api.AVRCP_OPID.F2.value,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value])

            if self.CommandRW(EVENT=[api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_REQ,
                                     released]):
                return True
            else:
                return False

        else:
            return False

    def mmi704(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_OPID.F3.value,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value])

        if self.CommandRW(EVENT=[api.Layer_ID.AVRCP,
                                 api.AVRCP_Event_ID.PASSTHROUGH_REQ,
                                 pressed]):

            released = b''.join([self.id,
                                 api.AVRCP_OPID.F3.value,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value])

            if self.CommandRW(EVENT=[api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_REQ,
                                     released]):
                return True
            else:
                return False

        else:
            return False

    def mmi705(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_OPID.F4.value,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value])

        if self.CommandRW(EVENT=[api.Layer_ID.AVRCP,
                                 api.AVRCP_Event_ID.PASSTHROUGH_REQ,
                                 pressed]):

            released = b''.join([self.id,
                                 api.AVRCP_OPID.F4.value,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value])

            if self.CommandRW(EVENT=[api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_REQ,
                                     released]):
                return True
            else:
                return False

        else:
            return False

    def mmi706(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_OPID.F5.value,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value])

        if self.CommandRW(EVENT=[api.Layer_ID.AVRCP,
                                 api.AVRCP_Event_ID.PASSTHROUGH_REQ,
                                 pressed]):

            released = b''.join([self.id,
                                 api.AVRCP_OPID.F5.value,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value])

            if self.CommandRW(EVENT=[api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_REQ,
                                     released]):
                return True
            else:
                return False

        else:
            return False

    def mmi707(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_OPID.VENDOR_UNIQUE.value,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value])

        if self.CommandRW(EVENT=[api.Layer_ID.AVRCP,
                                 api.AVRCP_Event_ID.PASSTHROUGH_REQ,
                                 pressed]):

            released = b''.join([self.id,
                                 api.AVRCP_OPID.VENDOR_UNIQUE.value,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value])

            if self.CommandRW(EVENT=[api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_REQ,
                                     released]):
                return True
            else:
                return False

        else:
            return False

    def mmi725(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.SELECT.value])

        count = 0

        while count != 2:
            if not self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                             api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                             pressed],
                                   EVENT  = [api.Layer_ID.AVRCP,
                                             api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                             self.id]):
                return False

            count += 1

        released = b''.join([self.id,
                             api.AVRCP_BUTTON_STATUS.RELEASED.value,
                             api.AVRCP_OPID.SELECT.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     released],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):
            return
        else:
            return False

    def mmi726(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.UP.value])

        count = 0

        while count != 2:
            if not self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                             api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                             pressed],
                                  EVENT   = [api.Layer_ID.AVRCP,
                                             api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                             self.id]):
                return False

            count += 1

        released = b''.join([self.id,
                             api.AVRCP_BUTTON_STATUS.RELEASED.value,
                             api.AVRCP_OPID.UP.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     released],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):
            return
        else:
            return False

    def mmi727(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.DOWN.value])

        count = 0

        while count != 2:
            if not self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                             api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                             pressed],
                                  EVENT   = [api.Layer_ID.AVRCP,
                                             api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                             self.id]):
                return False

            count += 1

        released = b''.join([self.id,
                             api.AVRCP_BUTTON_STATUS.RELEASED.value,
                             api.AVRCP_OPID.DOWN.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     released],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):
            return
        else:
            return False

    def mmi728(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.LEFT.value])

        count = 0

        while count != 2:
            if not self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                             api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                             pressed],
                                  EVENT   = [api.Layer_ID.AVRCP,
                                             api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                             self.id]):
                return False

            count += 1

        released = b''.join([self.id,
                             api.AVRCP_BUTTON_STATUS.RELEASED.value,
                             api.AVRCP_OPID.LEFT.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     released],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):
            return
        else:
            return False

    def mmi729(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.RIGHT.value])

        count = 0

        while count != 2:
            if not self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                             api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                             pressed],
                                  EVENT   = [api.Layer_ID.AVRCP,
                                             api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                             self.id]):
                return False

            count += 1

        released = b''.join([self.id,
                             api.AVRCP_BUTTON_STATUS.RELEASED.value,
                             api.AVRCP_OPID.RIGHT.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     released],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):
            return
        else:
            return False

    def mmi730(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.RIGHT_UP.value])

        count = 0

        while count != 2:
            if not self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                             api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                             pressed],
                                  EVENT   = [api.Layer_ID.AVRCP,
                                             api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                             self.id]):
                return False

            count += 1

        released = b''.join([self.id,
                             api.AVRCP_BUTTON_STATUS.RELEASED.value,
                             api.AVRCP_OPID.RIGHT_UP.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     released],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):
            return
        else:
            return False

    def mmi731(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.RIGHT_DOWN.value])

        count = 0

        while count != 2:
            if not self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                             api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                             pressed],
                                  EVENT   = [api.Layer_ID.AVRCP,
                                             api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                             self.id]):
                return False

            count += 1

        released = b''.join([self.id,
                             api.AVRCP_BUTTON_STATUS.RELEASED.value,
                             api.AVRCP_OPID.RIGHT_DOWN.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     released],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):
            return
        else:
            return False

    def mmi732(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.LEFT_UP.value])

        count = 0

        while count != 2:
            if not self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                             api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                             pressed],
                                  EVENT   = [api.Layer_ID.AVRCP,
                                             api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                             self.id]):
                return False

            count += 1

        released = b''.join([self.id,
                             api.AVRCP_BUTTON_STATUS.RELEASED.value,
                             api.AVRCP_OPID.LEFT_UP.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     released],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):
            return
        else:
            return False

    def mmi733(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.LEFT_DOWN.value])

        count = 0

        while count != 2:
            if not self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                             api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                             pressed],
                                  EVENT   = [api.Layer_ID.AVRCP,
                                             api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                             self.id]):
                return False

            count += 1

        released = b''.join([self.id,
                             api.AVRCP_BUTTON_STATUS.RELEASED.value,
                             api.AVRCP_OPID.LEFT_DOWN.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     released],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):
            return
        else:
            return False

    def mmi734(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.ROOT_MENU.value])

        count = 0

        while count != 2:
            if not self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                             api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                             pressed],
                                  EVENT   = [api.Layer_ID.AVRCP,
                                             api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                             self.id]):
                return False

            count += 1

        released = b''.join([self.id,
                             api.AVRCP_BUTTON_STATUS.RELEASED.value,
                             api.AVRCP_OPID.ROOT_MENU.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     released],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):
            return
        else:
            return False

    def mmi735(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.SETUP_MENU.value])

        count = 0

        while count != 2:
            if not self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                             api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                             pressed],
                                  EVENT   = [api.Layer_ID.AVRCP,
                                             api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                             self.id]):
                return False

            count += 1

        released = b''.join([self.id,
                             api.AVRCP_BUTTON_STATUS.RELEASED.value,
                             api.AVRCP_OPID.SETUP_MENU.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     released],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):
            return
        else:
            return False

    def mmi736(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.CONTENTS_MENU.value])

        count = 0

        while count != 2:
            if not self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                             api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                             pressed],
                                  EVENT   = [api.Layer_ID.AVRCP,
                                             api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                             self.id]):
                return False

            count += 1

        released = b''.join([self.id,
                             api.AVRCP_BUTTON_STATUS.RELEASED.value,
                             api.AVRCP_OPID.CONTENTS_MENU.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     released],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):
            return
        else:
            return False

    def mmi737(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.FAVORITE_MENU.value])

        count = 0

        while count != 2:
            if not self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                             api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                             pressed],
                                  EVENT   = [api.Layer_ID.AVRCP,
                                             api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                             self.id]):
                return False

            count += 1

        released = b''.join([self.id,
                             api.AVRCP_BUTTON_STATUS.RELEASED.value,
                             api.AVRCP_OPID.FAVORITE_MENU.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     released],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):
            return
        else:
            return False

    def mmi738(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.EXIT.value])

        count = 0

        while count != 2:
            if not self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                             api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                             pressed],
                                  EVENT   = [api.Layer_ID.AVRCP,
                                             api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                             self.id]):
                return False

            count += 1

        released = b''.join([self.id,
                             api.AVRCP_BUTTON_STATUS.RELEASED.value,
                             api.AVRCP_OPID.EXIT.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     released],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):
            return
        else:
            return False

    def mmi739(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.B0.value])

        count = 0

        while count != 2:
            if not self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                             api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                             pressed],
                                  EVENT   = [api.Layer_ID.AVRCP,
                                             api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                             self.id]):
                return False

            count += 1

        released = b''.join([self.id,
                             api.AVRCP_BUTTON_STATUS.RELEASED.value,
                             api.AVRCP_OPID.B0.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     released],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):
            return
        else:
            return False

    def mmi740(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.B1.value])

        count = 0

        while count != 2:
            if not self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                             api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                             pressed],
                                  EVENT   = [api.Layer_ID.AVRCP,
                                             api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                             self.id]):
                return False

            count += 1

        released = b''.join([self.id,
                             api.AVRCP_BUTTON_STATUS.RELEASED.value,
                             api.AVRCP_OPID.B1.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     released],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):
            return
        else:
            return False

    def mmi741(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.B2.value])

        count = 0

        while count != 2:
            if not self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                             api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                             pressed],
                                  EVENT   = [api.Layer_ID.AVRCP,
                                             api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                             self.id]):
                return False

            count += 1

        released = b''.join([self.id,
                             api.AVRCP_BUTTON_STATUS.RELEASED.value,
                             api.AVRCP_OPID.B2.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     released],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):
            return
        else:
            return False

    def mmi742(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.B3.value])

        count = 0

        while count != 2:
            if not self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                             api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                             pressed],
                                  EVENT   = [api.Layer_ID.AVRCP,
                                             api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                             self.id]):
                return False

            count += 1

        released = b''.join([self.id,
                             api.AVRCP_BUTTON_STATUS.RELEASED.value,
                             api.AVRCP_OPID.B3.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     released],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):
            return
        else:
            return False

    def mmi743(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.B4.value])

        count = 0

        while count != 2:
            if not self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                             api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                             pressed],
                                  EVENT   = [api.Layer_ID.AVRCP,
                                             api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                             self.id]):
                return False

            count += 1

        released = b''.join([self.id,
                             api.AVRCP_BUTTON_STATUS.RELEASED.value,
                             api.AVRCP_OPID.B4.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     released],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):
            return
        else:
            return False

    def mmi744(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.B5.value])

        count = 0

        while count != 2:
            if not self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                             api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                             pressed],
                                  EVENT   = [api.Layer_ID.AVRCP,
                                             api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                             self.id]):
                return False

            count += 1

        released = b''.join([self.id,
                             api.AVRCP_BUTTON_STATUS.RELEASED.value,
                             api.AVRCP_OPID.B5.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     released],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):
            return
        else:
            return False

    def mmi745(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.B6.value])

        count = 0

        while count != 2:
            if not self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                             api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                             pressed],
                                  EVENT   = [api.Layer_ID.AVRCP,
                                             api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                             self.id]):
                return False

            count += 1

        released = b''.join([self.id,
                             api.AVRCP_BUTTON_STATUS.RELEASED.value,
                             api.AVRCP_OPID.B6.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     released],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):
            return
        else:
            return False

    def mmi746(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.B7.value])

        count = 0

        while count != 2:
            if not self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                             api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                             pressed],
                                  EVENT   = [api.Layer_ID.AVRCP,
                                             api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                             self.id]):
                return False

            count += 1

        released = b''.join([self.id,
                             api.AVRCP_BUTTON_STATUS.RELEASED.value,
                             api.AVRCP_OPID.B7.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     released],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):
            return
        else:
            return False

    def mmi747(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.B8.value])

        count = 0

        while count != 2:
            if not self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                             api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                             pressed],
                                  EVENT   = [api.Layer_ID.AVRCP,
                                             api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                             self.id]):
                return False

            count += 1

        released = b''.join([self.id,
                             api.AVRCP_BUTTON_STATUS.RELEASED.value,
                             api.AVRCP_OPID.B8.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     released],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):
            return
        else:
            return False

    def mmi748(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.B9.value])

        count = 0

        while count != 2:
            if not self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                             api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                             pressed],
                                  EVENT   = [api.Layer_ID.AVRCP,
                                             api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                             self.id]):
                return False

            count += 1

        released = b''.join([self.id,
                             api.AVRCP_BUTTON_STATUS.RELEASED.value,
                             api.AVRCP_OPID.B9.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     released],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):
            return
        else:
            return False

    def mmi749(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.DOT.value])

        count = 0

        while count != 2:
            if not self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                             api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                             pressed],
                                  EVENT   = [api.Layer_ID.AVRCP,
                                             api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                             self.id]):
                return False

            count += 1

        released = b''.join([self.id,
                             api.AVRCP_BUTTON_STATUS.RELEASED.value,
                             api.AVRCP_OPID.DOT.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     released],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):
            return
        else:
            return False

    def mmi750(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.ENTER.value])

        count = 0

        while count != 2:
            if not self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                             api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                             pressed],
                                  EVENT   = [api.Layer_ID.AVRCP,
                                             api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                             self.id]):
                return False

            count += 1

        released = b''.join([self.id,
                             api.AVRCP_BUTTON_STATUS.RELEASED.value,
                             api.AVRCP_OPID.ENTER.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     released],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):
            return
        else:
            return False

    def mmi751(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.CLEAR.value])

        count = 0

        while count != 2:
            if not self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                             api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                             pressed],
                                  EVENT   = [api.Layer_ID.AVRCP,
                                             api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                             self.id]):
                return False

            count += 1

        released = b''.join([self.id,
                             api.AVRCP_BUTTON_STATUS.RELEASED.value,
                             api.AVRCP_OPID.CLEAR.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     released],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):
            return
        else:
            return False

    def mmi752(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.CHANNEL_UP.value])

        count = 0

        while count != 2:
            if not self.CommandRW(COMMAND=[api.Layer_ID.AVRCP,
                                           api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                           pressed],
                                  EVENT=[api.Layer_ID.AVRCP,
                                         api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                         self.id]):
                return False

            count += 1

        released = b''.join([self.id,
                             api.AVRCP_BUTTON_STATUS.RELEASED.value,
                             api.AVRCP_OPID.CHANNEL_UP.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     released],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):
            return
        else:
            return False

    def mmi753(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.CHANNEL_DOWN.value])

        count = 0

        while count != 2:
            if not self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                             api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                             pressed],
                                  EVENT   = [api.Layer_ID.AVRCP,
                                             api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                             self.id]):
                return False

            count += 1

        released = b''.join([self.id,
                             api.AVRCP_BUTTON_STATUS.RELEASED.value,
                             api.AVRCP_OPID.CHANNEL_DOWN.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     released],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):
            return
        else:
            return False

    def mmi754(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.PREVIOUS_CHANNEL.value])

        count = 0

        while count != 2:
            if not self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                             api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                             pressed],
                                  EVENT   = [api.Layer_ID.AVRCP,
                                             api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                             self.id]):
                return False

            count += 1

        released = b''.join([self.id,
                             api.AVRCP_BUTTON_STATUS.RELEASED.value,
                             api.AVRCP_OPID.PREVIOUS_CHANNEL.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     released],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):
            return
        else:
            return False

    def mmi755(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.SOUND_SELECT.value])

        count = 0

        while count != 2:
            if not self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                             api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                             pressed],
                                  EVENT   = [api.Layer_ID.AVRCP,
                                             api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                             self.id]):
                return False

            count += 1

        released = b''.join([self.id,
                             api.AVRCP_BUTTON_STATUS.RELEASED.value,
                             api.AVRCP_OPID.SOUND_SELECT.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     released],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):
            return
        else:
            return False

    def mmi756(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.INPUT_SELECT.value])

        count = 0

        while count != 2:
            if not self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                             api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                             pressed],
                                  EVENT   = [api.Layer_ID.AVRCP,
                                             api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                             self.id]):
                return False

            count += 1

        released = b''.join([self.id,
                             api.AVRCP_BUTTON_STATUS.RELEASED.value,
                             api.AVRCP_OPID.INPUT_SELECT.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     released],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):
            return
        else:
            return False

    def mmi757(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.DISPLAY_INFORMATION.value])

        count = 0

        while count != 2:
            if not self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                             api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                             pressed],
                                  EVENT   = [api.Layer_ID.AVRCP,
                                             api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                             self.id]):
                return False

            count += 1

        released = b''.join([self.id,
                             api.AVRCP_BUTTON_STATUS.RELEASED.value,
                             api.AVRCP_OPID.DISPLAY_INFORMATION.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     released],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):
            return
        else:
            return False

    def mmi758(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.HELP.value])

        count = 0

        while count != 2:
            if not self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                             api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                             pressed],
                                  EVENT   = [api.Layer_ID.AVRCP,
                                             api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                             self.id]):
                return False

            count += 1

        released = b''.join([self.id,
                             api.AVRCP_BUTTON_STATUS.RELEASED.value,
                             api.AVRCP_OPID.HELP.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     released],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):
            return
        else:
            return False

    def mmi759(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.PAGE_UP.value])

        count = 0

        while count != 2:
            if not self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                             api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                             pressed],
                                  EVENT   = [api.Layer_ID.AVRCP,
                                             api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                             self.id]):
                return False

            count += 1

        released = b''.join([self.id,
                             api.AVRCP_BUTTON_STATUS.RELEASED.value,
                             api.AVRCP_OPID.PAGE_UP.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     released],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):
            return
        else:
            return False

    def mmi760(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.PAGE_DOWN.value])

        count = 0

        while count != 2:
            if not self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                             api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                             pressed],
                                  EVENT   = [api.Layer_ID.AVRCP,
                                             api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                             self.id]):
                return False

            count += 1

        released = b''.join([self.id,
                             api.AVRCP_BUTTON_STATUS.RELEASED.value,
                             api.AVRCP_OPID.PAGE_DOWN.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     released],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):
            return
        else:
            return False

    def mmi761(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.POWER.value])

        count = 0

        while count != 2:
            if not self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                             api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                             pressed],
                                  EVENT   = [api.Layer_ID.AVRCP,
                                             api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                             self.id]):
                return False

            count += 1

        released = b''.join([self.id,
                             api.AVRCP_BUTTON_STATUS.RELEASED.value,
                             api.AVRCP_OPID.POWER.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     released],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):
            return
        else:
            return False

    def mmi762(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.VOLUME_UP.value])

        count = 0

        while count != 2:
            if not self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                             api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                             pressed],
                                  EVENT   = [api.Layer_ID.AVRCP,
                                             api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                             self.id]):
                return False

            count += 1

        released = b''.join([self.id,
                             api.AVRCP_BUTTON_STATUS.RELEASED.value,
                             api.AVRCP_OPID.VOLUME_UP.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     released],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):
            return
        else:
            return False

    def mmi763(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.VOLUME_DOWN.value])

        count = 0

        while count != 2:
            if not self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                             api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                             pressed],
                                  EVENT   = [api.Layer_ID.AVRCP,
                                             api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                             self.id]):
                return False

            count += 1

        released = b''.join([self.id,
                             api.AVRCP_BUTTON_STATUS.RELEASED.value,
                             api.AVRCP_OPID.VOLUME_DOWN.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     released],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):
            return
        else:
            return False

    def mmi764(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.MUTE.value])

        count = 0

        while count != 2:
            if not self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                             api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                             pressed],
                                  EVENT   = [api.Layer_ID.AVRCP,
                                             api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                             self.id]):
                return False

            count += 1

        released = b''.join([self.id,
                             api.AVRCP_BUTTON_STATUS.RELEASED.value,
                             api.AVRCP_OPID.MUTE.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     released],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):
            return
        else:
            return False

    def mmi765(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.PLAY.value])

        count = 0

        while count != 2:
            if not self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                             api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                             pressed],
                                  EVENT   = [api.Layer_ID.AVRCP,
                                             api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                             self.id]):
                return False

            count += 1

        released = b''.join([self.id,
                             api.AVRCP_BUTTON_STATUS.RELEASED.value,
                             api.AVRCP_OPID.PLAY.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     released],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):
            return
        else:
            return False

    def mmi766(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.STOP.value])

        count = 0

        while count != 2:
            if not self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                             api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                             pressed],
                                  EVENT   = [api.Layer_ID.AVRCP,
                                             api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                             self.id]):
                return False

            count += 1

        released = b''.join([self.id,
                             api.AVRCP_BUTTON_STATUS.RELEASED.value,
                             api.AVRCP_OPID.STOP.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     released],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):
            return
        else:
            return False

    def mmi767(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.PAUSE.value])

        count = 0

        while count != 2:
            if not self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                             api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                             pressed],
                                  EVENT   = [api.Layer_ID.AVRCP,
                                             api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                             self.id]):
                return False

            count += 1

        released = b''.join([self.id,
                             api.AVRCP_BUTTON_STATUS.RELEASED.value,
                             api.AVRCP_OPID.PAUSE.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     released],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):
            return
        else:
            return False

    def mmi768(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.RECORD.value])

        count = 0

        while count != 2:
            if not self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                             api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                             pressed],
                                  EVENT   = [api.Layer_ID.AVRCP,
                                             api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                             self.id]):
                return False

            count += 1

        released = b''.join([self.id,
                             api.AVRCP_BUTTON_STATUS.RELEASED.value,
                             api.AVRCP_OPID.RECORD.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     released],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):
            return
        else:
            return False

    def mmi769(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.REWIND.value])

        count = 0

        while count != 2:
            if not self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                             api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                             pressed],
                                  EVENT   = [api.Layer_ID.AVRCP,
                                             api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                             self.id]):
                return False

            count += 1

        released = b''.join([self.id,
                             api.AVRCP_BUTTON_STATUS.RELEASED.value,
                             api.AVRCP_OPID.REWIND.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     released],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):
            return
        else:
            return False

    def mmi770(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.FAST_FORWARD.value])

        count = 0

        while count != 2:
            if not self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                             api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                             pressed],
                                  EVENT   = [api.Layer_ID.AVRCP,
                                             api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                             self.id]):
                return False

            count += 1

        released = b''.join([self.id,
                             api.AVRCP_BUTTON_STATUS.RELEASED.value,
                             api.AVRCP_OPID.FAST_FORWARD.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     released],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):
            return
        else:
            return False

    def mmi771(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.EJECT.value])

        count = 0

        while count != 2:
            if not self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                             api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                             pressed],
                                  EVENT   = [api.Layer_ID.AVRCP,
                                             api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                             self.id]):
                return False

            count += 1

        released = b''.join([self.id,
                             api.AVRCP_BUTTON_STATUS.RELEASED.value,
                             api.AVRCP_OPID.EJECT.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     released],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):
            return
        else:
            return False

    def mmi772(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.FORWARD.value])

        count = 0

        while count != 2:
            if not self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                             api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                             pressed],
                                  EVENT   = [api.Layer_ID.AVRCP,
                                             api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                             self.id]):
                return False

            count += 1

        released = b''.join([self.id,
                             api.AVRCP_BUTTON_STATUS.RELEASED.value,
                             api.AVRCP_OPID.FORWARD.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     released],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):
            return
        else:
            return False

    def mmi773(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.BACKWARD.value])

        count = 0

        while count != 2:
            if not self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                             api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                             pressed],
                                  EVENT   = [api.Layer_ID.AVRCP,
                                             api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                             self.id]):
                return False

            count += 1

        released = b''.join([self.id,
                             api.AVRCP_BUTTON_STATUS.RELEASED.value,
                             api.AVRCP_OPID.BACKWARD.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     released],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):
            return
        else:
            return False

    def mmi774(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.ANGLE.value])

        count = 0

        while count != 2:
            if not self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                             api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                             pressed],
                                  EVENT   = [api.Layer_ID.AVRCP,
                                             api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                             self.id]):
                return False

            count += 1

        released = b''.join([self.id,
                             api.AVRCP_BUTTON_STATUS.RELEASED.value,
                             api.AVRCP_OPID.ANGLE.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     released],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):
            return
        else:
            return False

    def mmi775(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.SUBPICTURE.value])

        count = 0

        while count != 2:
            if not self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                             api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                             pressed],
                                  EVENT   = [api.Layer_ID.AVRCP,
                                             api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                             self.id]):
                return False

            count += 1

        released = b''.join([self.id,
                             api.AVRCP_BUTTON_STATUS.RELEASED.value,
                             api.AVRCP_OPID.SUBPICTURE.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     released],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):
            return
        else:
            return False

    def mmi776(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.F1.value])

        count = 0

        while count != 2:
            if not self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                             api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                             pressed],
                                  EVENT   = [api.Layer_ID.AVRCP,
                                             api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                             self.id]):
                return False

            count += 1

        released = b''.join([self.id,
                             api.AVRCP_BUTTON_STATUS.RELEASED.value,
                             api.AVRCP_OPID.F1.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     released],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):
            return
        else:
            return False

    def mmi777(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.F2.value])

        count = 0

        while count != 2:
            if not self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                             api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                             pressed],
                                  EVENT   = [api.Layer_ID.AVRCP,
                                             api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                             self.id]):
                return False

            count += 1

        released = b''.join([self.id,
                             api.AVRCP_BUTTON_STATUS.RELEASED.value,
                             api.AVRCP_OPID.F2.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     released],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):
            return
        else:
            return False

    def mmi778(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.F3.value])

        count = 0

        while count != 2:
            if not self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                             api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                             pressed],
                                  EVENT   = [api.Layer_ID.AVRCP,
                                             api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                             self.id]):
                return False

            count += 1

        released = b''.join([self.id,
                             api.AVRCP_BUTTON_STATUS.RELEASED.value,
                             api.AVRCP_OPID.F3.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     released],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):
            return
        else:
            return False

    def mmi779(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.F4.value])

        count = 0

        while count != 2:
            if not self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                             api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                             pressed],
                                  EVENT   = [api.Layer_ID.AVRCP,
                                             api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                             self.id]):
                return False

            count += 1

        released = b''.join([self.id,
                             api.AVRCP_BUTTON_STATUS.RELEASED.value,
                             api.AVRCP_OPID.F4.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     released],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):
            return
        else:
            return False

    def mmi780(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.F5.value])

        count = 0

        while count != 2:
            if not self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                             api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                             pressed],
                                  EVENT   = [api.Layer_ID.AVRCP,
                                             api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                             self.id]):
                return False

            count += 1

        released = b''.join([self.id,
                             api.AVRCP_BUTTON_STATUS.RELEASED.value,
                             api.AVRCP_OPID.F5.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     released],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):
            return
        else:
            return False

    def mmi781(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.VENDOR_UNIQUE.value])

        count = 0

        while count != 2:
            if not self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                             api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                             pressed],
                                  EVENT   = [api.Layer_ID.AVRCP,
                                             api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                             self.id]):
                return False

            count += 1

        released = b''.join([self.id,
                             api.AVRCP_BUTTON_STATUS.RELEASED.value,
                             api.AVRCP_OPID.VENDOR_UNIQUE.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     released],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):
            return
        else:
            return False

    def mmi800(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.SELECT.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     pressed],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):

            released = b''.join([self.id,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value,
                                 api.AVRCP_OPID.SELECT.value])

            if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                         api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                         released],
                              EVENT   = [api.Layer_ID.AVRCP,
                                         api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                         self.id]):
                return
            else:
                return False

        else:
            return False

    def mmi801(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.UP.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     pressed],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):

            released = b''.join([self.id,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value,
                                 api.AVRCP_OPID.UP.value])

            if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                         api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                         released],
                              EVENT   = [api.Layer_ID.AVRCP,
                                         api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                         self.id]):
                return
            else:
                return False

        else:
            return False

    def mmi802(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.DOWN.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     pressed],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):

            released = b''.join([self.id,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value,
                                 api.AVRCP_OPID.DOWN.value])

            if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                         api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                         released],
                              EVENT   = [api.Layer_ID.AVRCP,
                                         api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                         self.id]):
                return
            else:
                return False

        else:
            return False

    def mmi803(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.LEFT.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     pressed],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):

            released = b''.join([self.id,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value,
                                 api.AVRCP_OPID.LEFT.value])

            if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                         api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                         released],
                              EVENT   = [api.Layer_ID.AVRCP,
                                         api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                         self.id]):
                return
            else:
                return False

        else:
            return False

    def mmi804(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.RIGHT.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     pressed],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):

            released = b''.join([self.id,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value,
                                 api.AVRCP_OPID.RIGHT.value])

            if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                         api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                         released],
                              EVENT   = [api.Layer_ID.AVRCP,
                                         api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                         self.id]):
                return
            else:
                return False

        else:
            return False

    def mmi805(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.RIGHT_UP.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     pressed],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):

            released = b''.join([self.id,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value,
                                 api.AVRCP_OPID.RIGHT_UP.value])

            if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                         api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                         released],
                              EVENT   = [api.Layer_ID.AVRCP,
                                         api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                         self.id]):
                return
            else:
                return False

        else:
            return False

    def mmi806(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.RIGHT_DOWN.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     pressed],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):

            released = b''.join([self.id,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value,
                                 api.AVRCP_OPID.RIGHT_DOWN.value])

            if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                         api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                         released],
                              EVENT   = [api.Layer_ID.AVRCP,
                                         api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                         self.id]):
                return
            else:
                return False

        else:
            return False

    def mmi807(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.LEFT_UP.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     pressed],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):

            released = b''.join([self.id,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value,
                                 api.AVRCP_OPID.LEFT_UP.value])

            if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                         api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                         released],
                              EVENT   = [api.Layer_ID.AVRCP,
                                         api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                         self.id]):
                return
            else:
                return False

        else:
            return False

    def mmi808(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.LEFT_DOWN.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     pressed],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):

            released = b''.join([self.id,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value,
                                 api.AVRCP_OPID.LEFT_DOWN.value])

            if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                         api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                         released],
                              EVENT   = [api.Layer_ID.AVRCP,
                                         api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                         self.id]):
                return
            else:
                return False

        else:
            return False

    def mmi809(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.ROOT_MENU.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     pressed],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):

            released = b''.join([self.id,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value,
                                 api.AVRCP_OPID.ROOT_MENU.value])

            if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                         api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                         released],
                              EVENT   = [api.Layer_ID.AVRCP,
                                         api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                         self.id]):
                return
            else:
                return False

        else:
            return False

    def mmi810(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.SETUP_MENU.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     pressed],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):

            released = b''.join([self.id,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value,
                                 api.AVRCP_OPID.SETUP_MENU.value])

            if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                         api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                         released],
                              EVENT   = [api.Layer_ID.AVRCP,
                                         api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                         self.id]):
                return
            else:
                return False

        else:
            return False

    def mmi811(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.CONTENTS_MENU.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     pressed],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):

            released = b''.join([self.id,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value,
                                 api.AVRCP_OPID.CONTENTS_MENU.value])

            if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                         api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                         released],
                              EVENT   = [api.Layer_ID.AVRCP,
                                         api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                         self.id]):
                return
            else:
                return False

        else:
            return False

    def mmi812(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.FAVORITE_MENU.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     pressed],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):

            released = b''.join([self.id,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value,
                                 api.AVRCP_OPID.FAVORITE_MENU.value])

            if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                         api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                         released],
                              EVENT   = [api.Layer_ID.AVRCP,
                                         api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                         self.id]):
                return
            else:
                return False

        else:
            return False

    def mmi813(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.EXIT.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     pressed],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):

            released = b''.join([self.id,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value,
                                 api.AVRCP_OPID.EXIT.value])

            if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                         api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                         released],
                              EVENT   = [api.Layer_ID.AVRCP,
                                         api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                         self.id]):
                return
            else:
                return False

        else:
            return False

    def mmi814(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.B0.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     pressed],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):

            released = b''.join([self.id,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value,
                                 api.AVRCP_OPID.B0.value])

            if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                         api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                         released],
                              EVENT   = [api.Layer_ID.AVRCP,
                                         api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                         self.id]):
                return
            else:
                return False

        else:
            return False

    def mmi815(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.B1.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     pressed],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):

            released = b''.join([self.id,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value,
                                 api.AVRCP_OPID.B1.value])

            if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                         api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                         released],
                              EVENT   = [api.Layer_ID.AVRCP,
                                         api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                         self.id]):
                return
            else:
                return False

        else:
            return False

    def mmi816(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.B2.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     pressed],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):

            released = b''.join([self.id,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value,
                                 api.AVRCP_OPID.B2.value])

            if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                         api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                         released],
                              EVENT   = [api.Layer_ID.AVRCP,
                                         api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                         self.id]):
                return
            else:
                return False

        else:
            return False

    def mmi817(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.B3.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     pressed],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):

            released = b''.join([self.id,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value,
                                 api.AVRCP_OPID.B3.value])

            if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                         api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                         released],
                              EVENT   = [api.Layer_ID.AVRCP,
                                         api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                         self.id]):
                return
            else:
                return False

        else:
            return False

    def mmi818(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.B4.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     pressed],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):

            released = b''.join([self.id,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value,
                                 api.AVRCP_OPID.B4.value])

            if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                         api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                         released],
                              EVENT   = [api.Layer_ID.AVRCP,
                                         api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                         self.id]):
                return
            else:
                return False

        else:
            return False

    def mmi819(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.B5.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     pressed],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):

            released = b''.join([self.id,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value,
                                 api.AVRCP_OPID.B5.value])

            if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                         api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                         released],
                              EVENT   = [api.Layer_ID.AVRCP,
                                         api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                         self.id]):
                return
            else:
                return False

        else:
            return False

    def mmi820(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.B6.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     pressed],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):

            released = b''.join([self.id,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value,
                                 api.AVRCP_OPID.B6.value])

            if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                         api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                         released],
                              EVENT   = [api.Layer_ID.AVRCP,
                                         api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                         self.id]):
                return
            else:
                return False

        else:
            return False

    def mmi821(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.B7.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     pressed],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):

            released = b''.join([self.id,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value,
                                 api.AVRCP_OPID.B7.value])

            if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                         api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                         released],
                              EVENT   = [api.Layer_ID.AVRCP,
                                         api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                         self.id]):
                return
            else:
                return False

        else:
            return False

    def mmi822(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.B8.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     pressed],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):

            released = b''.join([self.id,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value,
                                 api.AVRCP_OPID.B8.value])

            if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                         api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                         released],
                              EVENT   = [api.Layer_ID.AVRCP,
                                         api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                         self.id]):
                return
            else:
                return False

        else:
            return False

    def mmi823(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.B9.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     pressed],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):

            released = b''.join([self.id,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value,
                                 api.AVRCP_OPID.B9.value])

            if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                         api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                         released],
                              EVENT   = [api.Layer_ID.AVRCP,
                                         api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                         self.id]):
                return
            else:
                return False

        else:
            return False

    def mmi824(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.DOT.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     pressed],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):

            released = b''.join([self.id,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value,
                                 api.AVRCP_OPID.DOT.value])

            if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                         api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                         released],
                              EVENT   = [api.Layer_ID.AVRCP,
                                         api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                         self.id]):
                return
            else:
                return False

        else:
            return False

    def mmi825(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.ENTER.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     pressed],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):

            released = b''.join([self.id,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value,
                                 api.AVRCP_OPID.ENTER.value])

            if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                         api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                         released],
                              EVENT   = [api.Layer_ID.AVRCP,
                                         api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                         self.id]):
                return
            else:
                return False

        else:
            return False

    def mmi826(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.CLEAR.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     pressed],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):

            released = b''.join([self.id,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value,
                                 api.AVRCP_OPID.CLEAR.value])

            if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                         api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                         released],
                              EVENT   = [api.Layer_ID.AVRCP,
                                         api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                         self.id]):
                return
            else:
                return False

        else:
            return False

    def mmi827(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.CHANNEL_UP.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     pressed],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):

            released = b''.join([self.id,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value,
                                 api.AVRCP_OPID.CHANNEL_UP.value])

            if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                         api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                         released],
                              EVENT   = [api.Layer_ID.AVRCP,
                                         api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                         self.id]):
                return
            else:
                return False

        else:
            return False

    def mmi828(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.CHANNEL_DOWN.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     pressed],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):

            released = b''.join([self.id,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value,
                                 api.AVRCP_OPID.CHANNEL_DOWN.value])

            if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                         api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                         released],
                              EVENT   = [api.Layer_ID.AVRCP,
                                         api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                         self.id]):
                return
            else:
                return False

        else:
            return False

    def mmi829(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.PREVIOUS_CHANNEL.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     pressed],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):

            released = b''.join([self.id,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value,
                                 api.AVRCP_OPID.PREVIOUS_CHANNEL.value])

            if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                         api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                         released],
                              EVENT   = [api.Layer_ID.AVRCP,
                                         api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                         self.id]):
                return
            else:
                return False

        else:
            return False

    def mmi830(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.SOUND_SELECT.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     pressed],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):

            released = b''.join([self.id,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value,
                                 api.AVRCP_OPID.SOUND_SELECT.value])

            if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                         api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                         released],
                              EVENT   = [api.Layer_ID.AVRCP,
                                         api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                         self.id]):
                return
            else:
                return False

        else:
            return False

    def mmi831(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.INPUT_SELECT.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     pressed],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):

            released = b''.join([self.id,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value,
                                 api.AVRCP_OPID.INPUT_SELECT.value])

            if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                         api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                         released],
                              EVENT   = [api.Layer_ID.AVRCP,
                                         api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                         self.id]):
                return
            else:
                return False

        else:
            return False

    def mmi832(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.DISPLAY_INFORMATION.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     pressed],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):

            released = b''.join([self.id,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value,
                                 api.AVRCP_OPID.DISPLAY_INFORMATION.value])

            if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                         api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                         released],
                              EVENT   = [api.Layer_ID.AVRCP,
                                         api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                         self.id]):
                return
            else:
                return False

        else:
            return False

    def mmi833(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.HELP.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     pressed],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):

            released = b''.join([self.id,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value,
                                 api.AVRCP_OPID.HELP.value])

            if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                         api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                         released],
                              EVENT   = [api.Layer_ID.AVRCP,
                                         api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                         self.id]):
                return
            else:
                return False

        else:
            return False

    def mmi834(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.PAGE_UP.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     pressed],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):

            released = b''.join([self.id,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value,
                                 api.AVRCP_OPID.PAGE_UP.value])

            if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                         api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                         released],
                              EVENT   = [api.Layer_ID.AVRCP,
                                         api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                         self.id]):
                return
            else:
                return False

        else:
            return False

    def mmi835(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.PAGE_DOWN.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     pressed],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):

            released = b''.join([self.id,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value,
                                 api.AVRCP_OPID.PAGE_DOWN.value])

            if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                         api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                         released],
                              EVENT   = [api.Layer_ID.AVRCP,
                                         api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                         self.id]):
                return
            else:
                return False

        else:
            return False

    def mmi836(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.POWER.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     pressed],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):

            released = b''.join([self.id,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value,
                                 api.AVRCP_OPID.POWER.value])

            if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                         api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                         released],
                              EVENT   = [api.Layer_ID.AVRCP,
                                         api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                         self.id]):
                return
            else:
                return False

        else:
            return False

    def mmi837(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.VOLUME_UP.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     pressed],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):

            released = b''.join([self.id,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value,
                                 api.AVRCP_OPID.VOLUME_UP.value])

            if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                         api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                         released],
                              EVENT   = [api.Layer_ID.AVRCP,
                                         api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                         self.id]):
                return
            else:
                return False

        else:
            return False

    def mmi838(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.VOLUME_DOWN.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     pressed],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):

            released = b''.join([self.id,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value,
                                 api.AVRCP_OPID.VOLUME_DOWN.value])

            if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                         api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                         released],
                              EVENT   = [api.Layer_ID.AVRCP,
                                         api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                         self.id]):
                return
            else:
                return False

        else:
            return False

    def mmi839(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.MUTE.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     pressed],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):

            released = b''.join([self.id,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value,
                                 api.AVRCP_OPID.MUTE.value])

            if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                         api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                         released],
                              EVENT   = [api.Layer_ID.AVRCP,
                                         api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                         self.id]):
                return
            else:
                return False

        else:
            return False

    def mmi840(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.PLAY.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     pressed],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):

            released = b''.join([self.id,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value,
                                 api.AVRCP_OPID.PLAY.value])

            if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                         api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                         released],
                              EVENT   = [api.Layer_ID.AVRCP,
                                         api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                         self.id]):
                return
            else:
                return False

        else:
            return False

    def mmi841(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.STOP.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     pressed],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):

            released = b''.join([self.id,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value,
                                 api.AVRCP_OPID.STOP.value])

            if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                         api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                         released],
                              EVENT   = [api.Layer_ID.AVRCP,
                                         api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                         self.id]):
                return
            else:
                return False

        else:
            return False

    def mmi842(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.PAUSE.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     pressed],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):

            released = b''.join([self.id,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value,
                                 api.AVRCP_OPID.PAUSE.value])

            if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                         api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                         released],
                              EVENT   = [api.Layer_ID.AVRCP,
                                         api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                         self.id]):
                return
            else:
                return False

        else:
            return False

    def mmi843(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.RECORD.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     pressed],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):

            released = b''.join([self.id,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value,
                                 api.AVRCP_OPID.RECORD.value])

            if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                         api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                         released],
                              EVENT   = [api.Layer_ID.AVRCP,
                                         api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                         self.id]):
                return
            else:
                return False

        else:
            return False

    def mmi844(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.REWIND.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     pressed],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):

            released = b''.join([self.id,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value,
                                 api.AVRCP_OPID.REWIND.value])

            if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                         api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                         released],
                              EVENT   = [api.Layer_ID.AVRCP,
                                         api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                         self.id]):
                return
            else:
                return False

        else:
            return False

    def mmi845(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.FAST_FORWARD.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     pressed],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):

            released = b''.join([self.id,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value,
                                 api.AVRCP_OPID.FAST_FORWARD.value])

            if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                         api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                         released],
                              EVENT   = [api.Layer_ID.AVRCP,
                                         api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                         self.id]):
                return
            else:
                return False

        else:
            return False

    def mmi846(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.EJECT.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     pressed],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):

            released = b''.join([self.id,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value,
                                 api.AVRCP_OPID.EJECT.value])

            if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                         api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                         released],
                              EVENT   = [api.Layer_ID.AVRCP,
                                         api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                         self.id]):
                return
            else:
                return False

        else:
            return False

    def mmi847(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.FORWARD.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     pressed],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):

            released = b''.join([self.id,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value,
                                 api.AVRCP_OPID.FORWARD.value])

            if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                         api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                         released],
                              EVENT   = [api.Layer_ID.AVRCP,
                                         api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                         self.id]):
                return
            else:
                return False

        else:
            return False

    def mmi848(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.BACKWARD.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     pressed],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):

            released = b''.join([self.id,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value,
                                 api.AVRCP_OPID.BACKWARD.value])

            if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                         api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                         released],
                              EVENT   = [api.Layer_ID.AVRCP,
                                         api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                         self.id]):
                return
            else:
                return False

        else:
            return False

    def mmi849(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.ANGLE.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     pressed],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):

            released = b''.join([self.id,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value,
                                 api.AVRCP_OPID.ANGLE.value])

            if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                         api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                         released],
                              EVENT   = [api.Layer_ID.AVRCP,
                                         api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                         self.id]):
                return
            else:
                return False

        else:
            return False

    def mmi850(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.SUBPICTURE.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     pressed],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):

            released = b''.join([self.id,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value,
                                 api.AVRCP_OPID.SUBPICTURE.value])

            if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                         api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                         released],
                              EVENT   = [api.Layer_ID.AVRCP,
                                         api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                         self.id]):
                return
            else:
                return False

        else:
            return False

    def mmi851(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.F1.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     pressed],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):

            released = b''.join([self.id,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value,
                                 api.AVRCP_OPID.F1.value])

            if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                         api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                         released],
                              EVENT   = [api.Layer_ID.AVRCP,
                                         api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                         self.id]):
                return
            else:
                return False

        else:
            return False

    def mmi852(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.F2.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     pressed],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):

            released = b''.join([self.id,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value,
                                 api.AVRCP_OPID.F2.value])

            if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                         api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                         released],
                              EVENT   = [api.Layer_ID.AVRCP,
                                         api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                         self.id]):
                return
            else:
                return False

        else:
            return False

    def mmi853(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.F3.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     pressed],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):

            released = b''.join([self.id,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value,
                                 api.AVRCP_OPID.F3.value])

            if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                         api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                         released],
                              EVENT   = [api.Layer_ID.AVRCP,
                                         api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                         self.id]):
                return
            else:
                return False

        else:
            return False

    def mmi854(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.F4.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     pressed],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):

            released = b''.join([self.id,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value,
                                 api.AVRCP_OPID.F4.value])

            if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                         api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                         released],
                              EVENT   = [api.Layer_ID.AVRCP,
                                         api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                         self.id]):
                return
            else:
                return False

        else:
            return False

    def mmi855(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.F5.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     pressed],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):

            released = b''.join([self.id,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value,
                                 api.AVRCP_OPID.F5.value])

            if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                         api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                         released],
                              EVENT   = [api.Layer_ID.AVRCP,
                                         api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                         self.id]):
                return
            else:
                return False

        else:
            return False

    def mmi856(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.VENDOR_UNIQUE.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     pressed],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):

            released = b''.join([self.id,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value,
                                 api.AVRCP_OPID.VENDOR_UNIQUE.value])

            if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                         api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                         released],
                              EVENT   = [api.Layer_ID.AVRCP,
                                         api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                         self.id]):
                return
            else:
                return False

        else:
            return False

    def mmi875(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.SELECT.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     pressed],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):

            released = b''.join([self.id,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value,
                                 api.AVRCP_OPID.SELECT.value])

            if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                         api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                         released],
                              EVENT   = [api.Layer_ID.AVRCP,
                                         api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                         self.id]):
                return
            else:
                return False

        else:
            return False

    def mmi876(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.UP.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     pressed],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):

            released = b''.join([self.id,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value,
                                 api.AVRCP_OPID.UP.value])

            if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                         api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                         released],
                              EVENT   = [api.Layer_ID.AVRCP,
                                         api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                         self.id]):
                return
            else:
                return False

        else:
            return False

    def mmi877(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.DOWN.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     pressed],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):

            released = b''.join([self.id,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value,
                                 api.AVRCP_OPID.DOWN.value])

            if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                         api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                         released],
                              EVENT   = [api.Layer_ID.AVRCP,
                                         api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                         self.id]):
                return
            else:
                return False

        else:
            return False

    def mmi878(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.LEFT.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     pressed],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):

            released = b''.join([self.id,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value,
                                 api.AVRCP_OPID.LEFT.value])

            if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                         api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                         released],
                              EVENT   = [api.Layer_ID.AVRCP,
                                         api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                         self.id]):
                return
            else:
                return False

        else:
            return False

    def mmi879(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.RIGHT.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     pressed],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):

            released = b''.join([self.id,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value,
                                 api.AVRCP_OPID.RIGHT.value])

            if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                         api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                         released],
                              EVENT   = [api.Layer_ID.AVRCP,
                                         api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                         self.id]):
                return
            else:
                return False

        else:
            return False

    def mmi880(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.RIGHT_UP.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     pressed],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):

            released = b''.join([self.id,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value,
                                 api.AVRCP_OPID.RIGHT_UP.value])

            if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                         api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                         released],
                              EVENT   = [api.Layer_ID.AVRCP,
                                         api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                         self.id]):
                return
            else:
                return False

        else:
            return False

    def mmi881(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.RIGHT_DOWN.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     pressed],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):

            released = b''.join([self.id,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value,
                                 api.AVRCP_OPID.RIGHT_DOWN.value])

            if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                         api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                         released],
                              EVENT   = [api.Layer_ID.AVRCP,
                                         api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                         self.id]):
                return
            else:
                return False

        else:
            return False

    def mmi882(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.LEFT_UP.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     pressed],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):

            released = b''.join([self.id,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value,
                                 api.AVRCP_OPID.LEFT_UP.value])

            if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                         api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                         released],
                              EVENT   = [api.Layer_ID.AVRCP,
                                         api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                         self.id]):
                return
            else:
                return False

        else:
            return False

    def mmi883(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.LEFT_DOWN.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     pressed],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):

            released = b''.join([self.id,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value,
                                 api.AVRCP_OPID.LEFT_DOWN.value])

            if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                         api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                         released],
                              EVENT   = [api.Layer_ID.AVRCP,
                                         api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                         self.id]):
                return
            else:
                return False

        else:
            return False

    def mmi884(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.ROOT_MENU.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     pressed],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):

            released = b''.join([self.id,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value,
                                 api.AVRCP_OPID.ROOT_MENU.value])

            if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                         api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                         released],
                              EVENT   = [api.Layer_ID.AVRCP,
                                         api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                         self.id]):
                return
            else:
                return False

        else:
            return False

    def mmi885(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.SETUP_MENU.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     pressed],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):

            released = b''.join([self.id,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value,
                                 api.AVRCP_OPID.SETUP_MENU.value])

            if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                         api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                         released],
                              EVENT   = [api.Layer_ID.AVRCP,
                                         api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                         self.id]):
                return
            else:
                return False

        else:
            return False

    def mmi886(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.CONTENTS_MENU.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     pressed],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):

            released = b''.join([self.id,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value,
                                 api.AVRCP_OPID.CONTENTS_MENU.value])

            if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                         api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                         released],
                              EVENT   = [api.Layer_ID.AVRCP,
                                         api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                         self.id]):
                return
            else:
                return False

        else:
            return False

    def mmi887(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.FAVORITE_MENU.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     pressed],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):

            released = b''.join([self.id,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value,
                                 api.AVRCP_OPID.FAVORITE_MENU.value])

            if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                         api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                         released],
                              EVENT   = [api.Layer_ID.AVRCP,
                                         api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                         self.id]):
                return
            else:
                return False

        else:
            return False

    def mmi888(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.EXIT.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     pressed],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):

            released = b''.join([self.id,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value,
                                 api.AVRCP_OPID.EXIT.value])

            if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                         api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                         released],
                              EVENT   = [api.Layer_ID.AVRCP,
                                         api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                         self.id]):
                return
            else:
                return False

        else:
            return False

    def mmi889(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.B0.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     pressed],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):

            released = b''.join([self.id,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value,
                                 api.AVRCP_OPID.B0.value])

            if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                         api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                         released],
                              EVENT   = [api.Layer_ID.AVRCP,
                                         api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                         self.id]):
                return
            else:
                return False

        else:
            return False

    def mmi890(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.B1.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     pressed],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):

            released = b''.join([self.id,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value,
                                 api.AVRCP_OPID.B1.value])

            if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                         api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                         released],
                              EVENT   = [api.Layer_ID.AVRCP,
                                         api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                         self.id]):
                return
            else:
                return False

        else:
            return False

    def mmi891(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.B2.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     pressed],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):

            released = b''.join([self.id,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value,
                                 api.AVRCP_OPID.B2.value])

            if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                         api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                         released],
                              EVENT   = [api.Layer_ID.AVRCP,
                                         api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                         self.id]):
                return
            else:
                return False

        else:
            return False

    def mmi892(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.B3.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     pressed],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):

            released = b''.join([self.id,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value,
                                 api.AVRCP_OPID.B3.value])

            if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                         api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                         released],
                              EVENT   = [api.Layer_ID.AVRCP,
                                         api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                         self.id]):
                return
            else:
                return False

        else:
            return False

    def mmi893(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.B4.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     pressed],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):

            released = b''.join([self.id,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value,
                                 api.AVRCP_OPID.B4.value])

            if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                         api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                         released],
                              EVENT   = [api.Layer_ID.AVRCP,
                                         api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                         self.id]):
                return
            else:
                return False

        else:
            return False

    def mmi894(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.B5.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     pressed],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):

            released = b''.join([self.id,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value,
                                 api.AVRCP_OPID.B5.value])

            if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                         api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                         released],
                              EVENT   = [api.Layer_ID.AVRCP,
                                         api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                         self.id]):
                return
            else:
                return False

        else:
            return False

    def mmi895(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.B6.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     pressed],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):

            released = b''.join([self.id,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value,
                                 api.AVRCP_OPID.B6.value])

            if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                         api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                         released],
                              EVENT   = [api.Layer_ID.AVRCP,
                                         api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                         self.id]):
                return
            else:
                return False

        else:
            return False

    def mmi896(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.B7.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     pressed],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):

            released = b''.join([self.id,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value,
                                 api.AVRCP_OPID.B7.value])

            if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                         api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                         released],
                              EVENT   = [api.Layer_ID.AVRCP,
                                         api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                         self.id]):
                return
            else:
                return False

        else:
            return False

    def mmi897(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.B8.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     pressed],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):

            released = b''.join([self.id,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value,
                                 api.AVRCP_OPID.B8.value])

            if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                         api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                         released],
                              EVENT   = [api.Layer_ID.AVRCP,
                                         api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                         self.id]):
                return
            else:
                return False

        else:
            return False

    def mmi898(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.B9.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     pressed],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):

            released = b''.join([self.id,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value,
                                 api.AVRCP_OPID.B9.value])

            if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                         api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                         released],
                              EVENT   = [api.Layer_ID.AVRCP,
                                         api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                         self.id]):
                return
            else:
                return False

        else:
            return False

    def mmi899(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.DOT.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     pressed],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):

            released = b''.join([self.id,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value,
                                 api.AVRCP_OPID.DOT.value])

            if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                         api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                         released],
                              EVENT   = [api.Layer_ID.AVRCP,
                                         api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                         self.id]):
                return
            else:
                return False

        else:
            return False

    def mmi900(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.ENTER.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     pressed],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):

            released = b''.join([self.id,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value,
                                 api.AVRCP_OPID.ENTER.value])

            if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                         api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                         released],
                              EVENT   = [api.Layer_ID.AVRCP,
                                         api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                         self.id]):
                return
            else:
                return False

        else:
            return False

    def mmi901(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.CLEAR.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     pressed],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):

            released = b''.join([self.id,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value,
                                 api.AVRCP_OPID.CLEAR.value])

            if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                         api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                         released],
                              EVENT   = [api.Layer_ID.AVRCP,
                                         api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                         self.id]):
                return
            else:
                return False

        else:
            return False

    def mmi902(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.CHANNEL_UP.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     pressed],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):

            released = b''.join([self.id,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value,
                                 api.AVRCP_OPID.CHANNEL_UP.value])

            if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                         api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                         released],
                              EVENT   = [api.Layer_ID.AVRCP,
                                         api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                         self.id]):
                return
            else:
                return False

        else:
            return False

    def mmi903(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.CHANNEL_DOWN.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     pressed],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):

            released = b''.join([self.id,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value,
                                 api.AVRCP_OPID.CHANNEL_DOWN.value])

            if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                         api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                         released],
                              EVENT   = [api.Layer_ID.AVRCP,
                                         api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                         self.id]):
                return
            else:
                return False

        else:
            return False

    def mmi904(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.PREVIOUS_CHANNEL.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     pressed],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):

            released = b''.join([self.id,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value,
                                 api.AVRCP_OPID.PREVIOUS_CHANNEL.value])

            if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                         api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                         released],
                              EVENT   = [api.Layer_ID.AVRCP,
                                         api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                         self.id]):
                return
            else:
                return False

        else:
            return False

    def mmi905(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.SOUND_SELECT.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     pressed],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):

            released = b''.join([self.id,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value,
                                 api.AVRCP_OPID.SOUND_SELECT.value])

            if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                         api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                         released],
                              EVENT   = [api.Layer_ID.AVRCP,
                                         api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                         self.id]):
                return
            else:
                return False

        else:
            return False

    def mmi906(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.INPUT_SELECT.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     pressed],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):

            released = b''.join([self.id,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value,
                                 api.AVRCP_OPID.INPUT_SELECT.value])

            if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                         api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                         released],
                              EVENT   = [api.Layer_ID.AVRCP,
                                         api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                         self.id]):
                return
            else:
                return False

        else:
            return False

    def mmi907(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.DISPLAY_INFORMATION.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     pressed],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):

            released = b''.join([self.id,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value,
                                 api.AVRCP_OPID.DISPLAY_INFORMATION.value])

            if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                         api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                         released],
                              EVENT   = [api.Layer_ID.AVRCP,
                                         api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                         self.id]):
                return
            else:
                return False

        else:
            return False

    def mmi908(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.HELP.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     pressed],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):

            released = b''.join([self.id,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value,
                                 api.AVRCP_OPID.HELP.value])

            if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                         api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                         released],
                              EVENT   = [api.Layer_ID.AVRCP,
                                         api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                         self.id]):
                return
            else:
                return False

        else:
            return False

    def mmi909(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.PAGE_UP.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     pressed],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):

            released = b''.join([self.id,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value,
                                 api.AVRCP_OPID.PAGE_UP.value])

            if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                         api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                         released],
                              EVENT   = [api.Layer_ID.AVRCP,
                                         api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                         self.id]):
                return
            else:
                return False

        else:
            return False

    def mmi910(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.PAGE_DOWN.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     pressed],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):

            released = b''.join([self.id,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value,
                                 api.AVRCP_OPID.PAGE_DOWN.value])

            if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                         api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                         released],
                              EVENT   = [api.Layer_ID.AVRCP,
                                         api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                         self.id]):
                return
            else:
                return False

        else:
            return False

    def mmi911(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.POWER.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     pressed],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):

            released = b''.join([self.id,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value,
                                 api.AVRCP_OPID.POWER.value])

            if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                         api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                         released],
                              EVENT   = [api.Layer_ID.AVRCP,
                                         api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                         self.id]):
                return
            else:
                return False

        else:
            return False

    def mmi912(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.VOLUME_UP.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     pressed],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):

            released = b''.join([self.id,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value,
                                 api.AVRCP_OPID.VOLUME_UP.value])

            if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                         api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                         released],
                              EVENT   = [api.Layer_ID.AVRCP,
                                         api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                         self.id]):
                return
            else:
                return False

        else:
            return False

    def mmi913(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.VOLUME_DOWN.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     pressed],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):

            released = b''.join([self.id,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value,
                                 api.AVRCP_OPID.VOLUME_DOWN.value])

            if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                         api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                         released],
                              EVENT   = [api.Layer_ID.AVRCP,
                                         api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                         self.id]):
                return
            else:
                return False

        else:
            return False

    def mmi914(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.MUTE.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     pressed],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):

            released = b''.join([self.id,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value,
                                 api.AVRCP_OPID.MUTE.value])

            if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                         api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                         released],
                              EVENT   = [api.Layer_ID.AVRCP,
                                         api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                         self.id]):
                return
            else:
                return False

        else:
            return False

    def mmi915(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.PLAY.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     pressed],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):

            released = b''.join([self.id,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value,
                                 api.AVRCP_OPID.PLAY.value])

            if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                         api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                         released],
                              EVENT   = [api.Layer_ID.AVRCP,
                                         api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                         self.id]):
                return
            else:
                return False

        else:
            return False

    def mmi916(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.STOP.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     pressed],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):

            released = b''.join([self.id,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value,
                                 api.AVRCP_OPID.STOP.value])

            if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                         api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                         released],
                              EVENT   = [api.Layer_ID.AVRCP,
                                         api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                         self.id]):
                return
            else:
                return False

        else:
            return False

    def mmi917(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.PAUSE.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     pressed],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):

            released = b''.join([self.id,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value,
                                 api.AVRCP_OPID.PAUSE.value])

            if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                         api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                         released],
                              EVENT   = [api.Layer_ID.AVRCP,
                                         api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                         self.id]):
                return
            else:
                return False

        else:
            return False

    def mmi918(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.RECORD.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     pressed],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):

            released = b''.join([self.id,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value,
                                 api.AVRCP_OPID.RECORD.value])

            if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                         api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                         released],
                              EVENT   = [api.Layer_ID.AVRCP,
                                         api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                         self.id]):
                return
            else:
                return False

        else:
            return False

    def mmi919(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.REWIND.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     pressed],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):

            released = b''.join([self.id,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value,
                                 api.AVRCP_OPID.REWIND.value])

            if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                         api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                         released],
                              EVENT   = [api.Layer_ID.AVRCP,
                                         api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                         self.id]):
                return
            else:
                return False

        else:
            return False

    def mmi920(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.FAST_FORWARD.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     pressed],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):

            released = b''.join([self.id,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value,
                                 api.AVRCP_OPID.FAST_FORWARD.value])

            if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                         api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                         released],
                              EVENT   = [api.Layer_ID.AVRCP,
                                         api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                         self.id]):
                return
            else:
                return False

        else:
            return False

    def mmi921(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.EJECT.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     pressed],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):

            released = b''.join([self.id,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value,
                                 api.AVRCP_OPID.EJECT.value])

            if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                         api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                         released],
                              EVENT   = [api.Layer_ID.AVRCP,
                                         api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                         self.id]):
                return
            else:
                return False

        else:
            return False

    def mmi922(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.FORWARD.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     pressed],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):

            released = b''.join([self.id,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value,
                                 api.AVRCP_OPID.FORWARD.value])

            if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                         api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                         released],
                              EVENT   = [api.Layer_ID.AVRCP,
                                         api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                         self.id]):
                return
            else:
                return False

        else:
            return False

    def mmi923(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.BACKWARD.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     pressed],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):

            released = b''.join([self.id,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value,
                                 api.AVRCP_OPID.BACKWARD.value])

            if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                         api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                         released],
                              EVENT   = [api.Layer_ID.AVRCP,
                                         api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                         self.id]):
                return
            else:
                return False

        else:
            return False

    def mmi924(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.ANGLE.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     pressed],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):

            released = b''.join([self.id,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value,
                                 api.AVRCP_OPID.ANGLE.value])

            if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                         api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                         released],
                              EVENT   = [api.Layer_ID.AVRCP,
                                         api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                         self.id]):
                return
            else:
                return False

        else:
            return False

    def mmi925(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.SUBPICTURE.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     pressed],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):

            released = b''.join([self.id,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value,
                                 api.AVRCP_OPID.SUBPICTURE.value])

            if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                         api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                         released],
                              EVENT   = [api.Layer_ID.AVRCP,
                                         api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                         self.id]):
                return
            else:
                return False

        else:
            return False

    def mmi926(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.F1.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     pressed],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):

            released = b''.join([self.id,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value,
                                 api.AVRCP_OPID.F1.value])

            if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                         api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                         released],
                              EVENT   = [api.Layer_ID.AVRCP,
                                         api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                         self.id]):
                return
            else:
                return False

        else:
            return False

    def mmi927(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.F2.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     pressed],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):

            released = b''.join([self.id,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value,
                                 api.AVRCP_OPID.F2.value])

            if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                         api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                         released],
                              EVENT   = [api.Layer_ID.AVRCP,
                                         api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                         self.id]):
                return
            else:
                return False

        else:
            return False

    def mmi928(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.F3.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     pressed],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):

            released = b''.join([self.id,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value,
                                 api.AVRCP_OPID.F3.value])

            if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                         api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                         released],
                              EVENT   = [api.Layer_ID.AVRCP,
                                         api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                         self.id]):
                return
            else:
                return False

        else:
            return False

    def mmi929(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.F4.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     pressed],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):

            released = b''.join([self.id,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value,
                                 api.AVRCP_OPID.F4.value])

            if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                         api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                         released],
                              EVENT   = [api.Layer_ID.AVRCP,
                                         api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                         self.id]):
                return
            else:
                return False

        else:
            return False

    def mmi930(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.F5.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     pressed],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):

            released = b''.join([self.id,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value,
                                 api.AVRCP_OPID.F5.value])

            if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                         api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                         released],
                              EVENT   = [api.Layer_ID.AVRCP,
                                         api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                         self.id]):
                return
            else:
                return False

        else:
            return False

    def mmi931(self, descript):
        logger.info(f'\n{descript}\n')

        pressed = b''.join([self.id,
                            api.AVRCP_BUTTON_STATUS.PRESSED.value,
                            api.AVRCP_OPID.VENDOR_UNIQUE.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                     pressed],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                     self.id]):

            released = b''.join([self.id,
                                 api.AVRCP_BUTTON_STATUS.RELEASED.value,
                                 api.AVRCP_OPID.VENDOR_UNIQUE.value])

            if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                         api.AVRCP_CMD_ID.PASSTHROUTH_REQ,
                                         released],
                              EVENT   = [api.Layer_ID.AVRCP,
                                         api.AVRCP_Event_ID.PASSTHROUGH_RSP,
                                         self.id]):
                return
            else:
                return False

        else:
            return False

    def mmi1002(self, descript):
        logger.info(f'\n{descript}\n')

        conninfo = self.get_connetion_info()

        if not conninfo:
            return False

        self.conninfo = conninfo

        return

    def mmi1016(self,descript):
        logger.info(''.join(['\n', descript,'\n']))

        conninfo = self.create_connection('BT')

        if not conninfo:
            return False

        self.conninfo = conninfo

        mtu         = bytes(2)
        connect_req = b''.join([self.conninfo['connhandle'],mtu])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVDTP,
                                     api.AVDTP_CMD_ID.CONNECT_REQ,
                                     connect_req],
                          EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                     api.Layer_ID.AVDTP,
                                     api.AVDTP_CMD_ID.CONNECT_REQ]):
            return
        else:
            return False

    def mmi2002(self, descript):
        logger.info(f'\n{descript}\n')
        if self.casename_b == b'AVRCP/TG/VLH/BI-01-C' or \
           self.casename_b == b'AVRCP/TG/VLH/BV-04-C' or \
           self.casename_b == b'AVRCP/TG/VLH/BV-01-I':
            if self.conninfo:
                notificationReq = self.CommandRW(EVENT =[api.Layer_ID.AVRCP,
                                                         api.AVRCP_Event_ID.REGISTER_NOTIFICATION_REQ,
                                                         self.id],
                                                 back  = True)
                if not notificationReq:
                    return False

                interval = notificationReq[4:]
                payload = b''.join([self.id,
                                    api.AVRCP_RESPONSE.CHANGED.value,
                                    len(interval).to_bytes(1, 'big'),
                                    interval])

                if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                             api.AVRCP_CMD_ID.REG_NOTIFICATION_RSP,
                                             payload],
                                  EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                             api.Layer_ID.AVRCP,
                                             api.AVRCP_CMD_ID.REG_NOTIFICATION_RSP]):
                    return
                else:
                    return False
                
        if not self.conninfo:
            conninfo = self.get_connetion_info()

            if not conninfo:
                return False

            self.conninfo = conninfo

        return

    def mmi2006(self, descript):
        logger.info(f'\n{descript}\n')

        mtu         = bytes(2)
        connect_req = b''.join([self.conninfo['connhandle'],mtu])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.CONNECT_REQ,
                                     connect_req],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.CONNECT_CFM,
                                     self.id]):
            return
        else:
            return False

    def mmi3010(self,descript):
        logger.info(''.join(['\n', descript,'\n']))
        startItem = b'\x00\x00\x00\x00'
        endItem   = b'\xFF\xFF\xFF\xFF'
        attCount  = b'\x00'
        scope     = b''.join([self.id,
                              api.AVRCP_SCOPE_MEDIA_PLAYER.VIRTUAL_FILESYSTEM.value,
                              startItem,
                              endItem,
                              attCount])

        folderItemRsp = self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                                  api.AVRCP_CMD_ID.GET_FOLDER_ITEM,
                                                  scope],
                                       EVENT   = [api.Layer_ID.AVRCP,
                                                  api.AVRCP_Event_ID.GET_FOLDER_ITEMS_RSP,
                                                  self.id],
                                       back    =  True)

        if not folderItemRsp:
            return False

        self.uidcounter = folderItemRsp[4:6]
        self.folderUid  = [num.to_bytes(4, 'big') * 2
                          for num in range(1, int.from_bytes(folderItemRsp[6:8], byteorder='big') + 1)]

        return

    def mmi3021(self,descript):
        logger.info(''.join(['\n', descript,'\n']))

        volume    = b'\x00'
        absVolume = b''.join([self.id,
                              api.AVRCP_RESPONSE.ACCEPT.value,
                              volume])

        if self.casename_b == b'AVRCP/TG/VLH/BV-02-I':
            absVolumeReq = self.CommandRW(EVENT = [api.Layer_ID.AVRCP,
                                                   api.AVRCP_Event_ID.SET_ABS_VOLUME_REQ,
                                                   self.id],
                                          back  =  True)

            if not absVolumeReq:
                return False

            if not self.volume:
                self.volume = absVolumeReq[3:]

            if self.volume:
                if self.volume != absVolumeReq[3:]:
                    self.volume = True

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.SET_ABSOLUTE_VOLUME_RSP,
                                     absVolume],
                          EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                     api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.SET_ABSOLUTE_VOLUME_RSP]):
            return
        else:
            return False

    def mmi3024(self,descript):
        logger.info(''.join(['\n', descript,'\n']))

        infoReq = self.CommandRW(EVENT = [api.Layer_ID.AVRCP,
                                          api.AVRCP_Event_ID.UNIT_SUBUNIT_INFO_REQ,
                                          self.id],
                                 back  =  True)

        if not infoReq:
            return False

        data = infoReq[4:]

        unitInfo = b''.join([self.id,
                             api.AVRCP_RESPONSE.STABLE.value,
                             api.AVRCP_UNIT_INFO_OPCODE.SUB_UNIT_INFO.value,
                             data])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.UNIT_SUBUNIT_INFO_RSP,
                                     unitInfo],
                          EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                     api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.UNIT_SUBUNIT_INFO_RSP]):
            return
        else:
            return False

    def mmi3025(self,descript):
        logger.info(''.join(['\n', descript,'\n']))

        infoReq = self.CommandRW(EVENT = [api.Layer_ID.AVRCP,
                                          api.AVRCP_Event_ID.UNIT_SUBUNIT_INFO_REQ,
                                          self.id],
                                 back  =  True)

        if not infoReq:
            return False

        data = infoReq[4:]

        unitInfo = b''.join([self.id,
                             api.AVRCP_RESPONSE.STABLE.value,
                             api.AVRCP_UNIT_INFO_OPCODE.UNIT_INFO.value,
                             data])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.UNIT_SUBUNIT_INFO_RSP,
                                     unitInfo],
                          EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                     api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.UNIT_SUBUNIT_INFO_RSP]):
            return
        else:
            return False

    def mmi3026(self,descript):
        logger.info(''.join(['\n', descript,'\n']))

        folderUid = (len(self.folderUid) + 1).to_bytes(4,'big')*2
        item      = b''.join([self.id,
                              api.AVRCP_SCOPE_MEDIA_PLAYER.NOW_PLAYING.value,
                              folderUid,
                              self.uidcounter])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.ADD_TO_NOW_PLAYING,
                                     item],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.ADD_TO_NOW_PLAYING,
                                     self.id]):
            return
        else:
            return False

    def mmi3028(self,descript):
        logger.info(''.join(['\n', descript,'\n']))

        item = b''.join([self.id,
                         api.AVRCP_SCOPE_MEDIA_PLAYER.SEARCH.value,
                         self.folderUid.pop(),
                         self.uidcounter])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.ADD_TO_NOW_PLAYING,
                                     item],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.ADD_TO_NOW_PLAYING,
                                     self.id]):
            return
        else:
            return False

    def mmi3029(self,descript):
        logger.info(''.join(['\n', descript,'\n']))

        item = b''.join([self.id,
                         api.AVRCP_SCOPE_MEDIA_PLAYER.VIRTUAL_FILESYSTEM.value,
                         self.folderUid[0],
                         self.uidcounter])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.ADD_TO_NOW_PLAYING,
                                     item],
                          EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                     api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.ADD_TO_NOW_PLAYING]):
            return
        else:
            return False

    def mmi3030(self,descript):
        logger.info(''.join(['\n', descript,'\n']))

        path = b''.join([self.id,
                         self.uidcounter,
                         api.AVRCP_DIRECTION_FOLDER.DOWN.value,
                         self.folderUid[0]])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.CHANGE_PATH,
                                     path],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.CHANGE_PATH_RSP,
                                     self.id]):
            return
        else:
            return False

    def mmi3031(self,descript):
        logger.info(''.join(['\n', descript,'\n']))

        path = b''.join([self.id,
                         self.uidcounter,
                         api.AVRCP_DIRECTION_FOLDER.DOWN.value,
                         self.folderUid[0]])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.CHANGE_PATH,
                                     path],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.CHANGE_PATH_RSP,
                                     self.id]):

            path = b''.join([self.id,
                             self.uidcounter,
                             api.AVRCP_DIRECTION_FOLDER.UP.value,
                             self.folderUid[0]])

            if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                         api.AVRCP_CMD_ID.CHANGE_PATH,
                                         path],
                              EVENT   = [api.Layer_ID.AVRCP,
                                         api.AVRCP_Event_ID.CHANGE_PATH_RSP,
                                         self.id]):
                return
            else:
                return False
        else:
            return False

    def mmi3032(self,descript):
        logger.info(''.join(['\n', descript,'\n']))

        capability = b''.join([self.id,
                               api.AVRCP_CAPABILITY_OPTION.EVENTS_SUPPORTED.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.GET_CAPABILITY,
                                     capability],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.GET_CAPABILITIES,
                                     self.id]):
            return
        else:
            return False

    def mmi3035(self,descript):
        logger.info(f'\n{descript}\n')

        attrID = b''.join([self.id,
                           len(api.AVRCP_PLAYER_APP_ATTR_ID.EQUALIZER.value).to_bytes(1,'big'),
                           api.AVRCP_PLAYER_APP_ATTR_ID.EQUALIZER.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.GET_CURRENT_VALUE,
                                     attrID],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.GET_CURR_PLAYER_APP_SET_VAL,
                                     self.id]):
            return
        else:
            return False

    def mmi3036(self,descript):
        logger.info(''.join(['\n', descript,'\n']))

        attrID  = b''.join([api.AVRCP_MEDIA_ATTR_ID.TITLE.value])
        element = b''.join([self.id,
                            api.AVRCP_ELEMENT_ID.PLAYING.value*8,
                            int(len(attrID)/4).to_bytes(1,'big'),
                            attrID])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.GET_ELEMENT_ATTRS,
                                     element],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.GET_ELEMENT_ATTR,
                                     self.id]):
            return
        else:
            return False

    def mmi3037(self,descript):
        logger.info(''.join(['\n', descript,'\n']))
        startItem= b'\x00\x00\x00\x00'
        endItem  = b'\xFF\xFF\xFF\xFF'
        attCount = b'\x00'
        scope    = b''.join([self.id,
                             api.AVRCP_SCOPE_MEDIA_PLAYER.LIST.value,
                             startItem,
                             endItem,
                             attCount])

        folderItemRsp = self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                                  api.AVRCP_CMD_ID.GET_FOLDER_ITEM,
                                                  scope],
                                       EVENT   = [api.Layer_ID.AVRCP,
                                                  api.AVRCP_Event_ID.GET_FOLDER_ITEMS_RSP,
                                                  self.id],
                                       back    =  True)

        if not folderItemRsp:
            return False

        self.uidcounter = folderItemRsp[4:6]

        return

    def mmi3038(self,descript):
        logger.info(''.join(['\n', descript,'\n']))
        startItem = b'\x00\x00\x00\x00'
        endItem   = b'\xFF\xFF\xFF\xFF'
        attCount  = b'\x00'
        scope     = b''.join([self.id,
                              api.AVRCP_SCOPE_MEDIA_PLAYER.NOW_PLAYING.value,
                              startItem,
                              endItem,
                              attCount])

        folderItemRsp = self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                                  api.AVRCP_CMD_ID.GET_FOLDER_ITEM,
                                                  scope],
                                       EVENT   = [api.Layer_ID.AVRCP,
                                                  api.AVRCP_Event_ID.GET_FOLDER_ITEMS_RSP,
                                                  self.id],
                                       back    =  True)

        if not folderItemRsp:
            return False

        if self.response == api.AVRCP_RESPONSE.INTERIM.value:
            playing = self.CommandRW(EVENT = [api.Layer_ID.AVRCP,
                                              api.AVRCP_Event_ID.NOW_PLAYING_CONTENT_CHANGED,
                                              self.id],
                                     back  =  True)

            if not playing:
                return True

            self.response = playing[3:4]

            return [None,'mmi']

        return

    def mmi3039(self,descript):
        logger.info(''.join(['\n', descript,'\n']))
        startItem = b'\x00\x00\x00\x00'
        endItem   = b'\xFF\xFF\xFF\xFF'
        attCount  = b'\x00'
        scope    = b''.join([self.id,
                             api.AVRCP_SCOPE_MEDIA_PLAYER.SEARCH.value,
                             startItem,
                             endItem,
                             attCount])

        folderItemRsp = self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                                  api.AVRCP_CMD_ID.GET_FOLDER_ITEM,
                                                  scope],
                                       EVENT   = [api.Layer_ID.AVRCP,
                                                  api.AVRCP_Event_ID.GET_FOLDER_ITEMS_RSP,
                                                  self.id],
                                       back    =  True)

        if not folderItemRsp:
            return False

        self.folderUid.append(folderItemRsp[13:21])

        return

    def mmi3040(self,descript):
        logger.info(''.join(['\n', descript,'\n']))

        startItem = b'\x00\x00\x00\x00'
        endItem   = b'\xFF\xFF\xFF\xFF'
        attCount  = b'\x00'
        scope     = b''.join([self.id,
                              api.AVRCP_SCOPE_MEDIA_PLAYER.VIRTUAL_FILESYSTEM.value,
                              startItem,
                              endItem,
                              attCount])

        folderItemRsp = self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                                  api.AVRCP_CMD_ID.GET_FOLDER_ITEM,
                                                  scope],
                                       EVENT   = [api.Layer_ID.AVRCP,
                                                  api.AVRCP_Event_ID.GET_FOLDER_ITEMS_RSP,
                                                  self.id],
                                       back    =  True)

        if not folderItemRsp:
            return False

        self.uidcounter = folderItemRsp[4:6]
        self.folderUid = [num.to_bytes(4, 'big') * 2
                          for num in range(1, int.from_bytes(folderItemRsp[6:8], byteorder='big') + 1)]

        if self.response == api.AVRCP_RESPONSE.INTERIM.value:
            uid = self.CommandRW(EVENT = [api.Layer_ID.AVRCP,
                                          api.AVRCP_Event_ID.UIDS_CHANGED,
                                          self.id],
                                 back  =  True)

            if not uid:
                return False

            self.response = uid[3:4]

            return [None,'mmi']

        return

    def mmi3042(self,descript):
        logger.info(''.join(['\n', descript,'\n']))
        startItem = b'\x00\x00\x00\x00'
        endItem   = b'\xFF\xFF\xFF\xFF'
        attCount  = b'\x00'
        scope     = b''.join([self.id,
                              api.AVRCP_SCOPE_MEDIA_PLAYER.NOW_PLAYING.value,
                              startItem,
                              endItem,
                              attCount])

        folderItemRsp = self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                                  api.AVRCP_CMD_ID.GET_FOLDER_ITEM,
                                                  scope],
                                       EVENT   = [api.Layer_ID.AVRCP,
                                                  api.AVRCP_Event_ID.GET_FOLDER_ITEMS_RSP,
                                                  self.id],
                                       back    =  True)

        if not folderItemRsp:
            return False

        folderUid = folderItemRsp[13:21]
        attCount  = b'\x00'
        item      = b''.join([self.id,
                              api.AVRCP_SCOPE_MEDIA_PLAYER.NOW_PLAYING.value,
                              folderUid,
                              self.uidcounter,
                              attCount])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.GET_ITEM_ATTRS,
                                     item],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.GET_ITEM_ATTRS_RSP,
                                     self.id]):
            return
        else:
            return False

    def mmi3043(self,descript):
        logger.info(''.join(['\n', descript,'\n']))

        attCount = b'\x00'
        item     = b''.join([self.id,
                             api.AVRCP_SCOPE_MEDIA_PLAYER.SEARCH.value,
                             self.folderUid.pop(),
                             self.uidcounter,
                             attCount])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.GET_ITEM_ATTRS,
                                     item],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.GET_ITEM_ATTRS_RSP,
                                     self.id]):
            return
        else:
            return False

    def mmi3044(self,descript):
        logger.info(''.join(['\n', descript,'\n']))

        attCount = b'\x00'
        item     = b''.join([self.id,
                             api.AVRCP_SCOPE_MEDIA_PLAYER.VIRTUAL_FILESYSTEM.value,
                             self.folderUid[0],
                             self.uidcounter,
                             attCount])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.GET_ITEM_ATTRS,
                                     item],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.GET_ITEM_ATTRS_RSP,
                                     self.id]):
            return
        else:
            return False

    def mmi3045(self,descript):
        logger.info(''.join(['\n', descript,'\n']))

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PLAY_STATUS,
                                     self.id],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.GET_PLAY_STATUS,
                                     self.id]):
            return
        else:
            return False

    def mmi3046(self,descript):
        logger.info(''.join(['\n', descript,'\n']))

        attrID   = b''.join([api.AVRCP_PLAYER_APP_ATTR_ID.EQUALIZER.value])
        attrText = b''.join([self.id,
                             len(attrID).to_bytes(1,'big'),
                             attrID])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.GET_ATTR_TEXT,
                                     attrText],
                          EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                     api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.GET_ATTR_TEXT]):
            return
        else:
            return False

    def mmi3047(self, descript):
        logger.info(f'\n{descript}\n')

        status = b''.join([api.AVRCP_EQUALIZER_STATUS.ON.value])
        value  = b''.join([self.id,
                           api.AVRCP_PLAYER_APP_ATTR_ID.EQUALIZER.value,
                           len(status).to_bytes(1,'big'),
                           status])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.GET_VALUE_TEXT,
                                     value],
                          EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                     api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.GET_VALUE_TEXT]):
            return
        else:
            return False

    def mmi3048(self,descript):
        logger.info(''.join(['\n', descript,'\n']))

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.LIST_ATTRS,
                                     self.id],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.LIST_PLAYER_APP_SET_ATTR,
                                     self.id]):
            return
        else:
            return False

    def mmi3049(self, descript):
        logger.info(f'\n{descript}\n')

        attrID = b''.join([self.id,
                           api.AVRCP_PLAYER_APP_ATTR_ID.REPEAT_MODE.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.LIST_VALUES,
                                     attrID],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.LIST_PLAYER_APP_SET_VAL,
                                     self.id]):
            return
        else:
            return False

    def mmi3050(self,descript):
        logger.info(''.join(['\n', descript,'\n']))
        logger.error('unsupport')
        return

    def mmi3051(self,descript):
        logger.info(''.join(['\n', descript,'\n']))

        if self.mmi3086(descript) == False:
            return False

        folderUid = (len(self.folderUid) + 1).to_bytes(4,'big')*2
        item      = b''.join([self.id,
                              api.AVRCP_SCOPE_MEDIA_PLAYER.VIRTUAL_FILESYSTEM.value,
                              folderUid,
                              self.uidcounter])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PLAY_ITEM,
                                     item],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PLAY_ITEM,
                                     self.id]):
            return
        else:
            return False

    def mmi3052(self,descript):
        logger.info(''.join(['\n', descript,'\n']))

        if self.mmi3086(descript) == False:
            return False

        startItem = b'\x00\x00\x00\x00'
        endItem   = b'\xFF\xFF\xFF\xFF'
        attCount  = b'\x00'
        scope     = b''.join([self.id,
                              api.AVRCP_SCOPE_MEDIA_PLAYER.NOW_PLAYING.value,
                              startItem,
                              endItem,
                              attCount])

        folderItemRsp = self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                                  api.AVRCP_CMD_ID.GET_FOLDER_ITEM,
                                                  scope],
                                       EVENT   = [api.Layer_ID.AVRCP,
                                                  api.AVRCP_Event_ID.GET_FOLDER_ITEMS_RSP,
                                                  self.id],
                                       back    =  True)

        if not folderItemRsp:
            return False

        folderUid = folderItemRsp[13:21]
        item      = b''.join([self.id,
                              api.AVRCP_SCOPE_MEDIA_PLAYER.NOW_PLAYING.value,
                              folderUid,
                              self.uidcounter])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PLAY_ITEM,
                                     item],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PLAY_ITEM,
                                     self.id]):
            return
        else:
            return False

    def mmi3053(self,descript):
        logger.info(''.join(['\n', descript,'\n']))

        item      = b''.join([self.id,
                              api.AVRCP_SCOPE_MEDIA_PLAYER.SEARCH.value,
                              self.folderUid.pop(),
                              self.uidcounter])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PLAY_ITEM,
                                     item],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PLAY_ITEM,
                                     self.id]):
            return
        else:
            return False

    def mmi3054(self,descript):
        logger.info(''.join(['\n', descript,'\n']))

        folderUid = (len(self.folderUid) + 1).to_bytes(4,'big')*2
        item      = b''.join([self.id,
                              api.AVRCP_SCOPE_MEDIA_PLAYER.VIRTUAL_FILESYSTEM.value,
                              folderUid,
                              self.uidcounter])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.PLAY_ITEM,
                                     item],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.PLAY_ITEM,
                                     self.id]):
            return
        else:
            return False

    def mmi3055(self,descript):
        logger.info(''.join(['\n', descript,'\n']))
        logger.error('unsupport')
        return

    def mmi3068(self,descript):
        logger.info(''.join(['\n', descript,'\n']))

        interval = b'\x00'
        payload  = b''.join([self.id,
                            api.AVRCP_RESPONSE.CHANGED.value,
                            len(interval).to_bytes(1, 'big'),
                            interval])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.REG_NOTIFICATION_CHANGED,
                                     payload],
                          EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                     api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.REG_NOTIFICATION_CHANGED]):
            return
        else:
            return False

    def mmi3069(self,descript):
        logger.info(''.join(['\n', descript,'\n']))

        suppID = b''.join([self.id,
                           api.AVRCP_SUPP_ID.VOLUME_CHANGED.value])

        notification = self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                                 api.AVRCP_CMD_ID.REGISTER_NOTIFICATION,
                                                 suppID],
                                      EVENT   = [api.Layer_ID.AVRCP,
                                                 api.AVRCP_Event_ID.VOLUME_CHANGED,
                                                 self.id],
                                      back    =  True)

        if not notification:
            return False

        self.response = notification[3:4]

        return

    def mmi3073(self,descript):
        logger.info(''.join(['\n', descript,'\n']))

        suppID = b''.join([self.id,
                           api.AVRCP_SUPP_ID.NOW_PLAYING_CHANGED.value])

        notification = self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                                 api.AVRCP_CMD_ID.REGISTER_NOTIFICATION,
                                                 suppID],
                                      EVENT   = [api.Layer_ID.AVRCP,
                                                 api.AVRCP_Event_ID.NOW_PLAYING_CONTENT_CHANGED,
                                                 self.id],
                                      back    =  True)

        if not notification:
            return False

        self.response = notification[3:4]

        return

    def mmi3081(self,descript):
        logger.info(''.join(['\n', descript,'\n']))

        suppID = b''.join([self.id,
                           api.AVRCP_SUPP_ID.UIDS_CHANGED.value])

        notification = self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                                 api.AVRCP_CMD_ID.REGISTER_NOTIFICATION,
                                                 suppID],
                                      EVENT   = [api.Layer_ID.AVRCP,
                                                 api.AVRCP_Event_ID.UIDS_CHANGED,
                                                 self.id],
                                      back    =  True)

        if not notification:
            return False

        self.response = notification[3:4]

        return

    def mmi3082(self,descript):
        logger.info(''.join(['\n', descript,'\n']))

        suppID = b''.join([self.id,
                           api.AVRCP_SUPP_ID.VOLUME_CHANGED.value])

        notification = self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                                 api.AVRCP_CMD_ID.REGISTER_NOTIFICATION,
                                                 suppID],
                                      EVENT   = [api.Layer_ID.AVRCP,
                                                 api.AVRCP_Event_ID.VOLUME_CHANGED,
                                                 self.id],
                                      back    =  True)

        if not notification:
            return False

        self.response = notification[3:4]

        return

    def mmi3083(self,descript):
        logger.info(''.join(['\n', descript,'\n']))

        search = b''.join([self.id,
                           len(self.ixit[b'TSPX_search_string'][1]).to_bytes(2,'big'),
                           self.ixit[b'TSPX_search_string'][1]])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.SEARCH,
                                     search],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.SEARCH_RSP,
                                     self.id]):
            return
        else:
            return False

    def mmi3084(self,descript):
        logger.info(''.join(['\n', descript,'\n']))

        volume = b'\x00'
        volume = b''.join([self.id,volume])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                    api.AVRCP_CMD_ID.SET_ABSOLUTE_VOLUME,
                                    volume],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.SET_ABS_VOLUME_RSP,
                                     self.id]):
            return
        else:
            return False

    def mmi3085(self,descript):
        logger.info(''.join(['\n', descript,'\n']))
        startItem= b'\x00\x00\x00\x00'
        endItem  = b'\xFF\xFF\xFF\xFF'
        attCount = b'\x00'
        scope    = b''.join([self.id,
                             api.AVRCP_SCOPE_MEDIA_PLAYER.LIST.value,
                             startItem,
                             endItem,
                             attCount])

        folderItemRsp = self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                                  api.AVRCP_CMD_ID.GET_FOLDER_ITEM,
                                                  scope],
                                       EVENT   = [api.Layer_ID.AVRCP,
                                                  api.AVRCP_Event_ID.GET_FOLDER_ITEMS_RSP,
                                                  self.id],
                                       back    =  True)

        if not folderItemRsp:
            return False

        self.uidcounter = folderItemRsp[4:6]
        playerId = folderItemRsp[13:15]
        player   = b''.join([self.id, playerId])

        playerRsp = self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                              api.AVRCP_CMD_ID.SET_ADDRESSED_PLAYER,
                                              player],
                                   EVENT   = [api.Layer_ID.AVRCP,
                                              api.AVRCP_Event_ID.SET_ADDRESSED_PLAYER,
                                              self.id],
                                   back    =  True)

        if not playerRsp:
            return False

        return

    def mmi3086(self,descript):
        logger.info(''.join(['\n', descript,'\n']))
        startItem= b'\x00\x00\x00\x00'
        endItem  = b'\xFF\xFF\xFF\xFF'
        attCount = b'\x00'
        scope    = b''.join([self.id,
                             api.AVRCP_SCOPE_MEDIA_PLAYER.LIST.value,
                             startItem,
                             endItem,
                             attCount])

        folderItemRsp = self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                                  api.AVRCP_CMD_ID.GET_FOLDER_ITEM,
                                                  scope],
                                       EVENT   = [api.Layer_ID.AVRCP,
                                                  api.AVRCP_Event_ID.GET_FOLDER_ITEMS_RSP,
                                                  self.id],
                                       back    =  True)

        if not folderItemRsp:
            return False

        self.uidcounter = folderItemRsp[4:6]
        playerId = folderItemRsp[13:15]
        player = b''.join([self.id, playerId])

        playerRsp = self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                              api.AVRCP_CMD_ID.SET_BROWSED_PLAYER,
                                              player],
                                   EVENT   = [api.Layer_ID.AVRCP,
                                              api.AVRCP_Event_ID.SET_BROWSERED_PLAYER_RSP,
                                              self.id],
                                   back    =  True)

        if not playerRsp:
            return False

        self.folderUid = [num.to_bytes(4, 'big') * 2
                          for num in range(1, int.from_bytes(playerRsp[6:10], byteorder='big') + 1)]

        return

    def mmi3087(self,descript):
        logger.info(''.join(['\n', descript,'\n']))

        repeat  = b''.join([api.AVRCP_PLAYER_APP_ATTR_ID.EQUALIZER.value,
                            api.AVRCP_REPEAT_MODE_STATUS.ALL_TRACK_REPEAT.value])

        shuffle = b''.join([api.AVRCP_PLAYER_APP_ATTR_ID.SHUFFLE.value,
                            api.AVRCP_SHUFFLE_STATUS.OFF.value])

        attrID  = b''.join([repeat,shuffle])

        value   = b''.join([self.id,
                            int(len(attrID) / 2).to_bytes(1, 'big'),
                            attrID])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.SET_VALUE,
                                     value],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.SET_PLAYER_APP_SET_VAL,
                                     self.id,]):
            return
        else:
            return False

    def mmi3094(self,descript):
        logger.info(''.join(['\n', descript,'\n']))

        item = b''.join([self.id,
                         api.AVRCP_SCOPE_MEDIA_PLAYER.LIST.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.GET_TOTAL_NUM_OF_ITEM,
                                     item],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.GET_TOTAL_NUM_OF_ITEMS_RSP,
                                     self.id]):
            return
        else:
            return False

    def mmi3095(self,descript):
        logger.info(''.join(['\n', descript,'\n']))

        item = b''.join([self.id,
                         api.AVRCP_SCOPE_MEDIA_PLAYER.NOW_PLAYING.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.GET_TOTAL_NUM_OF_ITEM,
                                     item],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.GET_TOTAL_NUM_OF_ITEMS_RSP,
                                     self.id]):
            return
        else:
            return False

    def mmi3096(self,descript):
        logger.info(''.join(['\n', descript,'\n']))

        item = b''.join([self.id,
                         api.AVRCP_SCOPE_MEDIA_PLAYER.SEARCH.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.GET_TOTAL_NUM_OF_ITEM,
                                     item],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.GET_TOTAL_NUM_OF_ITEMS_RSP,
                                     self.id]):
            return
        else:
            return False

    def mmi3097(self,descript):
        logger.info(''.join(['\n', descript,'\n']))

        item = b''.join([self.id,
                         api.AVRCP_SCOPE_MEDIA_PLAYER.VIRTUAL_FILESYSTEM.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVRCP,
                                     api.AVRCP_CMD_ID.GET_TOTAL_NUM_OF_ITEM,
                                     item],
                          EVENT   = [api.Layer_ID.AVRCP,
                                     api.AVRCP_Event_ID.GET_TOTAL_NUM_OF_ITEMS_RSP,
                                     self.id]):
            return
        else:
            return False

    def mmi3105(self,descript):
        logger.info(''.join(['\n', descript,'\n']))

        if self.CommandRW(COMMAND = [api.Layer_ID.BT_GAP,
                                     api.BT_GAP_CMD_ID.DISCONNECT,
                                     self.conninfo['connhandle']],
                          EVENT   = [api.Layer_ID.BT_GAP,
                                     api.BT_GAP_Event_ID.DISCONNECTED,
                                     api.BT_GAP_Status_ID.SUCCESS]):
            return
        else:
            return False

    def mmi3110(self,descript):
        logger.info(''.join(['\n', descript,'\n']))
        return True

class GAP(Common):
    def __init__(self,comport,profile,casename,ptsaddress_b,ixit,bleonly):
        Common.__init__(self,comport,profile,casename,ptsaddress_b,ixit,bleonly)
        self.id       = b'\x00'
        self.conninfo = None
        self.wait     = None

    def mmi(self,descript):
        if self.wait:
            time.sleep(self.wait)
            self.wait = None
            return

        if self.casename_b == b'GAP/BOND/NBON/BV-01-C'or \
           self.casename_b == b'GAP/BOND/BON/BV-02-C' or \
           self.casename_b == b'GAP/BOND/BON/BV-04-C' or \
           self.casename_b == b'GAP/SEC/AUT/BV-12-C' or \
           self.casename_b == b'GAP/SEC/AUT/BV-13-C' or \
           self.casename_b == b'GAP/SEC/AUT/BV-24-C' or \
           self.casename_b == b'GAP/DM/NBON/BV-01-C':
            if self.conninfo:
                if self.CommandRW(EVENT = [api.Layer_ID.BLE_SMP,
                                           api.SMP_Event_ID.SECURITY_REQUEST,
                                           self.conninfo['connhandle']]):
                    if self.CommandRW(COMMAND = [api.Layer_ID.BLE_SMP,
                                                 api.SMP_CMD_ID.INIT_PAIR,
                                                 self.conninfo['connhandle']],
                                      EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                                 api.Layer_ID.BLE_SMP,
                                                 api.SMP_CMD_ID.INIT_PAIR]):
                        return
                    else:
                        return False
                else:
                    return

        elif self.casename_b == b'GAP/SEC/SEM/BV-04-C':
            res = self.readEvent()
            if res[0:1] == api.Layer_ID.PERIPHERAL_USB_BC.value:
                return

            conninfo = self.get_connetion_info()

            if not conninfo:
                return False

            self.conninfo = conninfo

            if self.CommandRW(EVENT = [api.Layer_ID.BT_GAP,
                                       api.BT_GAP_Event_ID.ENCRYPT_STATUS,
                                       self.conninfo['connhandle']]):
                if self.CommandRW(EVENT = [api.Layer_ID.UTILITY,
                                           api.UTILITY_Event_ID.PAIRED_KEY_NOTIFY,
                                           b'\x00']):
                    time.sleep(2)
                    l2capId     = b'\x00'
                    openChanRsp = b''.join([l2capId,
                                            api.BT_L2CAP_CONN_RSP_RESULT.SUCCESSFUL.value,
                                            api.BT_L2CAP_CONN_RSP_STATUS.AUTHENTICATION_PENDING.value,
                                            len(api.BT_L2CAP_CONF_OPTIONS.MTU.value).to_bytes(1,'big'),
                                            api.BT_L2CAP_CONF_OPTIONS.MTU.value])

                    if self.CommandRW(COMMAND = [api.Layer_ID.BT_L2CAP,
                                                 api.BT_L2CAP_CMD_ID.OPEN_CHAN_RSP,
                                                 openChanRsp],
                                      EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                                 api.Layer_ID.BT_L2CAP,
                                                 api.BT_L2CAP_CMD_ID.OPEN_CHAN_RSP]):
                        return
                    else:
                        return False

        else:
            return

    def mmi4(self,descript):
        logger.info(''.join(['\n', descript,'\n']))
        AdvReport = bytes()

        if self.casename_b == b'GAP/BROB/OBSV/BV-01-C':
            AdvReport = b''.join([api.BLE_GAP_ADV.EVENTTYPE_ADV_NONCONN_IND.value,
                                  api.BLE_GAP_ADDR_TYPE.PUBLIC.value,
                                  bytes.fromhex(self.pts_address_b.decode())[::-1]])

        if self.casename_b == b'GAP/BROB/OBSV/BV-02-C':
            AdvReport = b''.join([api.BLE_GAP_ADV.EVENTTYPE_ADV_SCAN_RSP.value,
                                  api.BLE_GAP_ADDR_TYPE.PUBLIC.value,
                                  bytes.fromhex(self.pts_address_b.decode())[::-1]])

        advReport = self.CommandRW(EVENT = [api.Layer_ID.BLE_GAP,
                                            api.BLE_GAP_Event_ID.ADVERTISING_REPORT,
                                            AdvReport],
                                   back =   True)

        if not advReport:
            logger.error('...no received an advertising event...')
            return False

        report = self.adv_report_paser(advReport)

        if report['address'][::-1].hex().upper().encode() == self.pts_address_b:

            ScanMode = b''.join([api.BLE_GAP_SCAN.DISABLE.value,
                                 api.BLE_GAP_SCAN.FILTER_DUPLICATES_DISABLE.value,
                                 api.BLE_GAP_SCAN.MODE_OBSERVER.value])

            if self.set_scanning(scanMode=ScanMode):
                return True
            else:
                logger.error('... disable scan failure ...')
                return False
        else:
            logger.error(f'... pts_address     is {self.pts_address_b} ...')
            logger.error(f"... receive address is {report['address'][::-1].hex().upper().encode()} ...")
            return False

    def mmi5(self,descript):
        logger.info(''.join(['\n', descript,'\n']))
        AdvData = b''.join([len(api.BLE_GAP_ADV.DATATYPE_Flags.value
                            + api.BLE_GAP_ADV.Flags_Non_Discover.value).to_bytes(1,'big'),
                            api.BLE_GAP_ADV.DATATYPE_Flags.value,
                            api.BLE_GAP_ADV.Flags_Non_Discover.value])

        AdvParam = b''.join([b'\x00\x20\x00\x20',
                             api.BLE_GAP_ADV.TYPE_ADV_NONCONN_IND.value,
                             api.BLE_GAP_ADDR_TYPE.PUBLIC.value,
                             api.BLE_GAP_ADDR_TYPE.PUBLIC.value,
                             bytes.fromhex(self.pts_address_b.decode())[::-1],
                             api.BLE_GAP_ADV.CHANNEL_ALL.value,
                             api.BLE_GAP_ADV.FILTER_POLICY_DEFAULT.value])

        if not self.advertising(advData=AdvData, advParam=AdvParam, EnDisable=api.BLE_GAP_ADV.ENABLE):
            return False

    def mmi7(self,descript):
        logger.info(''.join(['\n', descript,'\n']))
        if not self.iut_white_list_init():
            return False

        IntervalWindow = b'\x00\x10\x00\x10'

        ScanParam = b''.join([api.BLE_GAP_SCAN.TYPE_ACTIVE_SCAN.value,
                              IntervalWindow,
                              api.BLE_GAP_ADDR_TYPE.PUBLIC.value,
                              api.BLE_GAP_SCAN.FILTER_POLICY_WHITELIST.value])

        ScanMode = b''.join([api.BLE_GAP_SCAN.ENABLE.value,
                             api.BLE_GAP_SCAN.FILTER_DUPLICATES_ENABLE.value,
                             api.BLE_GAP_SCAN.MODE_LIMITED_DISCOVERY.value])

        if self.set_scanning(scanParam=ScanParam, scanMode=ScanMode):
            AdvReport = b''.join([api.BLE_GAP_ADV.EVENTTYPE_ADV_SCAN_IND.value,
                                  api.BLE_GAP_ADDR_TYPE.PUBLIC.value,
                                  bytes.fromhex(self.pts_address_b.decode())[::-1]])

            advReport = self.CommandRW(EVENT = [api.Layer_ID.BLE_GAP,
                                                api.BLE_GAP_Event_ID.ADVERTISING_REPORT,
                                                AdvReport],
                                       back = True)

            if not advReport:
                logger.error('...no received an advertising event...')
                return False

            report = self.adv_report_paser(advReport)

            if report['address'][::-1].hex().upper().encode() == self.pts_address_b:

                ScanMode = b''.join([api.BLE_GAP_SCAN.DISABLE.value,
                                     api.BLE_GAP_SCAN.FILTER_DUPLICATES_DISABLE.value,
                                     api.BLE_GAP_SCAN.MODE_LIMITED_DISCOVERY.value])

                if self.set_scanning(scanMode=ScanMode):
                    return True
                else:
                    return False
            else:
                return False

    def mmi9(self,descript):
        logger.info(''.join(['\n', descript,'\n']))

        AdvData = b''.join([len(api.BLE_GAP_ADV.DATATYPE_Flags.value
                                + api.BLE_GAP_ADV.Flags_General_Discover.value).to_bytes(1, 'big'),
                            api.BLE_GAP_ADV.DATATYPE_Flags.value,
                            api.BLE_GAP_ADV.Flags_General_Discover.value])

        AdvParam = b''.join([b'\x00\x20\x00\x20',
                             api.BLE_GAP_ADV.TYPE_ADV_IND.value,
                             api.BLE_GAP_ADDR_TYPE.PUBLIC.value,
                             api.BLE_GAP_ADDR_TYPE.PUBLIC.value,
                             bytes.fromhex(self.pts_address_b.decode())[::-1],
                             api.BLE_GAP_ADV.CHANNEL_ALL.value,
                             api.BLE_GAP_ADV.FILTER_POLICY_DEFAULT.value])

        if not self.advertising(advData=AdvData, advParam=AdvParam, EnDisable=api.BLE_GAP_ADV.ENABLE):
            return False

    def mmi10(self,descript):
        logger.info(''.join(['\n', descript,'\n']))

        AdvReport = b''.join([api.BLE_GAP_ADV.EVENTTYPE_ADV_IND.value,
                              api.BLE_GAP_ADDR_TYPE.PUBLIC.value,
                              bytes.fromhex(self.pts_address_b.decode())[::-1]])

        advReport = self.CommandRW(EVENT = [api.Layer_ID.BLE_GAP,
                                            api.BLE_GAP_Event_ID.ADVERTISING_REPORT,
                                            AdvReport],
                                   back =   True)

        if not advReport:
            logger.error('...no received an advertising event...')
            return False

        report = self.adv_report_paser(advReport)

        if report['address'][::-1].hex().upper().encode() == self.pts_address_b:

            ScanMode = b''.join([api.BLE_GAP_SCAN.DISABLE.value,
                                 api.BLE_GAP_SCAN.FILTER_DUPLICATES_DISABLE.value,
                                 api.BLE_GAP_SCAN.MODE_LIMITED_DISCOVERY.value])

            if self.set_scanning(scanMode=ScanMode):
                return True
            else:
                return False
        else:
            return False

    def mmi11(self,descript):
        logger.info(''.join(['\n', descript,'\n']))

        AdvReport = b''.join([api.BLE_GAP_ADV.EVENTTYPE_ADV_IND.value,
                              api.BLE_GAP_ADDR_TYPE.PUBLIC.value,
                              bytes.fromhex(self.pts_address_b.decode())[::-1]])

        advReport = self.CommandRW(EVENT = [api.Layer_ID.BLE_GAP,
                                            api.BLE_GAP_Event_ID.ADVERTISING_REPORT,
                                            AdvReport])

        ScanMode = bytes()
        if not advReport:
            if self.casename_b == b'GAP/DISC/LIMP/BV-02-C' or \
               self.casename_b == b'GAP/DISC/LIMP/BV-03-C' or \
               self.casename_b == b'GAP/DISC/LIMP/BV-04-C' or \
               self.casename_b == b'GAP/DISC/LIMP/BV-05-C':
                ScanMode = b''.join([api.BLE_GAP_SCAN.DISABLE.value,
                             api.BLE_GAP_SCAN.FILTER_DUPLICATES_DISABLE.value,
                             api.BLE_GAP_SCAN.MODE_LIMITED_DISCOVERY.value])

            if self.casename_b == b'GAP/DISC/GENP/BV-03-C' or \
               self.casename_b == b'GAP/DISC/GENP/BV-04-C' or \
               self.casename_b == b'GAP/DISC/GENP/BV-05-C':
                ScanMode = b''.join([api.BLE_GAP_SCAN.DISABLE.value,
                             api.BLE_GAP_SCAN.FILTER_DUPLICATES_DISABLE.value,
                             api.BLE_GAP_SCAN.MODE_GENERAL_DISCOVERY.value])

            if self.set_scanning(scanMode=ScanMode):
                return True
            else:
                return False
        else:
            return False

    def mmi12(self,descript):
        logger.info(''.join(['\n', descript,'\n']))

        if not self.iut_white_list_init():
            return False

        IntervalWindow = b'\x00\x10\x00\x10'

        ScanParam = b''.join([api.BLE_GAP_SCAN.TYPE_PASSIVE_SCAN.value,
                              IntervalWindow,
                              api.BLE_GAP_ADDR_TYPE.PUBLIC.value,
                              api.BLE_GAP_SCAN.FILTER_POLICY_WHITELIST.value])

        ScanMode = b''.join([api.BLE_GAP_SCAN.ENABLE.value,
                             api.BLE_GAP_SCAN.FILTER_DUPLICATES_ENABLE.value,
                             api.BLE_GAP_SCAN.MODE_OBSERVER.value])

        if self.set_scanning(scanParam=ScanParam, scanMode=ScanMode):
            return True
        else:
            return False

    def mmi13(self,descript):
        logger.info(''.join(['\n', descript,'\n']))
        if not self.iut_white_list_init():
            return False

        IntervalWindow = b'\x00\x10\x00\x10'

        ScanParam = b''.join([api.BLE_GAP_SCAN.TYPE_ACTIVE_SCAN.value,
                              IntervalWindow,
                              api.BLE_GAP_ADDR_TYPE.PUBLIC.value,
                              api.BLE_GAP_SCAN.FILTER_POLICY_WHITELIST.value])

        ScanMode = b''.join([api.BLE_GAP_SCAN.ENABLE.value,
                             api.BLE_GAP_SCAN.FILTER_DUPLICATES_ENABLE.value,
                             api.BLE_GAP_SCAN.MODE_LIMITED_DISCOVERY.value])

        if self.set_scanning(scanParam=ScanParam, scanMode=ScanMode):
            return True
        else:
            return False

    def mmi14(self,descript):
        logger.info(''.join(['\n', descript,'\n']))

        AdvReport = b''.join([api.BLE_GAP_ADV.EVENTTYPE_ADV_IND.value,
                              api.BLE_GAP_ADDR_TYPE.PUBLIC.value,
                              bytes.fromhex(self.pts_address_b.decode())[::-1]])

        advReport = self.CommandRW(EVENT = [api.Layer_ID.BLE_GAP,
                                            api.BLE_GAP_Event_ID.ADVERTISING_REPORT,
                                            AdvReport],
                                   back =   True)

        if not advReport:
            logger.error('...no received an advertising event...')
            return False

        report = self.adv_report_paser(advReport)

        if report['address'][::-1].hex().upper().encode() == self.pts_address_b:

            ScanMode = b''.join([api.BLE_GAP_SCAN.DISABLE.value,
                                 api.BLE_GAP_SCAN.FILTER_DUPLICATES_DISABLE.value,
                                 api.BLE_GAP_SCAN.MODE_GENERAL_DISCOVERY.value])

            if self.set_scanning(scanMode=ScanMode):
                return True
            else:
                logger.error('... disable scan failure ...')
                return False
        else:
            logger.error(f'... pts_address     is {self.pts_address_b} ...')
            logger.error(f"... receive address is {report['address'][::-1].hex().upper().encode()} ...")
            return False

    def mmi20(self,descript):
        logger.info(''.join(['\n', descript,'\n']))

        AdvData = b''.join([len(api.BLE_GAP_ADV.DATATYPE_Flags.value
                            + api.BLE_GAP_ADV.Flags_Non_Discover.value).to_bytes(1,'big'),
                            api.BLE_GAP_ADV.DATATYPE_Flags.value,
                            api.BLE_GAP_ADV.Flags_Non_Discover.value])

        AdvParam = b''.join([b'\x00\x20\x00\x20',
                             api.BLE_GAP_ADV.TYPE_ADV_NONCONN_IND.value,
                             api.BLE_GAP_ADDR_TYPE.PUBLIC.value,
                             api.BLE_GAP_ADDR_TYPE.PUBLIC.value,
                             bytes.fromhex(self.pts_address_b.decode())[::-1],
                             api.BLE_GAP_ADV.CHANNEL_ALL.value,
                             api.BLE_GAP_ADV.FILTER_POLICY_DEFAULT.value])

        if not self.advertising(advData=AdvData, advParam=AdvParam, EnDisable=api.BLE_GAP_ADV.ENABLE):
            return False

    def mmi21(self,descript):
        logger.info(''.join(['\n', descript,'\n']))

        AdvData = b''.join([len(api.BLE_GAP_ADV.DATATYPE_Flags.value
                                + api.BLE_GAP_ADV.Flags_General_Discover.value).to_bytes(1, 'big'),
                            api.BLE_GAP_ADV.DATATYPE_Flags.value,
                            api.BLE_GAP_ADV.Flags_General_Discover.value])

        AdvParam = b''.join([b'\x00\x20\x00\x20',
                             api.BLE_GAP_ADV.TYPE_ADV_IND.value,
                             api.BLE_GAP_ADDR_TYPE.PUBLIC.value,
                             api.BLE_GAP_ADDR_TYPE.PUBLIC.value,
                             bytes.fromhex(self.pts_address_b.decode())[::-1],
                             api.BLE_GAP_ADV.CHANNEL_ALL.value,
                             api.BLE_GAP_ADV.FILTER_POLICY_DEFAULT.value])

        if not self.advertising(advData=AdvData, advParam=AdvParam, EnDisable=api.BLE_GAP_ADV.ENABLE):
            return False

        time.sleep(1)

        conninfo = self.get_connetion_info()

        if not conninfo:
            return False
        else:
            self.conninfo = conninfo
            return

    def mmi23(self,descript):
        logger.info(''.join(['\n', descript,'\n']))
        if not self.iut_white_list_init():
            return False

        IntervalWindow = b'\x00\x10\x00\x10'

        ScanParam = b''.join([api.BLE_GAP_SCAN.TYPE_ACTIVE_SCAN.value,
                              IntervalWindow,
                              api.BLE_GAP_ADDR_TYPE.PUBLIC.value,
                              api.BLE_GAP_SCAN.FILTER_POLICY_WHITELIST.value])

        ScanMode = b''.join([api.BLE_GAP_SCAN.ENABLE.value,
                             api.BLE_GAP_SCAN.FILTER_DUPLICATES_ENABLE.value,
                             api.BLE_GAP_SCAN.MODE_GENERAL_DISCOVERY.value])

        if self.set_scanning(scanParam=ScanParam, scanMode=ScanMode):
            return True
        else:
            return False

    def mmi24(self,descript):
        logger.info(''.join(['\n', descript,'\n']))

        localName = self.iut_get_device_name()
        AdvData = b''.join([len(api.BLE_GAP_ADV.DATATYPE_Complete_Local_Name.value
                            + localName).to_bytes(1,'big'),
                            api.BLE_GAP_ADV.DATATYPE_Complete_Local_Name.value,
                            localName])

        AdvParam = b''.join([b'\x00\x20\x00\x20',
                             api.BLE_GAP_ADV.TYPE_ADV_NONCONN_IND.value,
                             api.BLE_GAP_ADDR_TYPE.PUBLIC.value,
                             api.BLE_GAP_ADDR_TYPE.PUBLIC.value,
                             bytes.fromhex(self.pts_address_b.decode())[::-1],
                             api.BLE_GAP_ADV.CHANNEL_ALL.value,
                             api.BLE_GAP_ADV.FILTER_POLICY_DEFAULT.value])

        if not self.advertising(advData=AdvData, advParam=AdvParam, EnDisable=api.BLE_GAP_ADV.ENABLE):
            return False

    def mmi25(self,descript):
        logger.info(''.join(['\n', descript,'\n']))

        AdvData = b''.join([len(api.BLE_GAP_ADV.DATATYPE_Flags.value
                            + api.BLE_GAP_ADV.Flags_Limited_Discover.value).to_bytes(1,'big'),
                            api.BLE_GAP_ADV.DATATYPE_Flags.value,
                            api.BLE_GAP_ADV.Flags_Limited_Discover.value])

        AdvParam = b''.join([b'\x00\x20\x00\x20',
                             api.BLE_GAP_ADV.TYPE_ADV_NONCONN_IND.value,
                             api.BLE_GAP_ADDR_TYPE.PUBLIC.value,
                             api.BLE_GAP_ADDR_TYPE.PUBLIC.value,
                             bytes.fromhex(self.pts_address_b.decode())[::-1],
                             api.BLE_GAP_ADV.CHANNEL_ALL.value,
                             api.BLE_GAP_ADV.FILTER_POLICY_DEFAULT.value])

        if not self.advertising(advData=AdvData, advParam=AdvParam, EnDisable=api.BLE_GAP_ADV.ENABLE):
            return False

    def mmi26(self,descript):
        logger.info(''.join(['\n', descript,'\n']))

        specificData = b'\x13\xFE'
        AdvData = b''.join([len(api.BLE_GAP_ADV.DATATYPE_Manufacturer_Specific_Data.value
                            + specificData).to_bytes(1,'big'),
                            api.BLE_GAP_ADV.DATATYPE_Manufacturer_Specific_Data.value,
                            specificData])

        AdvParam = b''.join([b'\x00\x20\x00\x20',
                             api.BLE_GAP_ADV.TYPE_ADV_NONCONN_IND.value,
                             api.BLE_GAP_ADDR_TYPE.PUBLIC.value,
                             api.BLE_GAP_ADDR_TYPE.PUBLIC.value,
                             bytes.fromhex(self.pts_address_b.decode())[::-1],
                             api.BLE_GAP_ADV.CHANNEL_ALL.value,
                             api.BLE_GAP_ADV.FILTER_POLICY_DEFAULT.value])

        if not self.advertising(advData=AdvData, advParam=AdvParam, EnDisable=api.BLE_GAP_ADV.ENABLE):
            return False

    def mmi27(self,descript):
        logger.info(''.join(['\n', descript,'\n']))

        powerLevel = b'\x02'
        AdvData = b''.join([len(api.BLE_GAP_ADV.DATATYPE_Tx_Power_Level.value
                            + powerLevel).to_bytes(1,'big'),
                            api.BLE_GAP_ADV.DATATYPE_Tx_Power_Level.value,
                            powerLevel])

        AdvParam = b''.join([b'\x00\x20\x00\x20',
                             api.BLE_GAP_ADV.TYPE_ADV_NONCONN_IND.value,
                             api.BLE_GAP_ADDR_TYPE.PUBLIC.value,
                             api.BLE_GAP_ADDR_TYPE.PUBLIC.value,
                             bytes.fromhex(self.pts_address_b.decode())[::-1],
                             api.BLE_GAP_ADV.CHANNEL_ALL.value,
                             api.BLE_GAP_ADV.FILTER_POLICY_DEFAULT.value])

        if not self.advertising(advData=AdvData, advParam=AdvParam, EnDisable=api.BLE_GAP_ADV.ENABLE):
            return False

    def mmi31(self,descript):
        logger.info(f'\n{descript}\n')

        if self.CommandRW(COMMAND = [api.Layer_ID.BT_GAP,
                                     api.BT_GAP_CMD_ID.WRITE_SCAN_ENABLE,
                                     api.BT_GAP_SCAN_ENABLE.INQUIRY_SCAN_NO_SCAN_ENABLED],
                          EVENT   = [api.Layer_ID.BT_GAP,
                                     api.BT_GAP_Event_ID.COMMAND_COMPLETE,
                                     api.BT_GAP_Cmd_Complete_ID.WRITE_SCAN_ENABLE]):
            return True
        else:
            return False

    def mmi32(self,descript):
        logger.info(f'\n{descript}\n')

        numCurrentIac = b'\x01'
        lap_LIAC      = b''.join([numCurrentIac,
                                  api.BT_GAP_LAP.LIAC.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.BT_GAP,
                                     api.BT_GAP_CMD_ID.WRITE_IAC_LAP,
                                     lap_LIAC],
                          EVENT   = [api.Layer_ID.BT_GAP,
                                     api.BT_GAP_Event_ID.COMMAND_COMPLETE,
                                     api.BT_GAP_Cmd_Complete_ID.WRITE_CURRENT_IAC_LAP]):
            if self.casename_b == b'GAP/MOD/LDIS/BV-01-C':
                if self.CommandRW(COMMAND = [api.Layer_ID.BT_GAP,
                                             api.BT_GAP_CMD_ID.WRITE_SCAN_ENABLE,
                                             api.BT_GAP_SCAN_ENABLE.INQUIRY_SCAN_ENABLE_PAGE_SCAN_ENABLE],
                                  EVENT   = [api.Layer_ID.BT_GAP,
                                             api.BT_GAP_Event_ID.COMMAND_COMPLETE,
                                             api.BT_GAP_Cmd_Complete_ID.WRITE_SCAN_ENABLE]):
                    self.wait = 70
                    return [True,'mmi']
                else:
                    return False

            if self.casename_b == b'GAP/MOD/LDIS/BV-03-C':
                if self.CommandRW(COMMAND = [api.Layer_ID.BT_GAP,
                                             api.BT_GAP_CMD_ID.WRITE_SCAN_ENABLE,
                                             api.BT_GAP_SCAN_ENABLE.INQUIRY_SCAN_NO_SCAN_ENABLED],
                                  EVENT   = [api.Layer_ID.BT_GAP,
                                             api.BT_GAP_Event_ID.COMMAND_COMPLETE,
                                             api.BT_GAP_Cmd_Complete_ID.WRITE_SCAN_ENABLE]):
                    return True
                else:
                    return False
        else:
            return False

    def mmi33(self,descript):
        logger.info(''.join(['\n', descript,'\n']))

        numCurrentIac = b'\x01'
        lap_GIAC = b''.join([numCurrentIac,
                             api.BT_GAP_LAP.GIAC.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.BT_GAP,
                                     api.BT_GAP_CMD_ID.WRITE_IAC_LAP,
                                     lap_GIAC],
                          EVENT   = [api.Layer_ID.BT_GAP,
                                     api.BT_GAP_Event_ID.COMMAND_COMPLETE,
                                     api.BT_GAP_Cmd_Complete_ID.WRITE_CURRENT_IAC_LAP]):
            if self.CommandRW(COMMAND = [api.Layer_ID.BT_GAP,
                                         api.BT_GAP_CMD_ID.WRITE_SCAN_ENABLE,
                                         api.BT_GAP_SCAN_ENABLE.INQUIRY_SCAN_ENABLE_PAGE_SCAN_ENABLE],
                              EVENT   = [api.Layer_ID.BT_GAP,
                                         api.BT_GAP_Event_ID.COMMAND_COMPLETE,
                                         api.BT_GAP_Cmd_Complete_ID.WRITE_SCAN_ENABLE]):
                self.wait = 25
                return [True,'mmi']
            else:
                return False
        else:
            return False

    def mmi34(self,descript):
        logger.info(f'\n{descript}\n')

        if self.CommandRW(COMMAND = [api.Layer_ID.BT_GAP,
                                     api.BT_GAP_CMD_ID.WRITE_SCAN_ENABLE,
                                     api.BT_GAP_SCAN_ENABLE.INQUIRY_SCAN_NO_SCAN_ENABLED],
                          EVENT   = [api.Layer_ID.BT_GAP,
                                     api.BT_GAP_Event_ID.COMMAND_COMPLETE,
                                     api.BT_GAP_Cmd_Complete_ID.WRITE_SCAN_ENABLE]):
            return True
        else:
            return False

    def mmi35(self,descript):
        logger.info(''.join(['\n', descript,'\n']))

        serviceUUID = b'\x1F\x11'
        AdvData = b''.join([len(api.BLE_GAP_ADV.DATATYPE_Complete_List_16bit_Service_Class_UUIDs.value
                            + serviceUUID).to_bytes(1,'big'),
                            api.BLE_GAP_ADV.DATATYPE_Complete_List_16bit_Service_Class_UUIDs.value,
                            serviceUUID])

        AdvParam = b''.join([b'\x00\x20\x00\x20',
                                 api.BLE_GAP_ADV.TYPE_ADV_NONCONN_IND.value,
                                 api.BLE_GAP_ADDR_TYPE.PUBLIC.value,
                                 api.BLE_GAP_ADDR_TYPE.PUBLIC.value,
                                 bytes.fromhex(self.pts_address_b.decode())[::-1],
                                 api.BLE_GAP_ADV.CHANNEL_ALL.value,
                                 api.BLE_GAP_ADV.FILTER_POLICY_DEFAULT.value])

        if not self.advertising(advData=AdvData, advParam=AdvParam, EnDisable=api.BLE_GAP_ADV.ENABLE):
            return False

    def mmi36(self,descript):
        logger.info(''.join(['\n', descript,'\n']))
        if not self.iut_white_list_init():
            return False

        IntervalWindow = b'\x00\x10\x00\x10'

        ScanParam = b''.join([api.BLE_GAP_SCAN.TYPE_ACTIVE_SCAN.value,
                              IntervalWindow,
                              api.BLE_GAP_ADDR_TYPE.PUBLIC.value,
                              api.BLE_GAP_SCAN.FILTER_POLICY_WHITELIST.value])

        ScanMode = b''.join([api.BLE_GAP_SCAN.ENABLE.value,
                             api.BLE_GAP_SCAN.FILTER_DUPLICATES_ENABLE.value,
                             api.BLE_GAP_SCAN.MODE_GENERAL_DISCOVERY.value])

        if self.set_scanning(scanParam=ScanParam, scanMode=ScanMode):
            AdvReport = b''.join([api.BLE_GAP_ADV.EVENTTYPE_ADV_SCAN_IND.value,
                                  api.BLE_GAP_ADDR_TYPE.PUBLIC.value,
                                  bytes.fromhex(self.pts_address_b.decode())[::-1]])

            advReport = self.CommandRW(EVENT = [api.Layer_ID.BLE_GAP,
                                                api.BLE_GAP_Event_ID.ADVERTISING_REPORT,
                                                AdvReport],
                                       back = True)

            if not advReport:
                logger.error('...no received an advertising event...')
                return False

            report = self.adv_report_paser(advReport)

            if report['address'][::-1].hex().upper().encode() == self.pts_address_b:

                ScanMode = b''.join([api.BLE_GAP_SCAN.DISABLE.value,
                                     api.BLE_GAP_SCAN.FILTER_DUPLICATES_DISABLE.value,
                                     api.BLE_GAP_SCAN.MODE_GENERAL_DISCOVERY.value])

                if self.set_scanning(scanMode=ScanMode):
                    return [True,'mmi']
                else:
                    return False
            else:
                return False
        else:
            return False

    def mmi40(self,descript):
        logger.info(f'\n{descript}\n')

        conninfo = self.create_connection('BLE')

        if not conninfo:
            return False

        self.conninfo = conninfo
        return

    def mmi44(self,descript):
        logger.info(f'\n{descript}\n')

        terminate = b''.join([self.conninfo['connhandle'],
                              api.BLE_GAP_DISC_REASON.REMOTE_TERMINATE.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.BLE_GAP,
                                     api.BLE_GAP_CMD_ID.TERMINATE_CONNECTION,
                                     terminate],
                          EVENT   = [api.Layer_ID.BLE_GAP,
                                     api.BLE_GAP_Event_ID.DISCONNECTED,
                                     self.conninfo['connhandle']]):
            return
        else:
            return False

    def mmi46(self,descript):
        logger.info(f'\n{descript}\n')

        parameter = b''.join([self.conninfo['connhandle'],
                              bytes.fromhex(self.ixit[b'TSPX_con_interval_min'][1].decode()),
                              self.conninfo['connpara']])

        if self.CommandRW(COMMAND = [api.Layer_ID.BLE_L2CAP,
                                     api.BLE_L2CAP_CMD_ID.BLE_CPU,
                                     parameter],
                          EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                     api.Layer_ID.BLE_L2CAP,
                                     api.BLE_L2CAP_CMD_ID.BLE_CPU]):
            return
        else:
            return False

    def mmi47(self,descript):
        logger.info(''.join(['\n', descript,'\n']))
        AdvData  = bytes()
        AdvParam = bytes()

        # region set advertising data
        if self.casename_b == b'GAP/BROB/BCST/BV-01-C' or \
           self.casename_b == b'GAP/BROB/BCST/BV-02-C':
            AdvData  = bytes.fromhex(self.ixit[b'TSPX_advertising_data'][1].decode())
        # endregion

        # region set advertising parameter
        if self.casename_b == b'GAP/BROB/BCST/BV-01-C':
            AdvParam = b''.join([b'\x00\x20\x00\x20',
                                 api.BLE_GAP_ADV.TYPE_ADV_NONCONN_IND.value,
                                 api.BLE_GAP_ADDR_TYPE.PUBLIC.value,
                                 api.BLE_GAP_ADDR_TYPE.PUBLIC.value,
                                 bytes.fromhex(self.pts_address_b.decode())[::-1],
                                 api.BLE_GAP_ADV.CHANNEL_ALL.value,
                                 api.BLE_GAP_ADV.FILTER_POLICY_DEFAULT.value])

        if self.casename_b == b'GAP/BROB/BCST/BV-02-C':
            AdvParam = b''.join([b'\x00\x20\x00\x20',
                                 api.BLE_GAP_ADV.TYPE_ADV_SCAN_IND.value,
                                 api.BLE_GAP_ADDR_TYPE.PUBLIC.value,
                                 api.BLE_GAP_ADDR_TYPE.PUBLIC.value,
                                 bytes.fromhex(self.pts_address_b.decode())[::-1],
                                 api.BLE_GAP_ADV.CHANNEL_ALL.value,
                                 api.BLE_GAP_ADV.FILTER_POLICY_DEFAULT.value])
        # endregion

        if not self.advertising(advData=AdvData, advParam=AdvParam, EnDisable=api.BLE_GAP_ADV.ENABLE):
            return False

    def mmi49(self,descript):
        logger.info(''.join(['\n', descript,'\n']))

        AdvData = b''.join([len(api.BLE_GAP_ADV.DATATYPE_Flags.value
                            + api.BLE_GAP_ADV.Flags_Limited_Discover.value).to_bytes(1,'big'),
                            api.BLE_GAP_ADV.DATATYPE_Flags.value,
                            api.BLE_GAP_ADV.Flags_Limited_Discover.value])

        if self.casename_b == b'GAP/DISC/LIMM/BV-03-C':
            AdvData = b''.join([len(api.BLE_GAP_ADV.DATATYPE_Flags.value
                                + api.BLE_GAP_ADV.Flags_LE_Limited_Discover.value).to_bytes(1,'big'),
                                api.BLE_GAP_ADV.DATATYPE_Flags.value,
                                api.BLE_GAP_ADV.Flags_LE_Limited_Discover.value])

        AdvParam = b''.join([b'\x00\x20\x00\x20',
                             api.BLE_GAP_ADV.TYPE_ADV_NONCONN_IND.value,
                             api.BLE_GAP_ADDR_TYPE.PUBLIC.value,
                             api.BLE_GAP_ADDR_TYPE.PUBLIC.value,
                             bytes.fromhex(self.pts_address_b.decode())[::-1],
                             api.BLE_GAP_ADV.CHANNEL_ALL.value,
                             api.BLE_GAP_ADV.FILTER_POLICY_DEFAULT.value])

        if not self.advertising(advData=AdvData, advParam=AdvParam, EnDisable=api.BLE_GAP_ADV.ENABLE):
            return False

        time.sleep(((int(self.ixit[b'TSPX_lim_adv_timeout'][1])) / 1000)-5)

        if not self.advertising(EnDisable=api.BLE_GAP_ADV.DISABLE):
            return False

    def mmi50(self,descript):
        logger.info(''.join(['\n', descript,'\n']))

        AdvData = b''.join([len(api.BLE_GAP_ADV.DATATYPE_Flags.value
                            + api.BLE_GAP_ADV.Flags_Limited_Discover.value).to_bytes(1,'big'),
                            api.BLE_GAP_ADV.DATATYPE_Flags.value,
                            api.BLE_GAP_ADV.Flags_Limited_Discover.value])

        if self.casename_b == b'GAP/DISC/LIMM/BV-04-C':
            AdvData = b''.join([len(api.BLE_GAP_ADV.DATATYPE_Flags.value
                                + api.BLE_GAP_ADV.Flags_LE_Limited_Discover.value).to_bytes(1,'big'),
                                api.BLE_GAP_ADV.DATATYPE_Flags.value,
                                api.BLE_GAP_ADV.Flags_LE_Limited_Discover.value])


        AdvParam = b''.join([b'\x00\x20\x00\x20',
                             api.BLE_GAP_ADV.TYPE_ADV_IND.value,
                             api.BLE_GAP_ADDR_TYPE.PUBLIC.value,
                             api.BLE_GAP_ADDR_TYPE.PUBLIC.value,
                             bytes.fromhex(self.pts_address_b.decode())[::-1],
                             api.BLE_GAP_ADV.CHANNEL_ALL.value,
                             api.BLE_GAP_ADV.FILTER_POLICY_DEFAULT.value])

        if not self.advertising(advData=AdvData, advParam=AdvParam, EnDisable=api.BLE_GAP_ADV.ENABLE):
            return False

        time.sleep(((int(self.ixit[b'TSPX_lim_adv_timeout'][1])) / 1000)-5)

        if not self.advertising(EnDisable=api.BLE_GAP_ADV.DISABLE):
            return False

        return None

    def mmi51(self,descript):
        logger.info(''.join(['\n', descript,'\n']))

        AdvData = b''.join([len(api.BLE_GAP_ADV.DATATYPE_Flags.value
                            + api.BLE_GAP_ADV.Flags_General_Discover.value).to_bytes(1,'big'),
                            api.BLE_GAP_ADV.DATATYPE_Flags.value,
                            api.BLE_GAP_ADV.Flags_General_Discover.value])

        if self.casename_b == b'GAP/DISC/GENM/BV-03-C':
            AdvData = b''.join([len(api.BLE_GAP_ADV.DATATYPE_Flags.value
                                + api.BLE_GAP_ADV.Flags_LE_General_Discover.value).to_bytes(1,'big'),
                                api.BLE_GAP_ADV.DATATYPE_Flags.value,
                                api.BLE_GAP_ADV.Flags_LE_General_Discover.value])

        AdvParam = b''.join([b'\x00\x20\x00\x20',
                             api.BLE_GAP_ADV.TYPE_ADV_NONCONN_IND.value,
                             api.BLE_GAP_ADDR_TYPE.PUBLIC.value,
                             api.BLE_GAP_ADDR_TYPE.PUBLIC.value,
                             bytes.fromhex(self.pts_address_b.decode())[::-1],
                             api.BLE_GAP_ADV.CHANNEL_ALL.value,
                             api.BLE_GAP_ADV.FILTER_POLICY_DEFAULT.value])

        if not self.advertising(advData=AdvData, advParam=AdvParam, EnDisable=api.BLE_GAP_ADV.ENABLE):
            return False

        if self.casename_b == b'GAP/DISC/GENM/BV-01-C' or \
           self.casename_b == b'GAP/DISC/GENM/BV-03-C':
            return

        conninfo = self.get_connetion_info()

        if not conninfo:
            return False

        self.conninfo = conninfo

        return

    def mmi52(self,descript):
        logger.info(''.join(['\n', descript,'\n']))

        AdvData = b''.join([len(api.BLE_GAP_ADV.DATATYPE_Flags.value
                            + api.BLE_GAP_ADV.Flags_General_Discover.value).to_bytes(1,'big'),
                            api.BLE_GAP_ADV.DATATYPE_Flags.value,
                            api.BLE_GAP_ADV.Flags_General_Discover.value])

        if self.casename_b == b'GAP/DISC/GENM/BV-04-C':
            AdvData = b''.join([len(api.BLE_GAP_ADV.DATATYPE_Flags.value
                                + api.BLE_GAP_ADV.Flags_LE_General_Discover.value).to_bytes(1,'big'),
                                api.BLE_GAP_ADV.DATATYPE_Flags.value,
                                api.BLE_GAP_ADV.Flags_LE_General_Discover.value])

        AdvParam = b''.join([b'\x00\x20\x00\x20',
                             api.BLE_GAP_ADV.TYPE_ADV_IND.value,
                             api.BLE_GAP_ADDR_TYPE.PUBLIC.value,
                             api.BLE_GAP_ADDR_TYPE.PUBLIC.value,
                             bytes.fromhex(self.pts_address_b.decode())[::-1],
                             api.BLE_GAP_ADV.CHANNEL_ALL.value,
                             api.BLE_GAP_ADV.FILTER_POLICY_DEFAULT.value])

        if not self.advertising(advData=AdvData, advParam=AdvParam, EnDisable=api.BLE_GAP_ADV.ENABLE):
            return False

        if self.casename_b == b'GAP/DISC/GENM/BV-02-C' or \
           self.casename_b == b'GAP/DISC/GENM/BV-04-C':
            return

        conninfo = self.get_connetion_info()

        if not conninfo:
            return False

        self.conninfo = conninfo

        return

    def mmi53(self,descript):
        logger.info(''.join(['\n', descript,'\n']))
        return True

    def mmi54(self,descript):
        logger.info(''.join(['\n', descript,'\n']))

        AdvData = b''.join([len(api.BLE_GAP_ADV.DATATYPE_Flags.value
                            + api.BLE_GAP_ADV.Flags_General_Discover.value).to_bytes(1,'big'),
                            api.BLE_GAP_ADV.DATATYPE_Flags.value,
                            api.BLE_GAP_ADV.Flags_General_Discover.value])

        AdvParam = b''.join([b'\x00\x20\x00\x20',
                                 api.BLE_GAP_ADV.TYPE_ADV_NONCONN_IND.value,
                                 api.BLE_GAP_ADDR_TYPE.PUBLIC.value,
                                 api.BLE_GAP_ADDR_TYPE.PUBLIC.value,
                                 bytes.fromhex(self.pts_address_b.decode())[::-1],
                                 api.BLE_GAP_ADV.CHANNEL_ALL.value,
                                 api.BLE_GAP_ADV.FILTER_POLICY_DEFAULT.value])

        if not self.advertising(advData=AdvData, advParam=AdvParam, EnDisable=api.BLE_GAP_ADV.ENABLE):
            return False

    def mmi55(self,descript):
        logger.info(f'\n{descript}\n')

        AdvData = b''.join([len(api.BLE_GAP_ADV.DATATYPE_Flags.value
                                + api.BLE_GAP_ADV.Flags_Limited_Discover.value).to_bytes(1, 'big'),
                            api.BLE_GAP_ADV.DATATYPE_Flags.value,
                            api.BLE_GAP_ADV.Flags_Limited_Discover.value])

        AdvParam = b''.join([b'\x00\x20\x00\x20',
                             api.BLE_GAP_ADV.TYPE_ADV_NONCONN_IND.value,
                             api.BLE_GAP_ADDR_TYPE.PUBLIC.value,
                             api.BLE_GAP_ADDR_TYPE.PUBLIC.value,
                             bytes.fromhex(self.pts_address_b.decode())[::-1],
                             api.BLE_GAP_ADV.CHANNEL_ALL.value,
                             api.BLE_GAP_ADV.FILTER_POLICY_DEFAULT.value])

        if not self.advertising(advData=AdvData, advParam=AdvParam, EnDisable=api.BLE_GAP_ADV.ENABLE):
            return False

    def mmi59(self,descript):
        logger.info(''.join(['\n', descript,'\n']))
        return True

    def mmi60(self,descript):
        logger.info(''.join(['\n', descript,'\n']))

        AdvData = b''.join([len(api.BLE_GAP_ADV.DATATYPE_Flags.value
                            + api.BLE_GAP_ADV.Flags_General_Discover.value).to_bytes(1,'big'),
                            api.BLE_GAP_ADV.DATATYPE_Flags.value,
                            api.BLE_GAP_ADV.Flags_General_Discover.value])

        AdvParam = b''.join([b'\x00\x20\x00\x20',
                                 api.BLE_GAP_ADV.TYPE_ADV_DIRECT_IND.value,
                                 api.BLE_GAP_ADDR_TYPE.PUBLIC.value,
                                 api.BLE_GAP_ADDR_TYPE.PUBLIC.value,
                                 bytes.fromhex(self.pts_address_b.decode())[::-1],
                                 api.BLE_GAP_ADV.CHANNEL_ALL.value,
                                 api.BLE_GAP_ADV.FILTER_POLICY_DEFAULT.value])

        if not self.advertising(advData=AdvData, advParam=AdvParam, EnDisable=api.BLE_GAP_ADV.ENABLE):
            return False

    def mmi72(self,descript):
        logger.info(''.join(['\n', descript,'\n']))
        AdvData = b''.join([len(api.BLE_GAP_ADV.DATATYPE_Flags.value
                                + api.BLE_GAP_ADV.Flags_Non_Discover.value).to_bytes(1, 'big'),
                            api.BLE_GAP_ADV.DATATYPE_Flags.value,
                            api.BLE_GAP_ADV.Flags_Non_Discover.value])

        AdvParam = b''.join([b'\x00\x20\x00\x20',
                             api.BLE_GAP_ADV.TYPE_ADV_IND.value,
                             api.BLE_GAP_ADDR_TYPE.PUBLIC.value,
                             api.BLE_GAP_ADDR_TYPE.PUBLIC.value,
                             bytes.fromhex(self.pts_address_b.decode())[::-1],
                             api.BLE_GAP_ADV.CHANNEL_ALL.value,
                             api.BLE_GAP_ADV.FILTER_POLICY_DEFAULT.value])

        if not self.advertising(advData=AdvData, advParam=AdvParam, EnDisable=api.BLE_GAP_ADV.ENABLE):
            return False

    def mmi73(self,descript):
        logger.info(f'\n{descript}\n')

        startHandle = b'\x00\x01'
        endHandle   = b'\xFF\xFF'
        UUID        = b'\x2A\x00'
        readUUID    = b''.join([self.conninfo['connhandle'],
                                startHandle,
                                endHandle,
                                len(UUID).to_bytes(1,'big'),
                                UUID])

        if self.CommandRW(COMMAND = [api.Layer_ID.BLE_GATT,
                                     api.GATT_CMD_ID.READ_USING_UUID,
                                     readUUID],
                          EVENT   = [api.Layer_ID.BLE_GATT,
                                     api.GATT_Event_ID.READ_USING_UUID_RESP,
                                     self.conninfo['connhandle']]):
            return
        else:
            return False

    def mmi74(self,descript):
        logger.info(''.join(['\n', descript,'\n']))

        AdvData = b''.join([len(api.BLE_GAP_ADV.DATATYPE_Flags.value
                            + api.BLE_GAP_ADV.Flags_Non_Discover.value).to_bytes(1,'big'),
                            api.BLE_GAP_ADV.DATATYPE_Flags.value,
                            api.BLE_GAP_ADV.Flags_Non_Discover.value])

        AdvParam = b''.join([b'\x00\x20\x00\x20',
                                 api.BLE_GAP_ADV.TYPE_ADV_IND.value,
                                 api.BLE_GAP_ADDR_TYPE.PUBLIC.value,
                                 api.BLE_GAP_ADDR_TYPE.PUBLIC.value,
                                 bytes.fromhex(self.pts_address_b.decode())[::-1],
                                 api.BLE_GAP_ADV.CHANNEL_ALL.value,
                                 api.BLE_GAP_ADV.FILTER_POLICY_DEFAULT.value])

        if not self.advertising(advData=AdvData, advParam=AdvParam, EnDisable=api.BLE_GAP_ADV.ENABLE):
            return False

        time.sleep(1)

        conninfo = self.get_connetion_info()
        if not conninfo:
            return False
        else:
            self.conninfo = conninfo
            return

    def mmi75(self,descript):
        logger.info(''.join(['\n', descript,'\n']))

        AdvData = b''.join([len(api.BLE_GAP_ADV.DATATYPE_Flags.value
                            + api.BLE_GAP_ADV.Flags_General_Discover.value).to_bytes(1,'big'),
                            api.BLE_GAP_ADV.DATATYPE_Flags.value,
                            api.BLE_GAP_ADV.Flags_General_Discover.value])

        AdvParam = b''.join([b'\x00\x20\x00\x20',
                                 api.BLE_GAP_ADV.TYPE_ADV_IND.value,
                                 api.BLE_GAP_ADDR_TYPE.PUBLIC.value,
                                 api.BLE_GAP_ADDR_TYPE.PUBLIC.value,
                                 bytes.fromhex(self.pts_address_b.decode())[::-1],
                                 api.BLE_GAP_ADV.CHANNEL_ALL.value,
                                 api.BLE_GAP_ADV.FILTER_POLICY_DEFAULT.value])

        if not self.advertising(advData=AdvData, advParam=AdvParam, EnDisable=api.BLE_GAP_ADV.ENABLE):
            return False

        time.sleep(1)

        conninfo = self.get_connetion_info()
        if not conninfo:
            return False
        else:
            self.conninfo = conninfo
            return

    def mmi76(self,descript):
        logger.info(''.join(['\n', descript,'\n']))

        AdvData = b''.join([len(api.BLE_GAP_ADV.DATATYPE_Flags.value
                            + api.BLE_GAP_ADV.Flags_Limited_Discover.value).to_bytes(1,'big'),
                            api.BLE_GAP_ADV.DATATYPE_Flags.value,
                            api.BLE_GAP_ADV.Flags_Limited_Discover.value])

        AdvParam = b''.join([b'\x00\x20\x00\x20',
                                 api.BLE_GAP_ADV.TYPE_ADV_IND.value,
                                 api.BLE_GAP_ADDR_TYPE.PUBLIC.value,
                                 api.BLE_GAP_ADDR_TYPE.PUBLIC.value,
                                 bytes.fromhex(self.pts_address_b.decode())[::-1],
                                 api.BLE_GAP_ADV.CHANNEL_ALL.value,
                                 api.BLE_GAP_ADV.FILTER_POLICY_DEFAULT.value])

        if not self.advertising(advData=AdvData, advParam=AdvParam, EnDisable=api.BLE_GAP_ADV.ENABLE):
            return False

        time.sleep(1)

        conninfo = self.get_connetion_info()

        if not conninfo:
            return False

        self.conninfo = conninfo

        return

    def mmi77(self,descript):
        logger.info(f'\n{descript}\n')

        if self.casename_b == b'GAP/DM/CON/BV-01-C' or \
           self.casename_b == b'GAP/DM/BON/BV-01-C' or \
           self.casename_b == b'GAP/MOD/CON/BV-01-C':
            return

        if self.conninfo['layer'] == api.Layer_ID.BT_GAP.value:

            if self.CommandRW(COMMAND = [api.Layer_ID.BT_GAP,
                                         api.BT_GAP_CMD_ID.DISCONNECT,
                                         self.conninfo['connhandle']],
                              EVENT   = [api.Layer_ID.BT_GAP,
                                         api.BT_GAP_Event_ID.DISCONNECTED,
                                         api.BT_GAP_Status_ID.SUCCESS]):
                return
            else:
                return False

        terminate = b''.join([self.conninfo['connhandle'],
                              api.BLE_GAP_DISC_REASON.REMOTE_TERMINATE.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.BLE_GAP,
                                     api.BLE_GAP_CMD_ID.TERMINATE_CONNECTION,
                                     terminate],
                          EVENT   = [api.Layer_ID.BLE_GAP,
                                     api.BLE_GAP_Event_ID.DISCONNECTED,
                                     self.conninfo['connhandle']]):
            return
        else:
            return False

    def mmi78(self,descript):
        logger.info(f'\n{descript}\n')

        if self.casename_b == b'GAP/SEC/AUT/BV-12-C' or \
           self.casename_b == b'GAP/SEC/AUT/BV-13-C':
            config = b''.join([api.SMP_IoCapability.DISPLAYONLY.value,
                               api.SMP_AuthReqFlag.BONDINGMITM.value,
                               api.SMP_OOB.NOT_PRESENT.value,
                               api.SMP_SECURE_SET.NOSECURE.value])

            if not self.CommandRW(COMMAND = [api.Layer_ID.BLE_SMP,
                                             api.SMP_CMD_ID.CONFIG,
                                             config],
                                  EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                             api.Layer_ID.BLE_SMP,
                                             api.SMP_CMD_ID.CONFIG]):
                return False

        conninfo = self.create_connection('BLE')

        if not conninfo:
            return False

        if self.casename_b == b'GAP/BOND/NBON/BV-01-C' or \
           self.casename_b == b'GAP/BOND/BON/BV-02-C' or \
           self.casename_b == b'GAP/DM/NBON/BV-01-C':
            if self.conninfo:
                self.conninfo = conninfo
                return [None,'mmi']
            else:
                self.conninfo = conninfo
                return

        if self.casename_b == b'GAP/BOND/BON/BV-04-C' or \
           self.casename_b == b'GAP/SEC/AUT/BV-13-C' or \
           self.casename_b == b'GAP/SEC/AUT/BV-24-C':
            if self.conninfo:
                self.conninfo = conninfo
                return
            else:
                self.conninfo = conninfo
                return [None,'mmi']

        self.conninfo = conninfo
        return

    def mmi82(self,descript):
        logger.info(''.join(['\n', descript,'\n']))
        return True

    def mmi83(self,descript):
        logger.info(''.join(['\n', descript,'\n']))
        return True

    def mmi84(self,descript):
        logger.info(''.join(['\n', descript,'\n']))
        return True

    def mmi85(self,descript):
        logger.info(''.join(['\n', descript,'\n']))
        return True

    def mmi86(self,descript):
        logger.info(''.join(['\n', descript,'\n']))

        clockOffset   = b'\x00\x00'
        remoteNameReq = b''.join([bytes.fromhex(self.pts_address_b.decode())[::-1],
                                  api.BT_GAP_PAGE_SCAN_REPETITION.R0.value,
                                  clockOffset])

        remoteNameCmp = b''.join([api.BT_GAP_Status_ID.SUCCESS.value,
                                  bytes.fromhex(self.pts_address_b.decode())[::-1],
                                  b'PTS-GAP'])

        if self.CommandRW(COMMAND = [api.Layer_ID.BT_GAP,
                                     api.BT_GAP_CMD_ID.REMOTE_NAME_REQUEST,
                                     remoteNameReq],
                          EVENT   = [api.Layer_ID.BT_GAP,
                                     api.BT_GAP_Event_ID.REMOTE_NAME_REQUEST_COMPLETE,
                                     remoteNameCmp]):
            return True
        else:
            return False

    def mmi91(self,descript):
        logger.info(''.join(['\n', descript,'\n']))

        if self.casename_b == b'GAP/SEC/AUT/BV-11-C' or \
           self.casename_b == b'GAP/SEC/AUT/BV-14-C':
            config = b''.join([api.SMP_IoCapability.DISPLAYONLY.value,
                               api.SMP_AuthReqFlag.BONDING.value,
                               api.SMP_OOB.NOT_PRESENT.value,
                               api.SMP_SECURE_SET.NOSECURE.value])

            if not self.CommandRW(COMMAND = [api.Layer_ID.BLE_SMP,
                                         api.SMP_CMD_ID.CONFIG,
                                         config],
                              EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                         api.Layer_ID.BLE_SMP,
                                         api.SMP_CMD_ID.CONFIG]):
                return False

        AdvData = b''.join([len(api.BLE_GAP_ADV.DATATYPE_Flags.value
                            + api.BLE_GAP_ADV.Flags_General_Discover.value).to_bytes(1,'big'),
                            api.BLE_GAP_ADV.DATATYPE_Flags.value,
                            api.BLE_GAP_ADV.Flags_General_Discover.value])

        AdvParam = b''.join([b'\x00\x20\x00\x20',
                                 api.BLE_GAP_ADV.TYPE_ADV_IND.value,
                                 api.BLE_GAP_ADDR_TYPE.PUBLIC.value,
                                 api.BLE_GAP_ADDR_TYPE.PUBLIC.value,
                                 bytes.fromhex(self.pts_address_b.decode())[::-1],
                                 api.BLE_GAP_ADV.CHANNEL_ALL.value,
                                 api.BLE_GAP_ADV.FILTER_POLICY_DEFAULT.value])

        if not self.advertising(advData=AdvData, advParam=AdvParam, EnDisable=api.BLE_GAP_ADV.ENABLE):
            return False

        time.sleep(1)

        conninfo = self.get_connetion_info()
        if not conninfo:
            return False

        if self.casename_b == b'GAP/SEC/AUT/BV-20-C' or \
           self.casename_b == b'GAP/SEC/AUT/BV-22-C' or \
           self.casename_b == b'GAP/SEC/AUT/BV-23-C':
            if self.conninfo:
                self.conninfo = conninfo
                return
            else:
                self.conninfo = conninfo
                return [None,'mmi']

        self.conninfo = conninfo

        return

    def mmi100(self,descript):
        logger.info(f'\n{descript}\n')

        config = b''.join([api.SMP_IoCapability.NOINPUTNOOUTPUT.value,
                           api.SMP_AuthReqFlag.NOBONDING.value,
                           api.SMP_OOB.NOT_PRESENT.value,
                           api.SMP_SECURE_SET.NOSECURE.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.BLE_SMP,
                                     api.SMP_CMD_ID.CONFIG,
                                     config],
                          EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                     api.Layer_ID.BLE_SMP,
                                     api.SMP_CMD_ID.CONFIG]):
            if self.CommandRW(COMMAND = [api.Layer_ID.BLE_SMP,
                                         api.SMP_CMD_ID.INIT_PAIR,
                                         self.conninfo['connhandle']],
                              EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                         api.Layer_ID.BLE_SMP,
                                         api.SMP_CMD_ID.INIT_PAIR]):
                return
            else:
                return False
        else:
            return False

    def mmi101(self,descript):
        logger.info(''.join(['\n', descript,'\n']))

        AdvData = b''.join([len(api.BLE_GAP_ADV.DATATYPE_Flags.value
                                + api.BLE_GAP_ADV.Flags_General_Discover.value).to_bytes(1, 'big'),
                            api.BLE_GAP_ADV.DATATYPE_Flags.value,
                            api.BLE_GAP_ADV.Flags_General_Discover.value])

        AdvParam = b''.join([b'\x00\x20\x00\x20',
                             api.BLE_GAP_ADV.TYPE_ADV_IND.value,
                             api.BLE_GAP_ADDR_TYPE.PUBLIC.value,
                             api.BLE_GAP_ADDR_TYPE.PUBLIC.value,
                             bytes.fromhex(self.pts_address_b.decode())[::-1],
                             api.BLE_GAP_ADV.CHANNEL_ALL.value,
                             api.BLE_GAP_ADV.FILTER_POLICY_DEFAULT.value])

        if self.advertising(advData=AdvData, advParam=AdvParam, EnDisable=api.BLE_GAP_ADV.ENABLE):
            return True
        else:
            return False

    def mmi102(self,descript):
        logger.info(f'\n{descript}\n')

        conninfo = self.create_connection('BT')

        if not conninfo:
            return False

        self.conninfo = conninfo

    def mmi103(self,descript):
        logger.info(f'\n{descript}\n')

        conninfo = self.create_connection('BT')

        if not conninfo:
            return False

        self.conninfo = conninfo

        OpenChanReq  = b''.join([self.conninfo['connhandle'],
                                 bytes.fromhex(self.ixit[b'TSPX_psm'][1].decode()),
                                 len(api.BT_L2CAP_CONF_OPTIONS.MTU.value).to_bytes(1,'big'),
                                 api.BT_L2CAP_CONF_OPTIONS.MTU.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.BT_L2CAP,
                                     api.BT_L2CAP_CMD_ID.OPEN_CHAN_REQ,
                                     OpenChanReq],
                          EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                     api.Layer_ID.BT_L2CAP,
                                     api.BT_L2CAP_CMD_ID.OPEN_CHAN_REQ]):
            return
        else:
            return False

    def mmi104(self,descript):
        logger.info(f'\n{descript}\n')

        if self.casename_b == b'GAP/DM/NBON/BV-01-C':
            secMode = b''.join([api.BT_GAP_SECURITY.MODE_4.value,
                                api.BT_GAP_AUTH_REQUIREMENT.MITM_NOT_REQUIRED_NO_BONDING.value,
                                api.BT_GAP_IOCAPABILITY.NOINPUTNOOUTPUT.value])

            if self.CommandRW(COMMAND = [api.Layer_ID.BT_GAP,
                                         api.BT_GAP_CMD_ID.SET_CONNECTION_SECURITY,
                                         secMode],
                              EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                         api.Layer_ID.BT_GAP,
                                         api.BT_GAP_CMD_ID.SET_CONNECTION_SECURITY]):
                if self.conninfo:
                    return [True,'mmi']
                else:
                    return True

        config = b''.join([api.SMP_IoCapability.NOINPUTNOOUTPUT.value,
                           api.SMP_AuthReqFlag.NOBONDING.value,
                           api.SMP_OOB.NOT_PRESENT.value,
                           api.SMP_SECURE_SET.NOSECURE.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.BLE_SMP,
                                     api.SMP_CMD_ID.CONFIG,
                                     config],
                          EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                     api.Layer_ID.BLE_SMP,
                                     api.SMP_CMD_ID.CONFIG]):
            return [True,'mmi']

    def mmi105(self,descript):
        logger.info(f'\n{descript}\n')

        if self.CommandRW(COMMAND = [api.Layer_ID.BT_GAP,
                                     api.BT_GAP_CMD_ID.WRITE_SCAN_ENABLE,
                                     api.BT_GAP_SCAN_ENABLE.INQUIRY_SCAN_ENABLE_PAGE_SCAN_ENABLE],
                          EVENT   = [api.Layer_ID.BT_GAP,
                                     api.BT_GAP_Event_ID.COMMAND_COMPLETE,
                                     api.BT_GAP_Cmd_Complete_ID.WRITE_SCAN_ENABLE]):
            return True
        else:
            return False

    def mmi106(self,descript):
        logger.info(f'\n{descript}\n')

        if self.CommandRW(COMMAND = [api.Layer_ID.BLE_SMP,
                                     api.SMP_CMD_ID.INIT_PAIR,
                                     self.conninfo['connhandle']],
                          EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                     api.Layer_ID.BLE_SMP,
                                     api.SMP_CMD_ID.INIT_PAIR]):
            return
        else:
            return False

    def mmi108(self,descript):
        logger.info(f'\n{descript}\n')

        if self.casename_b == b'GAP/SEC/AUT/BV-21-C' and self.conninfo['bonded'] == b'\x00':
            if self.CommandRW(COMMAND = [api.Layer_ID.BLE_GAP,
                                         api.BLE_GAP_CMD_ID.START_ENCRYPTION,
                                         self.conninfo['connhandle']],
                              EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                         api.Layer_ID.BLE_GAP,
                                         api.BLE_GAP_CMD_ID.START_ENCRYPTION]):
                return
            else:
                return False

        if self.casename_b == b'GAP/DM/BON/BV-01-C':
            if self.CommandRW(COMMAND = [api.Layer_ID.BLE_SMP,
                                         api.SMP_CMD_ID.INIT_PAIR,
                                         self.conninfo['connhandle']],
                              EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                         api.Layer_ID.BLE_SMP,
                                         api.SMP_CMD_ID.INIT_PAIR]):
                return
            else:
                return False

        config = b''.join([api.SMP_IoCapability.NOINPUTNOOUTPUT.value,
                           api.SMP_AuthReqFlag.BONDING.value,
                           api.SMP_OOB.NOT_PRESENT.value,
                           api.SMP_SECURE_SET.NOSECURE.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.BLE_SMP,
                                     api.SMP_CMD_ID.CONFIG,
                                     config],
                          EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                     api.Layer_ID.BLE_SMP,
                                     api.SMP_CMD_ID.CONFIG]):
            if self.CommandRW(COMMAND = [api.Layer_ID.BLE_SMP,
                                         api.SMP_CMD_ID.INIT_PAIR,
                                         self.conninfo['connhandle']],
                              EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                         api.Layer_ID.BLE_SMP,
                                         api.SMP_CMD_ID.INIT_PAIR]):
                return
            else:
                return False
        else:
            return False

    def mmi112(self,descript):
        logger.info(f'\n{descript}\n')

        charHandle = bytes()
        if descript.find('handle') != -1:
            handle_index = descript.find('handle') + 9
            charHandle = bytes.fromhex(descript[handle_index:handle_index+4])

        read    = b''.join([self.conninfo['connhandle'],
                            charHandle,
                            bytes(2)])

        if self.CommandRW(COMMAND = [api.Layer_ID.BLE_GATT,
                                     api.GATT_CMD_ID.READ,
                                     read],
                          EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                     api.Layer_ID.BLE_GATT,
                                     api.MBA_RES.SUCCESS]):
            return
        else:
            return False

    def mmi114(self,descript):
        logger.info(f'\n{descript}\n')

        parameter = b''.join([self.conninfo['connhandle'],
                              bytes.fromhex(self.ixit[b'TSPX_con_interval_min'][1].decode()),
                              self.conninfo['connpara']])

        if self.CommandRW(COMMAND = [api.Layer_ID.BLE_L2CAP,
                                     api.BLE_L2CAP_CMD_ID.BLE_CPU,
                                     parameter],
                          EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                     api.Layer_ID.BLE_L2CAP,
                                     api.BLE_L2CAP_CMD_ID.BLE_CPU]):
            time.sleep((int(self.ixit[b'TSPX_iut_connection_parameter_timeout'][1]) / 1000))
            return
        else:
            return False

    def mmi117(self,descript):
        logger.info(''.join(['\n', descript,'\n']))
        return True

    def mmi118(self,descript):
        logger.info(''.join(['\n', descript,'\n']))
        return True

    def mmi120(self,descript):
        logger.info(''.join(['\n', descript,'\n']))
        return True

    def mmi121(self,descript):
        logger.info(f'\n{descript}\n')
        return True

    def mmi122(self,descript):
        logger.info(''.join(['\n', descript,'\n']))
        return True

    def mmi123(self,descript):
        logger.info(''.join(['\n', descript,'\n']))
        if not self.iut_white_list_init():
            return False

        IntervalWindow = b'\x00\x10\x00\x10'

        ScanParam = b''.join([api.BLE_GAP_SCAN.TYPE_ACTIVE_SCAN.value,
                              IntervalWindow,
                              api.BLE_GAP_ADDR_TYPE.PUBLIC.value,
                              api.BLE_GAP_SCAN.FILTER_POLICY_WHITELIST.value])

        ScanMode = b''.join([api.BLE_GAP_SCAN.ENABLE.value,
                             api.BLE_GAP_SCAN.FILTER_DUPLICATES_ENABLE.value,
                             api.BLE_GAP_SCAN.MODE_LIMITED_DISCOVERY.value])

        if self.set_scanning(scanParam=ScanParam, scanMode=ScanMode):
            AdvReport = b''.join([api.BLE_GAP_ADV.EVENTTYPE_ADV_SCAN_IND.value,
                                  api.BLE_GAP_ADDR_TYPE.PUBLIC.value,
                                  bytes.fromhex(self.pts_address_b.decode())[::-1]])

            advReport = self.CommandRW(EVENT = [api.Layer_ID.BLE_GAP,
                                                api.BLE_GAP_Event_ID.ADVERTISING_REPORT,
                                                AdvReport],
                                       back = True)

            if not advReport:
                ScanMode = b''.join([api.BLE_GAP_SCAN.DISABLE.value,
                             api.BLE_GAP_SCAN.FILTER_DUPLICATES_DISABLE.value,
                             api.BLE_GAP_SCAN.MODE_LIMITED_DISCOVERY.value])

                if self.set_scanning(scanMode=ScanMode):
                    return True
                else:
                    return False
            else:
                return False

    def mmi124(self,descript):
        logger.info(f'\n{descript}\n')
        return True

    def mmi126(self,descript):
        logger.info(f'\n{descript}\n')

        conninfo = self.create_connection('BT')

        if not conninfo:
            return False

        self.conninfo = conninfo

    def mmi127(self,descript):
        logger.info(f'\n{descript}\n')

        parameter = b''.join([self.conninfo['connhandle'],
                              bytes.fromhex(self.ixit[b'TSPX_con_interval_min'][1].decode()),
                              bytes.fromhex(self.ixit[b'TSPX_con_interval_max'][1].decode()),
                              bytes.fromhex(self.ixit[b'TSPX_iut_valid_connection_latency'][1].decode()),
                              bytes.fromhex(self.ixit[b'TSPX_conn_update_supervision_timeout'][1].decode()),
                              bytes.fromhex(self.ixit[b'TSPX_minimum_ce_length'][1].decode()),
                              bytes.fromhex(self.ixit[b'TSPX_maximum_ce_length'][1].decode())])

        if self.CommandRW(COMMAND = [api.Layer_ID.BLE_GAP,
                                     api.BLE_GAP_CMD_ID.UPDATE_CONN_PARA,
                                     parameter],
                          EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                     api.Layer_ID.BLE_GAP,
                                     api.BLE_GAP_CMD_ID.UPDATE_CONN_PARA]):
            return
        else:
            return False

    def mmi139(self,descript):
        logger.info(f'\n{descript}\n')

        if self.casename_b == b'GAP/SEC/AUT/BV-12-C' or \
           self.casename_b == b'GAP/SEC/AUT/BV-13-C':
            logger.debug(f"Handle :{b'005E'}")
            return [b'005E','mmi']
        else:
            logger.debug(f"Handle :{b'005E'}")
            return b'005E'

    def mmi143(self,descript):
        logger.info(f'\n{descript}\n')
        if self.CommandRW(EVENT = [api.Layer_ID.UTILITY,
                                   api.UTILITY_Event_ID.REMOTE_BOND_LOST,
                                   b'\x00']):
            return True
        else:
            return False

    def mmi144(self,descript):
        logger.info(f'\n{descript}\n')
        logger.debug(f"Handle :{b'005C'}")

        if self.casename_b == b'GAP/SEC/AUT/BV-24-C':
            return [b'005C','mmi']

        return b'005C'

    def mmi145(self,descript):
        logger.info(f'\n{descript}\n')
        time.sleep(70)
        return

    def mmi146(self,descript):
        logger.info(f'\n{descript}\n')

        address = list()

        numRsp = b'\x00'
        lap_GIAC = b''.join([api.BT_GAP_LAP.GIAC.value,
                             api.BT_GAP_INQUIRY_TIME.MAX.value,
                             numRsp])

        self.CommandRW(COMMAND=[api.Layer_ID.BT_GAP,
                                api.BT_GAP_CMD_ID.INQUIRY,
                                lap_GIAC])
        while 1:
            inquiryComplete = b''.join([api.Layer_ID.BT_GAP.value,
                                        api.BT_GAP_Event_ID.INQUIRY_COMPLETE.value,
                                        api.BT_GAP_Cmd_Status_ID.INQUIRY.value])

            inquiryResult   = b''.join([api.Layer_ID.BT_GAP.value,
                                        api.BT_GAP_Event_ID.INQUIRY_RESULT.value])

            event = self.readEvent()

            if event == False:
                return False

            if event == inquiryComplete:
                break

            if event[:2] == inquiryResult:
                address.append(event[3:9][::-1])
                continue

        if bytes.fromhex(self.pts_address_b.decode()) in address:
            return True
        else:
            return False

    def mmi147(self,descript):
        logger.info(f'\n{descript}\n')

        numRsp   = b'\x00'
        lap_LIAC = b''.join([api.BT_GAP_LAP.LIAC.value,
                             api.BT_GAP_INQUIRY_TIME.MAX.value,
                             numRsp])

        numRsp        = b'\x01'
        InquiryResult = b''.join([numRsp,
                                  bytes.fromhex(self.pts_address_b.decode())[::-1]])

        if self.CommandRW(COMMAND = [api.Layer_ID.BT_GAP,
                                     api.BT_GAP_CMD_ID.INQUIRY,
                                     lap_LIAC],
                          EVENT   = [api.Layer_ID.BT_GAP,
                                     api.BT_GAP_Event_ID.INQUIRY_RESULT,
                                     InquiryResult]):
            return True
        else:
            return False

    def mmi151(self, descript):
        logger.info(''.join(['\n', descript,'\n']))

        secMode = b''.join([api.BT_GAP_SECURITY.MODE_4.value,
                            api.BT_GAP_AUTH_REQUIREMENT.MITM_NOT_REQUIRED_GENERAL_BONDING.value,
                            api.BT_GAP_IOCAPABILITY.NOINPUTNOOUTPUT.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.BT_GAP,
                                     api.BT_GAP_CMD_ID.SET_CONNECTION_SECURITY,
                                     secMode],
                          EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                     api.Layer_ID.BT_GAP,
                                     api.BT_GAP_CMD_ID.SET_CONNECTION_SECURITY]):
                return True
        else:
            return False

    def mmi157(self,descript):
        logger.info(''.join(['\n', descript,'\n']))

        if not self.iut_white_list_init():
            return False

        IntervalWindow = b'\x00\x10\x00\x10'

        ScanParam = b''.join([api.BLE_GAP_SCAN.TYPE_ACTIVE_SCAN.value,
                              IntervalWindow,
                              api.BLE_GAP_ADDR_TYPE.PUBLIC.value,
                              api.BLE_GAP_SCAN.FILTER_POLICY_WHITELIST.value])

        ScanMode = b''.join([api.BLE_GAP_SCAN.ENABLE.value,
                             api.BLE_GAP_SCAN.FILTER_DUPLICATES_ENABLE.value,
                             api.BLE_GAP_SCAN.MODE_OBSERVER.value])

        if self.set_scanning(scanParam=ScanParam, scanMode=ScanMode):
            AdvReport = b''.join([api.BLE_GAP_ADV.EVENTTYPE_ADV_SCAN_IND.value,
                                  api.BLE_GAP_ADDR_TYPE.PUBLIC.value,
                                  bytes.fromhex(self.pts_address_b.decode())[::-1]])

            advReport = self.CommandRW(EVENT=[api.Layer_ID.BLE_GAP,
                                              api.BLE_GAP_Event_ID.ADVERTISING_REPORT,
                                              AdvReport],
                                       back=True)
            if not advReport:
                logger.error('...no received an advertising event...')
                return False

            scanInd = self.adv_report_paser(advReport)

            AdvReport = b''.join([api.BLE_GAP_ADV.EVENTTYPE_ADV_SCAN_RSP.value,
                                  api.BLE_GAP_ADDR_TYPE.PUBLIC.value,
                                  bytes.fromhex(self.pts_address_b.decode())[::-1]])

            advReport = self.CommandRW(EVENT=[api.Layer_ID.BLE_GAP,
                                              api.BLE_GAP_Event_ID.ADVERTISING_REPORT,
                                              AdvReport],
                                       back=True)
            if not advReport:
                logger.error('...no received an advertising event...')
                return False

            scanRsp = self.adv_report_paser(advReport)

            if scanInd['advData'].hex().upper() and scanRsp['advData'].hex().upper() in descript:

                ScanMode = b''.join([api.BLE_GAP_SCAN.DISABLE.value,
                                     api.BLE_GAP_SCAN.FILTER_DUPLICATES_DISABLE.value,
                                     api.BLE_GAP_SCAN.MODE_OBSERVER.value])

                if self.set_scanning(scanMode=ScanMode):
                    return True
                else:
                    return False
            else:
                return False
        else:
            return False

    def mmi158(self,descript):
        logger.info(''.join(['\n', descript,'\n']))
        if self.casename_b == b'GAP/IDLE/NAMP/BV-01-C':
             return True
        return False

    def mmi160(self,descript):
        logger.info(f'\n{descript}\n')

        numCurrentIac = b'\x01'
        lap_LIAC      = b''.join([numCurrentIac,
                                  api.BT_GAP_LAP.LIAC.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.BT_GAP,
                                     api.BT_GAP_CMD_ID.WRITE_IAC_LAP,
                                     lap_LIAC],
                          EVENT   = [api.Layer_ID.BT_GAP,
                                     api.BT_GAP_Event_ID.COMMAND_COMPLETE,
                                     api.BT_GAP_Cmd_Complete_ID.WRITE_CURRENT_IAC_LAP]):
            if self.CommandRW(COMMAND = [api.Layer_ID.BT_GAP,
                                         api.BT_GAP_CMD_ID.WRITE_SCAN_ENABLE,
                                         api.BT_GAP_SCAN_ENABLE.INQUIRY_SCAN_ENABLE_PAGE_SCAN_ENABLE],
                              EVENT   = [api.Layer_ID.BT_GAP,
                                         api.BT_GAP_Event_ID.COMMAND_COMPLETE,
                                         api.BT_GAP_Cmd_Complete_ID.WRITE_SCAN_ENABLE]):
                self.wait = 25
                return [None, 'mmi']
            else:
                return False
        else:
            return False

    def mmi162(self,descript):
        logger.info(f'\n{descript}\n')

        parameter    = b''.join([self.conninfo['connhandle'],
                                 bytes.fromhex(self.ixit[b'TSPX_con_interval_min'][1].decode()),
                                 self.conninfo['connpara']])

        if self.CommandRW(COMMAND = [api.Layer_ID.BLE_L2CAP,
                                     api.BLE_L2CAP_CMD_ID.BLE_CPU,
                                     parameter],
                          EVENT   = [api.Layer_ID.BLE_L2CAP,
                                     api.BLE_L2CAP_Event_ID.CONN_PARA_UPDATE_RSP,
                                     self.conninfo['connhandle']]):
            return
        else:
            return False

    def mmi164(self,descript):
        logger.info(''.join(['\n', descript,'\n']))
        return True

    def mmi165(self,descript):
        logger.info(''.join(['\n', descript,'\n']))

        clockOffset   = b'\x00\x00'
        remoteNameReq = b''.join([bytes.fromhex(self.pts_address_b.decode())[::-1],
                                  api.BT_GAP_PAGE_SCAN_REPETITION.R0.value,
                                  clockOffset])

        remoteNameCmp = b''.join([api.BT_GAP_Status_ID.SUCCESS.value,
                                  bytes.fromhex(self.pts_address_b.decode())[::-1],
                                  b'PTS-GAP'])

        if self.CommandRW(COMMAND = [api.Layer_ID.BT_GAP,
                                     api.BT_GAP_CMD_ID.REMOTE_NAME_REQUEST,
                                     remoteNameReq],
                          EVENT   = [api.Layer_ID.BT_GAP,
                                     api.BT_GAP_Event_ID.REMOTE_NAME_REQUEST_COMPLETE,
                                     remoteNameCmp]):
            return True
        else:
            return False

    def mmi166(self,descript):
        logger.info(''.join(['\n', descript,'\n']))
        secMode = bytes()

        if self.casename_b == b'GAP/SEC/SEM/BV-04-C' or \
           self.casename_b == b'GAP/SEC/SEM/BV-07-C' or \
           self.casename_b == b'GAP/SEC/SEM/BV-08-C':
            secMode = b''.join([api.BT_GAP_SECURITY.MODE_4.value,
                                api.BT_GAP_AUTH_REQUIREMENT.MITM_NOT_REQUIRED_GENERAL_BONDING.value,
                                api.BT_GAP_IOCAPABILITY.NOINPUTNOOUTPUT.value])

        if self.casename_b == b'GAP/SEC/SEM/BV-05-C' or \
           self.casename_b == b'GAP/SEC/SEM/BV-06-C' or \
           self.casename_b == b'GAP/SEC/SEM/BV-09-C' or \
           self.casename_b == b'GAP/SEC/SEM/BV-10-C':
            secMode = b''.join([api.BT_GAP_SECURITY.MODE_4.value,
                                api.BT_GAP_AUTH_REQUIREMENT.MITM_NOT_REQUIRED_NO_BONDING.value,
                                api.BT_GAP_IOCAPABILITY.NOINPUTNOOUTPUT.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.BT_GAP,
                                     api.BT_GAP_CMD_ID.SET_CONNECTION_SECURITY,
                                     secMode],
                          EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                     api.Layer_ID.BT_GAP,
                                     api.BT_GAP_CMD_ID.SET_CONNECTION_SECURITY]):
            if self.casename_b == b'GAP/SEC/SEM/BV-04-C':
                return [True,'mmi']
            else:
                return True
        else:
            return False

    def mmi169(self,descript):
        logger.info(''.join(['\n', descript,'\n']))
        if not self.iut_white_list_init():
            return False

        IntervalWindow = b'\x00\x10\x00\x10'

        ScanParam = b''.join([api.BLE_GAP_SCAN.TYPE_ACTIVE_SCAN.value,
                              IntervalWindow,
                              api.BLE_GAP_ADDR_TYPE.PUBLIC.value,
                              api.BLE_GAP_SCAN.FILTER_POLICY_WHITELIST.value])

        ScanMode = b''.join([api.BLE_GAP_SCAN.ENABLE.value,
                             api.BLE_GAP_SCAN.FILTER_DUPLICATES_ENABLE.value,
                             api.BLE_GAP_SCAN.MODE_OBSERVER.value])

        if self.set_scanning(scanParam=ScanParam, scanMode=ScanMode):
            return True
        else:
            return False

    def mmi170(self,descript):
        logger.info(f'\n{descript}\n')

        conninfo = self.create_connection('BT')

        if not conninfo:
            return False

        self.conninfo = conninfo

        rfcommPsm = bytes()
        if descript.find('RFCOMM') != -1:
            psm_index = descript.find('RFCOMM') + 9
            rfcommPsm = bytes.fromhex(descript[psm_index:psm_index+4])

        OpenChanReq  = b''.join([self.conninfo['connhandle'],
                                 rfcommPsm,
                                 len(api.BT_L2CAP_CONF_OPTIONS.MTU.value).to_bytes(1,'big'),
                                 api.BT_L2CAP_CONF_OPTIONS.MTU.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.BT_L2CAP,
                                     api.BT_L2CAP_CMD_ID.OPEN_CHAN_REQ,
                                     OpenChanReq],
                          EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                     api.Layer_ID.BT_L2CAP,
                                     api.BT_L2CAP_CMD_ID.OPEN_CHAN_REQ]):
            return
        else:
            return False

    def mmi171(self,descript):
        logger.info(f'\n{descript}\n')

        OpenChanReq  = b''.join([self.conninfo['connhandle'],
                                 bytes.fromhex(self.ixit[b'TSPX_psm'][1].decode()),
                                 len(api.BT_L2CAP_CONF_OPTIONS.MTU.value).to_bytes(1,'big'),
                                 api.BT_L2CAP_CONF_OPTIONS.MTU.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.BT_L2CAP,
                                     api.BT_L2CAP_CMD_ID.OPEN_CHAN_REQ,
                                     OpenChanReq],
                          EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                     api.Layer_ID.BT_L2CAP,
                                     api.BT_L2CAP_CMD_ID.OPEN_CHAN_REQ]):
            return
        else:
            return False

    def mmi208(self,descript):
        logger.info(f'\n{descript}\n')
        return True

    def mmi209(self,descript):
        logger.info(f'\n{descript}\n')
        return True

    def mmi224(self,descript):
        logger.info(f'\n{descript}\n')
        return True

    def mmi225(self,descript):
        logger.info(f'\n{descript}\n')
        return True

    def mmi226(self,descript):
        logger.info(f'\n{descript}\n')
        return True

    def mmi1002(self,descript):
        logger.info(''.join(['\n', descript,'\n']))

        passkey = self.CommandRW(EVENT = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                          api.Layer_ID.BLE_SMP,
                                          api.SMP_CMD_ID.GEN_PASSKEY],
                                 back  = True)
        if not passkey:
            return False
        else:
            logger.debug(f'PassKey :{passkey[5:]}')
            return passkey[5:]

class GATT(Common):
    def __init__(self,comport,profile,casename,ptsaddress_b,ixit,bleonly):
        Common.__init__(self,comport,profile,casename,ptsaddress_b,ixit,bleonly)
        self.id          = b'\x00'
        self.conninfo    = None
        self.readRsp     = str()
        self.writeRsp    = bytes()
        self.readRspUUID = list()
        self.errRsp      = bytes()
        self.services    = None

    def mmi(self,descript):
        if self.casename_b == b'GATT/CL/GAR/BI-05-C' or \
           self.casename_b == b'GATT/CL/GAR/BI-11-C' or \
           self.casename_b == b'GATT/CL/GAR/BI-17-C' or \
           self.casename_b == b'GATT/CL/GAW/BI-06-C' or \
           self.casename_b == b'GATT/CL/GAW/BI-13-C' or \
           self.casename_b == b'GATT/CL/GAW/BV-06-C':
            if self.conninfo:
                if self.CommandRW(EVENT = [api.Layer_ID.BLE_SMP,
                                           api.SMP_Event_ID.SECURITY_REQUEST,
                                           self.conninfo['connhandle']]):
                    if self.CommandRW(COMMAND = [api.Layer_ID.BLE_SMP,
                                                 api.SMP_CMD_ID.INIT_PAIR,
                                                 self.conninfo['connhandle']],
                                      EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                                 api.Layer_ID.BLE_SMP,
                                                 api.SMP_CMD_ID.INIT_PAIR]):
                        return
                    else:
                        return False
                else:
                    return False

        if self.casename_b == b'GATT/SR/GAR/BI-35-C':
            if self.conninfo:
                conninfo = self.get_connetion_info()

                if not conninfo:
                    return False

                self.conninfo = conninfo

                if self.CommandRW(EVENT = [api.Layer_ID.BT_GAP,
                                           api.BT_GAP_Event_ID.USER_CONFIRMATION_REQUEST,
                                           bytes.fromhex(self.pts_address_b.decode())[::-1]]):

                    connCmpCfm = self.CommandRW(COMMAND = [api.Layer_ID.BT_GAP,
                                                           api.BT_GAP_CMD_ID.DISPLAY_YESNO_RES,
                                                           b'\x00'],
                                                EVENT   = [api.Layer_ID.BLE_GATT,
                                                           api.GATT_Event_ID.BT_CONNECT_COMPLETE_CFM,
                                                           self.conninfo['connhandle']],
                                                back    =  True)

                    if not connCmpCfm:
                        return False

                    if connCmpCfm[4:] == api.MBA_RES.SUCCESS.value:
                        return
                    else:
                        return False

                else:
                    return False


        if self.casename_b == b'GATT/SR/GAS/BV-01-C' or \
           self.casename_b == b'GATT/SR/GAS/BV-02-C':
            if self.conninfo:
                if self.CommandRW(EVENT = [api.Layer_ID.BLE_GAP,
                                           api.BLE_GAP_Event_ID.DISCONNECTED,
                                           self.conninfo['connhandle']]):

                    if self.CommandRW(COMMAND = [api.Layer_ID.BLE_GATT,
                                                 api.GATT_CMD_ID.REMOVE_SERVICE,
                                                 b''],
                                      EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                                 api.Layer_ID.BLE_GATT,
                                                 api.GATT_CMD_ID.REMOVE_SERVICE]):

                        if self.CommandRW(COMMAND = [api.Layer_ID.BLE_GATT,
                                                     api.GATT_CMD_ID.SERVICE_CHANGE,
                                                     b''],
                                          EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                                     api.Layer_ID.BLE_GATT,
                                                     api.GATT_CMD_ID.SERVICE_CHANGE]):
                            return
                        else:
                            return False
                    else:
                        return False
                else:
                    return False

        return

    def mmi1(self,descript):
        logger.info(''.join(['\n', descript,'\n']))

        if self.casename_b == b'GATT/SR/GAR/BI-35-C':
            secMode = b''.join([api.BT_GAP_SECURITY.MODE_4.value,
                                api.BT_GAP_AUTH_REQUIREMENT.MITM_REQUIRED_GENERAL_BONDING.value,
                                api.BT_GAP_IOCAPABILITY.DISPLAYYESNO.value])

            if self.CommandRW(COMMAND = [api.Layer_ID.BT_GAP,
                                         api.BT_GAP_CMD_ID.SET_CONNECTION_SECURITY,
                                         secMode],
                              EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                         api.Layer_ID.BT_GAP,
                                         api.BT_GAP_CMD_ID.SET_CONNECTION_SECURITY]):
                self.conninfo = True
                return [True,'mmi']
            else:
                return False

        AdvData = b''.join([len(api.BLE_GAP_ADV.DATATYPE_Flags.value
                                + api.BLE_GAP_ADV.Flags_General_Discover.value).to_bytes(1, 'big'),
                            api.BLE_GAP_ADV.DATATYPE_Flags.value,
                            api.BLE_GAP_ADV.Flags_General_Discover.value])

        AdvParam = b''.join([b'\x00\x20\x00\x20',
                             api.BLE_GAP_ADV.TYPE_ADV_IND.value,
                             api.BLE_GAP_ADDR_TYPE.PUBLIC.value,
                             api.BLE_GAP_ADDR_TYPE.PUBLIC.value,
                             bytes.fromhex(self.pts_address_b.decode())[::-1],
                             api.BLE_GAP_ADV.CHANNEL_ALL.value,
                             api.BLE_GAP_ADV.FILTER_POLICY_DEFAULT.value])

        if not self.advertising(advData=AdvData, advParam=AdvParam, EnDisable=api.BLE_GAP_ADV.ENABLE):
            return False

        time.sleep(1)

        conninfo = self.get_connetion_info()

        if not conninfo:
            return False

        self.conninfo = conninfo

        if self.casename_b == b'GATT/SR/GAN/BV-01-C' or \
           self.casename_b == b'GATT/SR/GAI/BV-01-C':
            dataSession = b''.join([self.conninfo['connhandle'],
                                    api.TRS_creditBaseCtrl.ENABLE.value,
                                    api.TRS_ROLE.SERVER.value])

            if self.CommandRW(COMMAND = [api.Layer_ID.BLE_TRS,
                                         api.TRS_CMD_ID.ENABLE_DATA_SESSION,
                                         dataSession],
                              EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                         api.Layer_ID.BLE_TRS,
                                         api.TRS_CMD_ID.ENABLE_DATA_SESSION,]):
                return
            else:
                return False

        if self.casename_b == b'GATT/SR/GAC/BV-01-C' or \
           self.casename_b == b'GATT/SR/GAS/BV-04-C' or \
           self.casename_b == b'GATT/SR/GAS/BV-07-C':
            return [None, 'mmi']

        return

    def mmi2(self,descript):
        logger.info(f'\n{descript}\n')

        conninfo = self.create_connection('BLE')

        if not conninfo:
            return False

        self.conninfo = conninfo

        if self.casename_b == b'GATT/CL/GAR/BI-05-C' or \
           self.casename_b == b'GATT/CL/GAR/BI-11-C' or \
           self.casename_b == b'GATT/CL/GAR/BI-17-C' or \
           self.casename_b == b'GATT/CL/GAW/BI-06-C' or \
           self.casename_b == b'GATT/CL/GAW/BI-13-C' or \
           self.casename_b == b'GATT/CL/GAW/BV-06-C':
            return [None,'mmi']

        return

    def mmi3(self,descript):
        logger.info(f'\n{descript}\n')

        if self.conninfo['layer'] == api.Layer_ID.BT_GAP.value:

            if self.CommandRW(COMMAND = [api.Layer_ID.BLE_GATT,
                                         api.GATT_CMD_ID.BT_DISCONNECT,
                                         self.conninfo['connhandle']],
                              EVENT   = [api.Layer_ID.BLE_GATT,
                                         api.GATT_Event_ID.BT_DISCONNECT_CFM,
                                         self.conninfo['connhandle']]):
                return
            else:
                return False

        Terminate = b''.join([self.conninfo['connhandle'],
                              api.BLE_GAP_DISC_REASON.REMOTE_TERMINATE.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.BLE_GAP,
                                     api.BLE_GAP_CMD_ID.TERMINATE_CONNECTION,
                                     Terminate],
                          EVENT   = [api.Layer_ID.BLE_GAP,
                                     api.BLE_GAP_Event_ID.DISCONNECTED,
                                     self.conninfo['connhandle']]):
            return
        else:
            return False

    def mmi4(self,descript):
        logger.info(f'\n{descript}\n')
        return True

    def mmi5(self, descript):
        logger.info(f'\n{descript}\n')

        secMode = b''.join([api.BT_GAP_SECURITY.MODE_4.value,
                            api.BT_GAP_AUTH_REQUIREMENT.MITM_REQUIRED_GENERAL_BONDING.value,
                            api.BT_GAP_IOCAPABILITY.DISPLAYYESNO.value])

        if self.CommandRW(COMMAND=[api.Layer_ID.BT_GAP,
                                   api.BT_GAP_CMD_ID.SET_CONNECTION_SECURITY,
                                   secMode],
                          EVENT=[api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                 api.Layer_ID.BT_GAP,
                                 api.BT_GAP_CMD_ID.SET_CONNECTION_SECURITY]):

            conninfo = self.create_connection('BT')

            if not conninfo:
                return False

            self.conninfo = conninfo

            time.sleep(1)

            mtu = b'\x00\x00'
            connect = b''.join([self.conninfo['connhandle'], mtu])

            if self.CommandRW(COMMAND=[api.Layer_ID.BLE_GATT,
                                       api.GATT_CMD_ID.BT_CONNECT,
                                       connect],
                              EVENT=[api.Layer_ID.BT_GAP,
                                     api.BT_GAP_Event_ID.USER_CONFIRMATION_REQUEST,
                                     bytes.fromhex(self.pts_address_b.decode())[::-1]]):

                connCmpCfm = self.CommandRW(COMMAND=[api.Layer_ID.BT_GAP,
                                                     api.BT_GAP_CMD_ID.DISPLAY_YESNO_RES,
                                                     b'\x00'],
                                            EVENT=[api.Layer_ID.BLE_GATT,
                                                   api.GATT_Event_ID.BT_CONNECT_COMPLETE_CFM,
                                                   self.conninfo['connhandle']],
                                            back=True)

                if not connCmpCfm:
                    return False

                if connCmpCfm[4:] == api.MBA_RES.SUCCESS.value:
                    return
                else:
                    return False

            else:
                return False

    def mmi10(self,descript):
        logger.info(f'\n{descript}\n')

        if self.CommandRW(COMMAND = [api.Layer_ID.BLE_GATT,
                                     api.GATT_CMD_ID.DIS_ALL_PSERV,
                                     self.conninfo['connhandle']],
                          EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                     api.Layer_ID.BLE_GATT,
                                     api.GATT_CMD_ID.DIS_ALL_PSERV]):
            return
        else:
            return False

    def mmi11(self, descript):
        logger.info(f'\n{descript}\n')

        errRsp = self.CommandRW(EVENT = [api.Layer_ID.BLE_GATT,
                                         api.GATT_Event_ID.ERROR_RESP,
                                         self.conninfo['connhandle']],
                                back = True)

        if not errRsp:
            logger.error('uart event not GATT error response...')
            return False

        if errRsp[7:] == api.GATT_ERROR_CODES.ATTRIBUTE_NOT_FOUND.value:
            return True
        else:
            logger.error(f'GATT error code is {errRsp[7:]} ,not {api.GATT_ERROR_CODES.ATTRIBUTE_NOT_FOUND.value}')
            return False

    def mmi12(self,descript):
        logger.info(f'\n{descript}\n')

        mtu = b''.join([self.conninfo['connhandle'],
                        int(self.ixit[b'TSPX_mtu_size'][1]).to_bytes(2,'big')])

        if self.CommandRW(COMMAND = [api.Layer_ID.BLE_GATT,
                                     api.GATT_CMD_ID.EX_MTU,
                                     mtu],
                          EVENT   = [api.Layer_ID.BLE_GATT,
                                     api.GATT_Event_ID.UPDATE_MTU,
                                     self.conninfo['connhandle']]):
            return
        else:
            return False

    def mmi13(self, descript):
        logger.info(f'\n{descript}\n')

        return [True,'mmi']

    def mmi15(self,descript):
        logger.info(f'\n{descript}\n')

        startHandle = b'\x00\x01'
        endHandle   = b'\xFF\xFF'
        uuidValue   = b'\x28\x02'
        uuid        = b''.join([self.conninfo['connhandle'],
                                startHandle,
                                endHandle,
                                len(uuidValue).to_bytes(1,'big'),
                                uuidValue])

        if not self.CommandRW(COMMAND = [api.Layer_ID.BLE_GATT,
                                         api.GATT_CMD_ID.READ_USING_UUID,
                                         uuid],
                              EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                         api.Layer_ID.BLE_GATT,
                                         api.GATT_CMD_ID.READ_USING_UUID]):
            return False

        errRsp  = b''.join([api.Layer_ID.BLE_GATT.value,
                            api.GATT_Event_ID.ERROR_RESP.value,
                            self.conninfo['connhandle']])

        rev = self.readEvent()

        if not rev:
            logger.error('uart event not GATT error response...')
            return False

        if rev[:4] == errRsp:
            self.errRsp = rev

        return

    def mmi16(self, descript):
        logger.info(f'\n{descript}\n')

        errRsp = self.CommandRW(EVENT = [api.Layer_ID.BLE_GATT,
                                         api.GATT_Event_ID.ERROR_RESP,
                                         self.conninfo['connhandle']],
                                back = True)

        if not errRsp:
            logger.error('uart event not GATT error response...')
            return False

        if errRsp[7:] == api.GATT_ERROR_CODES.ATTRIBUTE_NOT_FOUND.value:
            return True
        else:
            logger.error(f'GATT error code is {errRsp[7:]} ,not {api.GATT_ERROR_CODES.ATTRIBUTE_NOT_FOUND.value}')
            return False

    def mmi17(self,descript):
        logger.info(f'\n{descript}\n')
        datas = list()

        if self.casename_b == b'GATT/SR/GAD/BV-01-C':
            return True

        while 1:
            serviceRsp = b''.join([api.Layer_ID.BLE_GATT.value,
                                   api.GATT_Event_ID.DISC_PRIM_SERV_RESP.value,
                                   self.conninfo['connhandle']])

            errRsp     = b''.join([api.Layer_ID.BLE_GATT.value,
                                   api.GATT_Event_ID.ERROR_RESP.value,
                                   self.conninfo['connhandle']])

            rev = self.readEvent()

            if not rev:
                logger.error('uart event not GATT discovery primary services response...')
                return False

            if rev[:4] == errRsp:
                break

            if rev[:4] == serviceRsp:
                pairLength  = int(bytes.hex(rev[4:5]),16)
                dataLength  = int(bytes.hex(rev[5:6]),16)*256 + int(bytes.hex(rev[6:7]),16)

                if dataLength == 0:
                    break

                attrData    = rev[8:]
                groupNumber = int(len(attrData) / (dataLength / pairLength))
                services    = [attrData[i:i+groupNumber][4:] for i in range(0,len(attrData),groupNumber)]

                for service in services:
                    if len(service) == 0:
                        return False
                    datas.append(service.hex().upper())

                if rev[7:8] == api.GATT_PROCEDURE_STATUS.FINISH.value:
                    break

        for data in datas:
            primaryService = f"Primary Service = '{data}'"

            if primaryService not in descript:
                logger.error(f'primary services: {data} not in database')
                return False

        return True

    def mmi18(self,descript):
        logger.info(f'\n{descript}\n')

        startHandle = b'\x00\x01'
        endHandle   = b'\xFF\xFF'
        uuidValue   = bytes.fromhex(descript[descript.find('to')+4:descript.find('O')-1])
        uuid        = b''.join([self.conninfo['connhandle'],
                                startHandle,
                                endHandle,
                                len(uuidValue).to_bytes(1,'big'),
                                uuidValue])

        if self.CommandRW(COMMAND = [api.Layer_ID.BLE_GATT,
                                     api.GATT_CMD_ID.DIS_PRIMARY_SERV_UUID,
                                     uuid],
                          EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                     api.Layer_ID.BLE_GATT,
                                     api.GATT_CMD_ID.DIS_PRIMARY_SERV_UUID]):
            return
        else:
            return False

    def mmi19(self,descript):
        logger.info(f'\n{descript}\n')
        datas = list()

        while 1:
            uuidRsp = b''.join([api.Layer_ID.BLE_GATT.value,
                                api.GATT_Event_ID.DISC_PRIM_SERV_BY_UUID_RESP.value,
                                self.conninfo['connhandle']])

            errRsp     = b''.join([api.Layer_ID.BLE_GATT.value,
                                   api.GATT_Event_ID.ERROR_RESP.value,
                                   self.conninfo['connhandle']])

            rev = self.readEvent()

            if not rev:
                logger.error('uart event not GATT discovery primary services by uuid response...')
                return False

            if rev[:4] == errRsp:
                break

            if rev[:4] == uuidRsp:
                for i in range(0, len(rev[7:]), 2):
                    datas.append(rev[7:][i:i + 2].hex().upper())

                if rev[6:7] == api.GATT_PROCEDURE_STATUS.FINISH.value:
                    break

        for data in datas:
            handle = f"handle = '{data}'"

            if handle not in descript:
                logger.error(f'primary services handle: {data} not in database')
                return False

        return True

    def mmi20(self,descript):
        logger.info(f'\n{descript}\n')

        startHandle = b'\x00\x01'
        endHandle   = b'\xFF\xFF'
        uuidValue   = bytes.fromhex(descript[descript.find('to')+4:descript.find('O')-1].replace('-',''))
        uuid        = b''.join([self.conninfo['connhandle'],
                                startHandle,
                                endHandle,
                                len(uuidValue).to_bytes(1,'big'),
                                uuidValue])

        if self.CommandRW(COMMAND = [api.Layer_ID.BLE_GATT,
                                     api.GATT_CMD_ID.DIS_PRIMARY_SERV_UUID,
                                     uuid],
                          EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                     api.Layer_ID.BLE_GATT,
                                     api.GATT_CMD_ID.DIS_PRIMARY_SERV_UUID]):
            return
        else:
            return False

    def mmi21(self,descript):
        logger.info(f'\n{descript}\n')
        datas = list()

        while 1:
            uuidRsp = b''.join([api.Layer_ID.BLE_GATT.value,
                                api.GATT_Event_ID.DISC_PRIM_SERV_BY_UUID_RESP.value,
                                self.conninfo['connhandle']])

            errRsp     = b''.join([api.Layer_ID.BLE_GATT.value,
                                   api.GATT_Event_ID.ERROR_RESP.value,
                                   self.conninfo['connhandle']])

            rev = self.readEvent()

            if not rev:
                logger.error('uart event not GATT discovery primary services by uuid response...')
                return False

            if rev[:4] == errRsp:
                break

            if rev[:4] == uuidRsp:
                for i in range(0, len(rev[7:]), 2):
                    datas.append(rev[7:][i:i + 2].hex().upper())

                if rev[6:7] == api.GATT_PROCEDURE_STATUS.FINISH.value:
                    break

        for data in datas:
            handle = f"handle = '{data}'"

            if handle not in descript:
                logger.error(f'primary services handle: {data} not in database')
                return False

        return True

    def mmi22(self,descript):
        logger.info(f'\n{descript}\n')
        return True

    def mmi24(self,descript):
        logger.info(f'\n{descript}\n')

        if self.casename_b == b'GATT/SR/GAD/BV-03-C':
            return True

        uuids = list()

        errRsp           = b''.join([api.Layer_ID.BLE_GATT.value,
                                     api.GATT_Event_ID.ERROR_RESP.value,
                                     self.conninfo['connhandle']])

        readRsp          = b''.join([api.Layer_ID.BLE_GATT.value,
                                     api.GATT_Event_ID.READ_RESP.value,
                                     self.conninfo['connhandle']])

        readUsingUUIDRsp = b''.join([api.Layer_ID.BLE_GATT.value,
                                     api.GATT_Event_ID.READ_USING_UUID_RESP.value,
                                     self.conninfo['connhandle']])


        startHandle = b'\x00\x01'
        endHandle   = b'\xFF\xFF'
        uuidValue   = b'\x28\x02'

        while 1:
            uuid = b''.join([self.conninfo['connhandle'],
                             startHandle,
                             endHandle,
                             len(uuidValue).to_bytes(1,'big'),
                             uuidValue])

            if not self.CommandRW(COMMAND = [api.Layer_ID.BLE_GATT,
                                             api.GATT_CMD_ID.READ_USING_UUID,
                                             uuid],
                                  EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                             api.Layer_ID.BLE_GATT,
                                             api.GATT_CMD_ID.READ_USING_UUID]):
                return False

            rev = self.readEvent()

            if not rev:
                logger.error('uart event not GATT error response...')
                return False

            if rev[:4] == errRsp:
                self.errRsp = rev
                break

            if rev[:4] == readUsingUUIDRsp:
                pairLength  = int(bytes.hex(rev[4:5]), 16)
                dataLength  = int(bytes.hex(rev[5:6]), 16) * 256 + int(bytes.hex(rev[6:7]), 16)
                attrData    = rev[8:]
                groupNumber = int(len(attrData) / (dataLength / pairLength))
                services    = [attrData[i:i + groupNumber] for i in range(0, len(attrData), groupNumber)]

                if pairLength == 6:
                    Attribute_handle  = attrData[:2].hex().upper()
                    Service_Attribute = attrData[2:4].hex().upper()
                    Group_Handle      = attrData[4:].hex().upper()
                    charHandle        = attrData[2:4]
                    valueOffset       = bytes(2)

                    while 1:
                        value = b''.join([self.conninfo['connhandle'],
                                          charHandle,
                                          valueOffset])

                        if not self.CommandRW(COMMAND = [api.Layer_ID.BLE_GATT,
                                                         api.GATT_CMD_ID.READ,
                                                         value],
                                              EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                                         api.Layer_ID.BLE_GATT,
                                                         api.GATT_CMD_ID.READ]):
                            return False

                        rev = self.readEvent()

                        if not rev:
                            logger.error('uart event not GATT error response...')
                            return False

                        if rev[:4] == errRsp:
                            self.errRsp = rev
                            break

                        if rev[:4] == readRsp:

                            if rev[5:7] == b'\x00\x00':
                                break

                            value = rev[7:][::-1].hex().upper()

                            self.readRsp = ''.join([self.readRsp, value])

                            if len(rev[7:]) == int(self.ixit[b'TSPX_mtu_size'][1]) - 1:

                                valueOffset = (int(bytes.hex(valueOffset), 16) +
                                               int(self.ixit[b'TSPX_mtu_size'][1]) - 1).to_bytes(2, 'big')

                                continue
                        break

                    uuids.append('Attribute Handle = \'{0}\'O Included Service Attribute handle = \'{1}\'O,'
                                 'End Group Handle = \'{2}\'O,Service UUID = \'{3}\'O'.format(Attribute_handle,
                                                                                              Service_Attribute,
                                                                                              Group_Handle,
                                                                                              self.readRsp))

                    startHandle  = (int(Attribute_handle, 16) + 1).to_bytes(2, 'big')
                    self.readRsp = ''

                    continue

                for service in services:
                    Attribute_handle  = service[0:2].hex().upper()
                    Service_Attribute = service[2:4].hex().upper()
                    Group_Handle      = service[4:6].hex().upper()
                    Service_UUID      = service[6:].hex().upper()

                    uuids.append('Attribute Handle = \'{0}\'O Included Service Attribute handle = \'{1}\'O,'
                                 'End Group Handle = \'{2}\'O,Service UUID = \'{3}\'O'.format(Attribute_handle,
                                                                                              Service_Attribute,
                                                                                              Group_Handle,
                                                                                              Service_UUID))

                    if service == services[-1]:
                        if service[0:2] == endHandle:
                            break
                        startHandle = (int(Attribute_handle, 16) + 1).to_bytes(2,'big')

        for uuid in uuids:
            if uuid not in descript:
                return False

        return True

    def mmi25(self,descript):
        logger.info(f'\n{descript}\n')
        return True

    def mmi26(self,descript):
        logger.info(f'\n{descript}\n')

        if self.errRsp[7:] == api.GATT_ERROR_CODES.ATTRIBUTE_NOT_FOUND.value:
            return True
        else:
            logger.error('GATT error code is {0} ,not {1}'.format(self.errRsp[7:],
                                                                  api.GATT_ERROR_CODES.ATTRIBUTE_NOT_FOUND.value))
            return False

    def mmi27(self,descript):
        logger.info(f'\n{descript}\n')
        startPoint  = descript.find('start handle')+16
        endPoint    = descript.find('end handle')+14
        startHandle = bytes.fromhex(descript[startPoint:startPoint+4])
        endHandle   = bytes.fromhex(descript[endPoint:endPoint+4])
        charHandle  = b''.join([self.conninfo['connhandle'],
                                startHandle,
                                endHandle])

        if self.CommandRW(COMMAND = [api.Layer_ID.BLE_GATT,
                                     api.GATT_CMD_ID.DIS_ALL_CHAR,
                                     charHandle],
                          EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                     api.Layer_ID.BLE_GATT,
                                     api.GATT_CMD_ID.DIS_ALL_CHAR]):
            return
        else:
            return False

    def mmi28(self,descript):
        logger.info(f'\n{descript}\n')
        datas = list()

        while 1:
            charRsp = b''.join([api.Layer_ID.BLE_GATT.value,
                                api.GATT_Event_ID.DISC_CHAR_RESP.value,
                                self.conninfo['connhandle']])

            errRsp  = b''.join([api.Layer_ID.BLE_GATT.value,
                                api.GATT_Event_ID.ERROR_RESP.value,
                                self.conninfo['connhandle']])

            rev = self.readEvent()

            if not rev:
                logger.error('uart event not GATT discovery characteristics response...')
                return False

            if rev[:4] == errRsp:
                break

            if rev[:4] == charRsp:
                pairLength  = int(bytes.hex(rev[4:5]),16)
                dataLength  = int(bytes.hex(rev[5:6]),16)*256 + int(bytes.hex(rev[6:7]),16)

                if dataLength == 0:
                    break

                attrData    = rev[8:]
                groupNumber = int(len(attrData) / (dataLength / pairLength))
                services    = [attrData[i:i+groupNumber][:2] for i in range(0,len(attrData),groupNumber)]

                for service in services:
                    if len(service) == 0:
                        return False
                    datas.append(service.hex().upper())

                if rev[7:8] == api.GATT_PROCEDURE_STATUS.FINISH.value:
                    break

        for data in datas:
            handle = 'handle=\'{0}\''.format(data)
            if handle not in descript:
                logger.error('characteristics services: {0} not in database'.format(data))
                return False

        return True

    def mmi29(self,descript):
        logger.info(f'\n{descript}\n')
        startPoint  = descript.find('start from handle')+21
        endPoint    = descript.find('end handle')+14
        startHandle = bytes.fromhex(descript[startPoint:startPoint+4])
        endHandle   = bytes.fromhex(descript[endPoint:endPoint+4])

        if 'UUID = 0x' in descript:
            uuidPoint = descript.find('UUID =')+9
            charUUID  = bytes.fromhex(descript[uuidPoint:uuidPoint+4])
        else:
            uuidPoint = descript.find('UUID =')+7
            charUUID    = bytes.fromhex(descript[uuidPoint:uuidPoint+39].replace('-',''))

        charHandle  = b''.join([self.conninfo['connhandle'],
                                startHandle,
                                endHandle,
                                charUUID])

        if self.CommandRW(COMMAND = [api.Layer_ID.BLE_GATT,
                                     api.GATT_CMD_ID.DIS_CHAR_USING_UUID,
                                     charHandle],
                          EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                     api.Layer_ID.BLE_GATT,
                                     api.GATT_CMD_ID.DIS_CHAR_USING_UUID]):
            return
        else:
            return False

    def mmi30(self,descript):
        logger.info(f'\n{descript}\n')
        datas = list()

        while 1:
            charUUIDRsp = b''.join([api.Layer_ID.BLE_GATT.value,
                                    api.GATT_Event_ID.DISC_CHAR_BY_UUID_RESP.value,
                                    self.conninfo['connhandle']])

            errRsp      = b''.join([api.Layer_ID.BLE_GATT.value,
                                    api.GATT_Event_ID.ERROR_RESP.value,
                                    self.conninfo['connhandle']])

            rev = self.readEvent()

            if not rev:
                logger.error('uart event not GATT discovery characteristics by uuid response...')
                return False

            if rev[:4] == errRsp:
                break

            if rev[:4] == charUUIDRsp:
                pairLength  = int(bytes.hex(rev[4:5]),16)
                dataLength  = int(bytes.hex(rev[5:6]),16)*256 + int(bytes.hex(rev[6:7]),16)

                if dataLength == 0:
                    break

                attrData    = rev[8:]
                groupNumber = int(len(attrData) / (dataLength / pairLength))
                services    = [attrData[i:i+groupNumber][3:5] for i in range(0,len(attrData),groupNumber)]

                for service in services:
                    if len(service) == 0:
                        return False
                    datas.append(service.hex().upper())

                if rev[7:8] == api.GATT_PROCEDURE_STATUS.FINISH.value:
                    break

        for data in datas:
            handle = 'handle=\'{0}\''.format(data)
            if handle not in descript:
                logger.error('characteristics services handle: {0} not in database'.format(data))
                return False

        return True

    def mmi31(self,descript):
        logger.info(f'\n{descript}\n')
        startPoint  = descript.find('start from handle')+21
        endPoint    = descript.find('end handle')+14
        startHandle = bytes.fromhex(descript[startPoint:startPoint+4])
        endHandle   = bytes.fromhex(descript[endPoint:endPoint+4])

        charHandle  = b''.join([self.conninfo['connhandle'],
                                startHandle,
                                endHandle])

        if self.CommandRW(COMMAND = [api.Layer_ID.BLE_GATT,
                                     api.GATT_CMD_ID.DIS_ALL_DESC,
                                     charHandle],
                          EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                     api.Layer_ID.BLE_GATT,
                                     api.GATT_CMD_ID.DIS_ALL_DESC]):
            return
        else:
            return False

    def mmi32(self,descript):
        logger.info(f'\n{descript}\n')
        datas = list()

        while 1:
            descRsp = b''.join([api.Layer_ID.BLE_GATT.value,
                                api.GATT_Event_ID.DISC_DESC_RESP.value,
                                self.conninfo['connhandle']])

            errRsp  = b''.join([api.Layer_ID.BLE_GATT.value,
                                api.GATT_Event_ID.ERROR_RESP.value,
                                self.conninfo['connhandle']])

            rev = self.readEvent()

            if not rev:
                logger.error('uart event not GATT discovery characteristics descriptors response...')
                return False

            if rev[:4] == errRsp:
                break

            if rev[:4] == descRsp:
                dataLength = int(bytes.hex(rev[5:6]),16)*256 + int(bytes.hex(rev[6:7]),16)

                if dataLength == 0:
                    break

                attrData = rev[8:]
                services = [attrData[i:i+dataLength][2:] for i in range(0,len(attrData),dataLength)]

                for service in services:
                    if len(service) == 0:
                        return False
                    datas.append(service.hex().upper())

                if rev[7:8] == api.GATT_PROCEDURE_STATUS.FINISH.value:
                    break

        for data in datas:
            uuid = 'UUID=0x{0}'.format(data)
            if uuid not in descript:
                logger.error('characteristics descriptors uuid: {0} not in database'.format(data))
                return False

        return True

    def mmi33(self, descript):
        logger.info(f'\n{descript}\n')

        if '0x1801' in descript:
            return True
        else:
            return False

    def mmi40(self,descript):
        logger.info(f'\n{descript}\n')

        if self.errRsp[7:] == api.GATT_ERROR_CODES.INVALID_HANDLE.value:
            return True
        else:
            logger.error('GATT error code is {0} ,not {1}'.format(self.errRsp[7:],
                                                                  api.GATT_ERROR_CODES.INVALID_HANDLE.value))
            return False

    def mmi41(self,descript):
        logger.info(f'\n{descript}\n')

        if self.errRsp[7:] == api.GATT_ERROR_CODES.READ_NOT_PERMITTED.value:
            return True
        else:
            logger.error('GATT error code is {0} ,not {1}'.format(self.errRsp[7:],
                                                                  api.GATT_ERROR_CODES.READ_NOT_PERMITTED.value))
            return False

    def mmi42(self,descript):
        logger.info(f'\n{descript}\n')

        if self.errRsp[7:] == api.GATT_ERROR_CODES.INSUFFICIENT_AUTHORIZATION.value:
            return True
        else:
            logger.error('GATT error code is {0} ,not {1}'.format(self.errRsp[7:],
                                                            api.GATT_ERROR_CODES.INSUFFICIENT_AUTHORIZATION.value))
            return False

    def mmi43(self,descript):
        logger.info(f'\n{descript}\n')

        if self.errRsp[7:] == api.GATT_ERROR_CODES.INSUFFICIENT_AUTHENTICATION.value:
            return True
        else:
            logger.error('GATT error code is {0} ,not {1}'.format(self.errRsp[7:],
                                                            api.GATT_ERROR_CODES.INSUFFICIENT_AUTHENTICATION.value))
            return False

    def mmi44(self,descript):
        logger.info(f'\n{descript}\n')

        if self.errRsp[7:] == api.GATT_ERROR_CODES.INSUFFICIENT_ENCRYPTION_KEY_SIZE.value:
            return True
        else:
            logger.error('GATT error code is {0} ,not {1}'.format(self.errRsp[7:],
                                                        api.GATT_ERROR_CODES.INSUFFICIENT_ENCRYPTION_KEY_SIZE.value))
            return False

    def mmi45(self,descript):
        logger.info(f'\n{descript}\n')

        if self.errRsp[7:] == api.GATT_ERROR_CODES.ATTRIBUTE_NOT_FOUND.value:
            return True
        else:
            logger.error('GATT error code is {0} ,not {1}'.format(self.errRsp[7:],
                                                        api.GATT_ERROR_CODES.ATTRIBUTE_NOT_FOUND.value))
            return False

    def mmi46(self,descript):
        logger.info(f'\n{descript}\n')

        if self.errRsp[7:] == api.GATT_ERROR_CODES.INVALID_OFFSET.value:
            return True
        else:
            logger.error('GATT error code is {0} ,not {1}'.format(self.errRsp[7:],
                                                        api.GATT_ERROR_CODES.INVALID_OFFSET.value))
            return False

    def mmi47(self,descript):
        logger.info(f'\n{descript}\n')

        if self.errRsp[7:] == api.GATT_ERROR_CODES.APPLICATION_ERROR.value:
            return True
        else:
            logger.error('GATT error code is {0} ,not {1}'.format(self.errRsp[7:],
                                                                  api.GATT_ERROR_CODES.APPLICATION_ERROR.value))
            return False

    def mmi48(self,descript):
        logger.info(f'\n{descript}\n')
        charPoint   = descript.find('handle')+10
        charHandle  = bytes.fromhex(descript[charPoint:charPoint+4])
        valueOffset = bytes(2)

        while 1:
            value = b''.join([self.conninfo['connhandle'],
                              charHandle,
                              valueOffset])

            if not self.CommandRW(COMMAND = [api.Layer_ID.BLE_GATT,
                                             api.GATT_CMD_ID.READ,
                                             value],
                                  EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                             api.Layer_ID.BLE_GATT,
                                             api.GATT_CMD_ID.READ]):
                return False

            if self.casename_b == b'GATT/CL/GAT/BV-01-C':
                return

            readRsp = b''.join([api.Layer_ID.BLE_GATT.value,
                                api.GATT_Event_ID.READ_RESP.value,
                                self.conninfo['connhandle']])

            errRsp  = b''.join([api.Layer_ID.BLE_GATT.value,
                                api.GATT_Event_ID.ERROR_RESP.value,
                                self.conninfo['connhandle']])

            rev = self.readEvent()

            if not rev:
                logger.error('uart event not GATT discovery characteristics descriptors response...')
                return False

            if rev[:4] == errRsp:
                self.errRsp = rev
                break

            if rev[:4] == readRsp:

                if rev[5:7] == b'\x00\x00':
                    break

                value = rev[7:].hex().upper()

                self.readRsp = ''.join([self.readRsp,value])

                if len(rev[7:]) == int(self.ixit[b'TSPX_mtu_size'][1])-1:
                    valueOffset = (int(bytes.hex(valueOffset),16) +
                                   int(self.ixit[b'TSPX_mtu_size'][1])-1).to_bytes(2,'big')
                    continue

            break

        return

    def mmi49(self,descript):
        logger.info(f'\n{descript}\n')

        time.sleep(30)

        if self.CommandRW(EVENT=[api.Layer_ID.BLE_GATT,
                                 api.GATT_Event_ID.TIMEOUT,
                                 b'']):
            return
        else:
            return False

    def mmi50(self,descript):
        logger.info(f'\n{descript}\n')

        if self.casename_b == b'GATT/CL/GAR/BV-01-C':

            if len(self.readRsp) == 0:
                logger.error('No received characteristics value')
                return False

            value = 'value=\'{0}\''.format(self.readRsp)

            if value not in descript:
                logger.error('characteristics value: {0} not in database'.format(value))
                return False

            self.readRsp = str()

            return True

        if self.readRspUUID:
            if descript.count('Attribute Handle') != len(self.readRspUUID):
                handles = list()

                for handle in descript.split('Attribute Handle = '):
                    if handle.find('Value') != -1:
                        handles.append(bytes.fromhex(handle[1:5]))

                for handle in handles:
                    valueOffset = bytes(2)
                    while 1:
                        value = b''.join([self.conninfo['connhandle'],
                                          handle,
                                          valueOffset])

                        if not self.CommandRW(COMMAND = [api.Layer_ID.BLE_GATT,
                                                         api.GATT_CMD_ID.READ,
                                                         value],
                                              EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                                         api.Layer_ID.BLE_GATT,
                                                         api.GATT_CMD_ID.READ]):
                            return False

                        readRsp = b''.join([api.Layer_ID.BLE_GATT.value,
                                            api.GATT_Event_ID.READ_RESP.value,
                                            self.conninfo['connhandle']])

                        errRsp = b''.join([api.Layer_ID.BLE_GATT.value,
                                           api.GATT_Event_ID.ERROR_RESP.value,
                                           self.conninfo['connhandle']])

                        rev = self.readEvent()

                        if not rev:
                            logger.error('uart event not GATT discovery characteristics descriptors response...')
                            return False

                        if rev[:4] == errRsp:
                            self.errRsp = rev
                            break

                        if rev[:4] == readRsp:

                            if rev[5:7] == b'\x00\x00':
                                break

                            value = rev[7:].hex().upper()

                            self.readRsp = ''.join([self.readRsp, value])

                            if len(rev[7:]) == int(self.ixit[b'TSPX_mtu_size'][1]) - 1:
                                valueOffset = (int(bytes.hex(valueOffset), 16) +
                                               int(self.ixit[b'TSPX_mtu_size'][1]) - 1).to_bytes(2, 'big')
                                continue
                        break

                    value = 'Attribute Handle = \'{0}\'O Value = {1}'.format(handle.hex().upper(),self.readRsp)

                    if value not in descript:
                        logger.error('characteristics value: {0} not in database'.format(value))
                        return False

                    self.readRsp = str()

                return True

            for data in self.readRspUUID:
                if len(data) == 0:
                    logger.error('No received characteristics value')
                    return False

                if 'Attribute Handle = \'{0}\'O'.format(data[0:4]) in descript:
                    for handle in descript.split('Attribute '):
                        if data[0:4] in handle:
                            valuePoint = handle.find('Value =')+8
                            value = handle[valuePoint:].strip()

                            if len(value) != len(data[4:]):
                                valueOffset = bytes(2)
                                while 1:
                                    value = b''.join([self.conninfo['connhandle'],
                                                      bytes.fromhex(data[0:4]),
                                                      valueOffset])

                                    if not self.CommandRW(COMMAND = [api.Layer_ID.BLE_GATT,
                                                                     api.GATT_CMD_ID.READ,
                                                                     value],
                                                          EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                                                     api.Layer_ID.BLE_GATT,
                                                                     api.GATT_CMD_ID.READ]):
                                        return False

                                    readRsp = b''.join([api.Layer_ID.BLE_GATT.value,
                                                        api.GATT_Event_ID.READ_RESP.value,
                                                        self.conninfo['connhandle']])

                                    errRsp = b''.join([api.Layer_ID.BLE_GATT.value,
                                                       api.GATT_Event_ID.ERROR_RESP.value,
                                                       self.conninfo['connhandle']])

                                    rev = self.readEvent()

                                    if not rev:
                                        logger.error('uart event not GATT discovery '
                                                     'characteristics descriptors response...')
                                        return False

                                    if rev[:4] == errRsp:
                                        self.errRsp = rev
                                        break

                                    if rev[:4] == readRsp:

                                        if rev[5:7] == b'\x00\x00':
                                            break

                                        value = rev[7:].hex().upper()

                                        self.readRsp = ''.join([self.readRsp, value])

                                        if len(rev[7:]) == int(self.ixit[b'TSPX_mtu_size'][1]) - 1:
                                            valueOffset = (int(bytes.hex(valueOffset), 16) +
                                                           int(self.ixit[b'TSPX_mtu_size'][1]) - 1).to_bytes(2, 'big')
                                            continue
                                    break

                                value = 'Attribute Handle = \'{0}\'O Value = {1}'.format(data[0:4],self.readRsp)

                                if value not in descript:
                                    logger.error('characteristics value: {0} not in database'.format(value))
                                    return False

                                self.readRsp = str()

                            else:
                                value = 'Attribute Handle = \'{0}\'O Value = {1}'.format(data[0:4], data[4:])

                                if value not in descript:
                                    logger.error('characteristics value: {0} not in database'.format(value))
                                    return False

            self.readRspUUID = list()

            return True
        else:
            logger.error('No received characteristics value')
            return False

    def mmi51(self,descript):
        logger.info(f'\n{descript}\n')
        startPoint  = descript.find('handle')+16
        endPoint    = descript.find('to')+4
        uuidPoint   = descript.find('UUID')+8
        startHandle = bytes.fromhex(descript[startPoint:startPoint+4])
        endHandle   = bytes.fromhex(descript[endPoint:endPoint+4])
        uuid        = bytes.fromhex(descript[uuidPoint:uuidPoint + 4])
        uuidValue   = b''.join([self.conninfo['connhandle'],
                                startHandle,
                                endHandle,
                                len(uuid).to_bytes(1,'big'),
                                uuid])

        if not self.CommandRW(COMMAND = [api.Layer_ID.BLE_GATT,
                                         api.GATT_CMD_ID.READ_USING_UUID,
                                         uuidValue],
                              EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                         api.Layer_ID.BLE_GATT,
                                         api.GATT_CMD_ID.READ_USING_UUID]):
            return False

        errRsp  = b''.join([api.Layer_ID.BLE_GATT.value,
                            api.GATT_Event_ID.ERROR_RESP.value,
                            self.conninfo['connhandle']])

        rev = self.readEvent()

        if not rev:
            logger.error('uart event not GATT error response...')
            return False

        if rev[:4] == errRsp:
            self.errRsp = rev

        return

    def mmi52(self,descript):
        logger.info(f'\n{descript}\n')

        if self.casename_b == b'GATT/SR/GAR/BV-04-C' or \
           self.casename_b == b'GATT/SR/GAR/BV-06-C' or \
           self.casename_b == b'GATT/SR/GAR/BV-07-C' or \
           self.casename_b == b'GATT/SR/GAR/BV-08-C':
            return True

        if len(self.readRsp) == 0:
            logger.error('No received characteristics value')
            return False

        value = 'value=\'{0}\''.format(self.readRsp)

        if value not in descript:
            logger.error('characteristics value: {0} not in database'.format(value))
            return False

        self.readRsp = str()

        return True

    def mmi53(self,descript):
        logger.info(f'\n{descript}\n')
        charPoint   = descript.find('handle')+10
        offsetPoint = descript.find('offset')+21
        charHandle  = bytes.fromhex(descript[charPoint:charPoint+4])
        valueOffset = bytes.fromhex(descript[offsetPoint:offsetPoint+4])

        while 1:
            value = b''.join([self.conninfo['connhandle'],
                              charHandle,
                              valueOffset])

            if not self.CommandRW(COMMAND = [api.Layer_ID.BLE_GATT,
                                             api.GATT_CMD_ID.READ,
                                             value],
                                  EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                             api.Layer_ID.BLE_GATT,
                                             api.GATT_CMD_ID.READ]):
                return False

            readRsp = b''.join([api.Layer_ID.BLE_GATT.value,
                                api.GATT_Event_ID.READ_RESP.value,
                                self.conninfo['connhandle']])

            errRsp  = b''.join([api.Layer_ID.BLE_GATT.value,
                                api.GATT_Event_ID.ERROR_RESP.value,
                                self.conninfo['connhandle']])

            rev = self.readEvent()

            if not rev:
                logger.error('uart event not GATT discovery characteristics descriptors response...')
                return False

            if rev[:4] == errRsp:
                self.errRsp = rev
                break

            if rev[:4] == readRsp:

                if rev[5:7] == b'\x00\x00':
                    break

                value = rev[7:].hex().upper()

                self.readRsp = ''.join([self.readRsp,value])

                if len(rev[7:]) == int(self.ixit[b'TSPX_mtu_size'][1])-1:
                    valueOffset = (int(bytes.hex(valueOffset),16) +
                                   int(self.ixit[b'TSPX_mtu_size'][1])-1).to_bytes(2,'big')
                    continue

            break

        return

    def mmi58(self,descript):
        logger.info(f'\n{descript}\n')
        charPoint   = descript.find('handle')+10
        charHandle  = bytes.fromhex(descript[charPoint:charPoint+4])
        valueOffset = bytes(2)

        while 1:
            value = b''.join([self.conninfo['connhandle'],
                              charHandle,
                              valueOffset])

            if not self.CommandRW(COMMAND = [api.Layer_ID.BLE_GATT,
                                             api.GATT_CMD_ID.READ,
                                             value],
                                  EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                             api.Layer_ID.BLE_GATT,
                                             api.GATT_CMD_ID.READ]):
                return False

            readRsp = b''.join([api.Layer_ID.BLE_GATT.value,
                                api.GATT_Event_ID.READ_RESP.value,
                                self.conninfo['connhandle']])

            errRsp  = b''.join([api.Layer_ID.BLE_GATT.value,
                                api.GATT_Event_ID.ERROR_RESP.value,
                                self.conninfo['connhandle']])

            rev = self.readEvent()

            if not rev:
                logger.error('uart event not GATT discovery characteristics descriptors response...')
                return False

            if rev[:4] == errRsp:
                self.errRsp = rev
                break

            if rev[:4] == readRsp:

                if rev[5:7] == b'\x00\x00':
                    break

                value = rev[7:].hex().upper()

                self.readRsp = ''.join([self.readRsp,value])

                if len(rev[7:]) == int(self.ixit[b'TSPX_mtu_size'][1])-1:
                    valueOffset = (int(bytes.hex(valueOffset),16) +
                                   int(self.ixit[b'TSPX_mtu_size'][1])-1).to_bytes(2,'big')
                    continue

            break

        return

    def mmi59(self,descript):
        logger.info(f'\n{descript}\n')

        if len(self.readRsp) == 0:
            logger.error('No received characteristics value')
            return False

        value = 'value=\'{0}\''.format(self.readRsp)

        if value not in descript:
            logger.error('characteristics value: {0} not in database'.format(value))
            return False

        self.readRsp = str()

        return True

    def mmi61(self,descript):
        logger.info(f'\n{descript}\n')

        if self.errRsp[7:] == api.GATT_ERROR_CODES.INVALID_HANDLE.value:
            return True
        else:
            logger.error('GATT error code is {0} ,not {1}'.format(self.errRsp[7:],
                                                                  api.GATT_ERROR_CODES.INVALID_HANDLE.value))
            return False

    def mmi62(self,descript):
        logger.info(f'\n{descript}\n')

        if self.errRsp[7:] == api.GATT_ERROR_CODES.WRITE_NOT_PERMITTED.value:
            return True
        else:
            logger.error('GATT error code is {0} ,not {1}'.format(self.errRsp[7:],
                                                                  api.GATT_ERROR_CODES.WRITE_NOT_PERMITTED.value))
            return False

    def mmi63(self,descript):
        logger.info(f'\n{descript}\n')

        if self.errRsp[7:] == api.GATT_ERROR_CODES.INSUFFICIENT_AUTHORIZATION.value:
            return True
        else:
            logger.error('GATT error code is {0} ,not {1}'.format(self.errRsp[7:],
                                                            api.GATT_ERROR_CODES.INSUFFICIENT_AUTHORIZATION.value))
            return False

    def mmi64(self,descript):
        logger.info(f'\n{descript}\n')

        if self.errRsp[7:] == api.GATT_ERROR_CODES.INSUFFICIENT_AUTHENTICATION.value:
            return True
        else:
            logger.error('GATT error code is {0} ,not {1}'.format(self.errRsp[7:],
                                                            api.GATT_ERROR_CODES.INSUFFICIENT_AUTHENTICATION.value))
            return False

    def mmi65(self,descript):
        logger.info(f'\n{descript}\n')

        if self.errRsp[7:] == api.GATT_ERROR_CODES.INSUFFICIENT_ENCRYPTION_KEY_SIZE.value:
            return True
        else:
            logger.error('GATT error code is {0} ,not {1}'.format(self.errRsp[7:],
                                                        api.GATT_ERROR_CODES.INSUFFICIENT_ENCRYPTION_KEY_SIZE.value))
            return False

    def mmi66(self,descript):
        logger.info(f'\n{descript}\n')

        if self.errRsp[7:] == api.GATT_ERROR_CODES.INVALID_OFFSET.value:
            return True
        else:
            logger.error('GATT error code is {0} ,not {1}'.format(self.errRsp[7:],
                                                                  api.GATT_ERROR_CODES.INVALID_OFFSET.value))
            return False

    def mmi67(self,descript):
        logger.info(f'\n{descript}\n')

        if self.casename_b == b'GATT/CL/GAW/BI-33-C':
            if self.errRsp[7:] == api.GATT_ERROR_CODES.INVALID_ATTRIBUTE_VALUE_LENGTH.value:
                return True
            else:
                logger.error('GATT error code is {0} ,not {1}'.format(self.errRsp[7:],
                                                    api.GATT_ERROR_CODES.INVALID_ATTRIBUTE_VALUE_LENGTH.value))
            return False

        if self.errRsp[7:] == api.GATT_ERROR_CODES.INVALID_OFFSET.value:
            return True
        else:
            logger.error('GATT error code is {0} ,not {1}'.format(self.errRsp[7:],
                                                                  api.GATT_ERROR_CODES.INVALID_OFFSET.value))
            return False

    def mmi69(self,descript):
        logger.info(f'\n{descript}\n')
        charPoint    = descript.find('handle') + 10
        charHandle   = bytes.fromhex(descript[charPoint:charPoint+4])
        charValue    = b''.join([value for value in [num.to_bytes(1,'big') for num in range(18)]])
        valueOffset  = bytes(2)
        flag         = api.GATT_EXEC_WRITE_FLAGS.CANCEL_ALL.value
        writeData    = b''.join([self.conninfo['connhandle'],
                                 charHandle,
                                 len(charValue).to_bytes(2,'big'),
                                 charValue,
                                 api.GATT_WRITE_TYPES.PREP_WRITE_REQ.value,
                                 valueOffset,
                                 flag])

        if self.CommandRW(COMMAND = [api.Layer_ID.BLE_GATT,
                                     api.GATT_CMD_ID.WRITE,
                                     writeData],
                          EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                     api.Layer_ID.BLE_GATT,
                                     api.GATT_CMD_ID.WRITE]):
            writeRsp = b''.join([api.Layer_ID.BLE_GATT.value,
                                api.GATT_Event_ID.WRITE_RESP.value,
                                self.conninfo['connhandle']])

            errRsp  = b''.join([api.Layer_ID.BLE_GATT.value,
                                api.GATT_Event_ID.ERROR_RESP.value,
                                self.conninfo['connhandle']])

            rev = self.readEvent()

            if not rev:
                logger.error('uart event not received GATT write response...')
                return False

            if rev[:4] == errRsp:
                self.errRsp = rev
                return

            if rev[:4] == writeRsp:
                self.writeRsp = rev
                return

        else:
            return False

    def mmi70(self,descript):
        logger.info(f'\n{descript}\n')
        charPoint    = descript.find('handle') + 10
        charHandle   = bytes.fromhex(descript[charPoint:charPoint+4])
        valuePoint1  = descript.find('<=') + 4
        valuePoint2  = descript.find('\' byte')
        valueNums    = int(descript[valuePoint1:valuePoint2])
        valueOffset  = bytes(2)
        flag         = api.GATT_EXEC_WRITE_FLAGS.CANCEL_ALL.value

        while valueNums > 0:
            if valueNums < 18:
                charValue = b''.join([value for value in [num.to_bytes(1,'big') for num in range(valueNums)]])
            else:
                charValue = b''.join([value for value in [num.to_bytes(1, 'big') for num in range(18)]])

            writeData    = b''.join([self.conninfo['connhandle'],
                                     charHandle,
                                     len(charValue).to_bytes(2,'big'),
                                     charValue,
                                     api.GATT_WRITE_TYPES.WRITE_CMD.value,
                                     valueOffset,
                                     flag])

            if not self.CommandRW(COMMAND = [api.Layer_ID.BLE_GATT,
                                             api.GATT_CMD_ID.WRITE,
                                             writeData],
                                  EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                             api.Layer_ID.BLE_GATT,
                                             api.GATT_CMD_ID.WRITE]):
                return False

            valueNums -= 18

            if valueNums > 18:
                valueOffset = (int(bytes.hex(valueOffset),16) + 18).to_bytes(2,'big')
                continue

            if valueNums > 0:
                valueOffset = (int(bytes.hex(valueOffset),16) + valueNums).to_bytes(2,'big')

        return

    def mmi71(self, descript):
        logger.info(f'\n{descript}\n')

        time.sleep(30)

        if self.CommandRW(EVENT=[api.Layer_ID.BLE_GATT,
                                 api.GATT_Event_ID.TIMEOUT,
                                 b'']):
            return
        else:
            return False

    def mmi74(self,descript):
        logger.info(f'\n{descript}\n')
        charPoint    = descript.find('handle') + 10
        charHandle   = bytes.fromhex(descript[charPoint:charPoint+4])
        valuePoint1  = descript.find('<=') + 4
        valuePoint2  = descript.find('\' byte')
        valueNums    = int(descript[valuePoint1:valuePoint2])
        valueOffset  = bytes(2)
        flag         = api.GATT_EXEC_WRITE_FLAGS.CANCEL_ALL.value

        while valueNums > 0:
            if valueNums < 18:
                charValue = b''.join([value for value in [num.to_bytes(1,'big') for num in range(valueNums)]])
            else:
                charValue = b''.join([value for value in [num.to_bytes(1, 'big') for num in range(18)]])

            writeData = b''.join([self.conninfo['connhandle'],
                                  charHandle,
                                  len(charValue).to_bytes(2, 'big'),
                                  charValue,
                                  api.GATT_WRITE_TYPES.WRITE_REQ.value,
                                  valueOffset,
                                  flag])

            if not self.CommandRW(COMMAND = [api.Layer_ID.BLE_GATT,
                                             api.GATT_CMD_ID.WRITE,
                                             writeData],
                                  EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                             api.Layer_ID.BLE_GATT,
                                             api.GATT_CMD_ID.WRITE]):
                return False

            if self.casename_b == b'GATT/CL/GAT/BV-02-C':
                return

            writeRsp = b''.join([api.Layer_ID.BLE_GATT.value,
                                api.GATT_Event_ID.WRITE_RESP.value,
                                self.conninfo['connhandle']])

            errRsp  = b''.join([api.Layer_ID.BLE_GATT.value,
                                api.GATT_Event_ID.ERROR_RESP.value,
                                self.conninfo['connhandle']])

            rev = self.readEvent()

            if not rev:
                logger.error('uart event not received GATT write response...')
                return False

            if rev[:4] == errRsp:
                self.errRsp = rev

            if rev[:4] == writeRsp:
                self.writeRsp = rev

            valueNums -= 18

            if valueNums > 18:
                valueOffset = (int(bytes.hex(valueOffset),16) + 18).to_bytes(2,'big')
                continue

            if valueNums > 0:
                valueOffset = (int(bytes.hex(valueOffset),16) + valueNums).to_bytes(2,'big')

        return

    def mmi75(self,descript):
        logger.info(f'\n{descript}\n')

        rev = self.CommandRW(EVENT = [api.Layer_ID.PTS_TEST,
                                      api.PTS_TEST_Event_ID.GATTS_WRITE,
                                      self.conninfo['connhandle']],
                             back  = True)

        if not rev:
            return False

        handle = rev[4:6].hex().upper()
        value  = rev[12:].hex().upper()

        if 'characteristic handle= \'{0}\'O value= \'{1}\'O'.format(handle,value) in descript:
            return True
        else:
            return False

    def mmi76(self,descript):
        logger.info(f'\n{descript}\n')
        charPoint    = descript.find('handle') + 10
        charHandle   = bytes.fromhex(descript[charPoint:charPoint+4])
        charValue    = b''.join([value for value in [num.to_bytes(1,'big') for num in range(18)]])
        valueOffset  = bytes(2)
        flag         = api.GATT_EXEC_WRITE_FLAGS.CANCEL_ALL.value
        writeData    = b''.join([self.conninfo['connhandle'],
                                 charHandle,
                                 len(charValue).to_bytes(2,'big'),
                                 charValue,
                                 api.GATT_WRITE_TYPES.PREP_WRITE_REQ.value,
                                 valueOffset,
                                 flag])

        if self.CommandRW(COMMAND = [api.Layer_ID.BLE_GATT,
                                     api.GATT_CMD_ID.WRITE,
                                     writeData],
                          EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                     api.Layer_ID.BLE_GATT,
                                     api.GATT_CMD_ID.WRITE]):
            writeRsp = b''.join([api.Layer_ID.BLE_GATT.value,
                                api.GATT_Event_ID.WRITE_RESP.value,
                                self.conninfo['connhandle']])

            errRsp  = b''.join([api.Layer_ID.BLE_GATT.value,
                                api.GATT_Event_ID.ERROR_RESP.value,
                                self.conninfo['connhandle']])

            rev = self.readEvent()

            if not rev:
                logger.error('uart event not received GATT write response...')
                return False

            if rev[:4] == errRsp:
                self.errRsp = rev
                return

            if rev[:4] == writeRsp:
                self.writeRsp = rev
                return

        else:
            return False

    def mmi77(self,descript):
        logger.info(f'\n{descript}\n')
        charPoint    = descript.find('handle') + 10
        charHandle   = bytes.fromhex(descript[charPoint:charPoint+4])
        charValue    = b''.join([value for value in [num.to_bytes(1,'big') for num in range(18)]])
        offsetPoint1 = descript.find('greater than \'') + 14
        offsetPoint2 = descript.find('\' byte')
        valueOffset  = int(descript[offsetPoint1:offsetPoint2]).to_bytes(2,'big')
        flag         = api.GATT_EXEC_WRITE_FLAGS.CANCEL_ALL.value
        writeData    = b''.join([self.conninfo['connhandle'],
                                 charHandle,
                                 len(charValue).to_bytes(2,'big'),
                                 charValue,
                                 api.GATT_WRITE_TYPES.PREP_WRITE_REQ.value,
                                 valueOffset,
                                 flag])

        if self.CommandRW(COMMAND = [api.Layer_ID.BLE_GATT,
                                     api.GATT_CMD_ID.WRITE,
                                     writeData],
                          EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                     api.Layer_ID.BLE_GATT,
                                     api.GATT_CMD_ID.WRITE]):
            writeRsp = b''.join([api.Layer_ID.BLE_GATT.value,
                                api.GATT_Event_ID.WRITE_RESP.value,
                                self.conninfo['connhandle']])

            errRsp  = b''.join([api.Layer_ID.BLE_GATT.value,
                                api.GATT_Event_ID.ERROR_RESP.value,
                                self.conninfo['connhandle']])

            rev = self.readEvent()

            if not rev:
                logger.error('uart event not received GATT write response...')
                return False

            if rev[:4] == errRsp:
                self.errRsp = rev
                return

            if rev[:4] == writeRsp:
                self.writeRsp = rev
                return

        else:
            return False

    def mmi80(self,descript):
        logger.info(f'\n{descript}\n')
        charPoint    = descript.find('handle') + 10
        charHandle   = bytes.fromhex(descript[charPoint:charPoint+4])
        valuePoint1  = descript.find('greater than \'') + 14
        valuePoint2  = descript.find('\' byte')
        valueNums    = int(descript[valuePoint1:valuePoint2])
        valueOffset  = bytes(2)
        flag         = api.GATT_EXEC_WRITE_FLAGS.CANCEL_ALL.value
        while valueNums > 0:
            if valueNums < 18:
                charValue = b''.join([value for value in [num.to_bytes(1,'big') for num in range(valueNums)]])
            else:
                charValue = b''.join([value for value in [num.to_bytes(1, 'big') for num in range(18)]])

            writeData = b''.join([self.conninfo['connhandle'],
                                  charHandle,
                                  len(charValue).to_bytes(2, 'big'),
                                  charValue,
                                  api.GATT_WRITE_TYPES.WRITE_REQ.value,
                                  valueOffset,
                                  flag])

            if not self.CommandRW(COMMAND = [api.Layer_ID.BLE_GATT,
                                             api.GATT_CMD_ID.WRITE,
                                             writeData],
                                  EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                             api.Layer_ID.BLE_GATT,
                                             api.GATT_CMD_ID.WRITE]):
                return False

            writeRsp = b''.join([api.Layer_ID.BLE_GATT.value,
                                api.GATT_Event_ID.WRITE_RESP.value,
                                self.conninfo['connhandle']])

            errRsp  = b''.join([api.Layer_ID.BLE_GATT.value,
                                api.GATT_Event_ID.ERROR_RESP.value,
                                self.conninfo['connhandle']])

            rev = self.readEvent()

            if not rev:
                logger.error('uart event not received GATT write response...')
                return False

            if rev[:4] == errRsp:
                self.errRsp = rev

            if rev[:4] == writeRsp:
                self.writeRsp = rev

            valueNums -= 18

            if valueNums > 18:
                valueOffset = (int(bytes.hex(valueOffset),16) + 18).to_bytes(2,'big')
                continue

            if valueNums > 0:
                valueOffset = (int(bytes.hex(valueOffset),16) + valueNums).to_bytes(2,'big')

        return

    def mmi81(self,descript):
        logger.info(f'\n{descript}\n')
        charPoint    = descript.find('handle') + 10
        charHandle   = bytes.fromhex(descript[charPoint:charPoint+4])
        valuePoint1  = descript.find('greater than \'') + 14
        valuePoint2  = descript.find('\' byte')
        valueNums    = int(descript[valuePoint1:valuePoint2])
        valueOffset  = bytes(2)
        flag         = api.GATT_EXEC_WRITE_FLAGS.CANCEL_ALL.value

        while valueNums > 0:
            if valueNums < 18:
                charValue = b''.join([value for value in [num.to_bytes(1,'big') for num in range(valueNums)]])
            else:
                charValue = b''.join([value for value in [num.to_bytes(1, 'big') for num in range(18)]])

            writeData = b''.join([self.conninfo['connhandle'],
                                  charHandle,
                                  len(charValue).to_bytes(2, 'big'),
                                  charValue,
                                  api.GATT_WRITE_TYPES.PREP_WRITE_REQ.value,
                                  valueOffset,
                                  flag])

            if not self.CommandRW(COMMAND = [api.Layer_ID.BLE_GATT,
                                             api.GATT_CMD_ID.WRITE,
                                             writeData],
                                  EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                             api.Layer_ID.BLE_GATT,
                                             api.GATT_CMD_ID.WRITE]):
                return False

            writeRsp = b''.join([api.Layer_ID.BLE_GATT.value,
                                api.GATT_Event_ID.WRITE_RESP.value,
                                self.conninfo['connhandle']])

            errRsp  = b''.join([api.Layer_ID.BLE_GATT.value,
                                api.GATT_Event_ID.ERROR_RESP.value,
                                self.conninfo['connhandle']])

            rev = self.readEvent()

            if not rev:
                logger.error('uart event not received GATT write response...')
                return False

            if rev[:4] == errRsp:
                self.errRsp = rev

            if rev[:4] == writeRsp:
                self.writeRsp = rev

            valueNums -= 18

            if valueNums > 18:
                valueOffset = (int(bytes.hex(valueOffset),16) + 18).to_bytes(2,'big')
                continue

            if valueNums > 0:
                valueOffset = (int(bytes.hex(valueOffset),16) + valueNums).to_bytes(2,'big')

        return

    def mmi82(self,descript):
        logger.info(f'\n{descript}\n')
        charHandle   = bytes(2)
        charValue    = b''.join([value for value in [num.to_bytes(1,'big') for num in range(18)]])
        valueOffset  = bytes(2)
        flag         = api.GATT_EXEC_WRITE_FLAGS.WRITE.value
        if self.casename_b == b'GATT/CL/GAW/BI-32-C':
            flag = api.GATT_EXEC_WRITE_FLAGS.CANCEL_ALL.value

        writeData    = b''.join([self.conninfo['connhandle'],
                                 charHandle,
                                 len(charValue).to_bytes(2,'big'),
                                 charValue,
                                 api.GATT_WRITE_TYPES.EXEC_WRITE_REQ.value,
                                 valueOffset,
                                 flag])

        if self.CommandRW(COMMAND = [api.Layer_ID.BLE_GATT,
                                     api.GATT_CMD_ID.WRITE,
                                     writeData],
                          EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                     api.Layer_ID.BLE_GATT,
                                     api.GATT_CMD_ID.WRITE]):
            writeRsp = b''.join([api.Layer_ID.BLE_GATT.value,
                                api.GATT_Event_ID.WRITE_RESP.value,
                                self.conninfo['connhandle']])

            errRsp  = b''.join([api.Layer_ID.BLE_GATT.value,
                                api.GATT_Event_ID.ERROR_RESP.value,
                                self.conninfo['connhandle']])

            rev = self.readEvent()

            if not rev:
                logger.error('uart event not received GATT write response...')
                return False

            if rev[:4] == errRsp:
                self.errRsp = rev
                return

            if rev[:4] == writeRsp:
                self.writeRsp = rev
                return

        else:
            return False

    def mmi90(self,descript):
        logger.info(f'\n{descript}\n')

        if self.CommandRW(EVENT = [api.Layer_ID.BLE_GATT,
                                   api.GATT_Event_ID.HV_NOTIFY,
                                   self.conninfo['connhandle']]):
            return True
        else:
            return False

    def mmi91(self,descript):
        logger.info(f'\n{descript}\n')
        charPoint    = descript.find('handle') + 10
        charHandle   = bytes.fromhex(descript[charPoint:charPoint+4])
        charValue    = b'\x01\x00'
        valueOffset  = bytes(2)
        flag         = api.GATT_EXEC_WRITE_FLAGS.CANCEL_ALL.value
        writeData    = b''.join([self.conninfo['connhandle'],
                                 charHandle,
                                 len(charValue).to_bytes(2,'big'),
                                 charValue,
                                 api.GATT_WRITE_TYPES.WRITE_REQ.value,
                                 valueOffset,
                                 flag])

        if self.CommandRW(COMMAND = [api.Layer_ID.BLE_GATT,
                                     api.GATT_CMD_ID.WRITE,
                                     writeData],
                          EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                     api.Layer_ID.BLE_GATT,
                                     api.GATT_CMD_ID.WRITE]):
            writeRsp = b''.join([api.Layer_ID.BLE_GATT.value,
                                api.GATT_Event_ID.WRITE_RESP.value,
                                self.conninfo['connhandle']])

            errRsp  = b''.join([api.Layer_ID.BLE_GATT.value,
                                api.GATT_Event_ID.ERROR_RESP.value,
                                self.conninfo['connhandle']])

            rev = self.readEvent()

            if not rev:
                logger.error('uart event not received GATT write response...')
                return False

            if rev[:4] == errRsp:
                self.errRsp = rev
                return

            if rev[:4] == writeRsp:
                self.writeRsp = rev
                return

        else:
            return False

    def mmi92(self,descript):
        logger.info(f'\n{descript}\n')
        charPoint  = descript.find('handle') + 10
        charHandle = bytes.fromhex(descript[charPoint:charPoint+4])
        value      = (api.GATT_MTU_LENGTH.MAX_MTU_LEN.value - api.GATT_HEADER_SIZE.HANDLE_VALUE.value).to_bytes(2,'big')
        data       = b''.join([self.conninfo['connhandle'],
                               charHandle,
                               len(value).to_bytes(2,'big'),
                               value,
                               api.GATT_SEND_HV_TYPES.HV_NOTIFICATION.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.BLE_GATT,
                                     api.GATT_CMD_ID.SEND_HANDLE_VALUE,
                                     data],
                          EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                     api.Layer_ID.BLE_GATT,
                                     api.GATT_CMD_ID.SEND_HANDLE_VALUE]):
            return
        else:
            return False

    def mmi95(self,descript):
        logger.info(f'\n{descript}\n')

        if self.CommandRW(EVENT = [api.Layer_ID.BLE_GATT,
                                   api.GATT_Event_ID.HV_INDICATE,
                                   self.conninfo['connhandle']]):
            return True
        else:
            return False

    def mmi96(self,descript):
        logger.info(f'\n{descript}\n')
        return [True,'mmi']

    def mmi97(self,descript):
        logger.info(f'\n{descript}\n')
        time.sleep(30)
        return

    def mmi98(self,descript):
        logger.info(f'\n{descript}\n')
        charPoint  = descript.find('handle') + 10
        charHandle = bytes.fromhex(descript[charPoint:charPoint+4])
        value      = (api.GATT_MTU_LENGTH.MAX_MTU_LEN.value - api.GATT_HEADER_SIZE.HANDLE_VALUE.value).to_bytes(2,'big')
        data       = b''.join([self.conninfo['connhandle'],
                               charHandle,
                               len(value).to_bytes(2,'big'),
                               value,
                               api.GATT_SEND_HV_TYPES.HV_INDICATION.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.BLE_GATT,
                                     api.GATT_CMD_ID.SEND_HANDLE_VALUE,
                                     data],
                          EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                     api.Layer_ID.BLE_GATT,
                                     api.GATT_CMD_ID.SEND_HANDLE_VALUE]):
            return
        else:
            return False

    def mmi99(self,descript):
        logger.info(f'\n{descript}\n')
        charPoint    = descript.find('handle') + 10
        charHandle   = bytes.fromhex(descript[charPoint:charPoint+4])
        charValue    = b'\x02\x00'
        valueOffset  = bytes(2)
        flag         = api.GATT_EXEC_WRITE_FLAGS.CANCEL_ALL.value
        writeData    = b''.join([self.conninfo['connhandle'],
                                 charHandle,
                                 len(charValue).to_bytes(2,'big'),
                                 charValue,
                                 api.GATT_WRITE_TYPES.WRITE_REQ.value,
                                 valueOffset,
                                 flag])

        if self.CommandRW(COMMAND = [api.Layer_ID.BLE_GATT,
                                     api.GATT_CMD_ID.WRITE,
                                     writeData],
                          EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                     api.Layer_ID.BLE_GATT,
                                     api.GATT_CMD_ID.WRITE]):
            writeRsp = b''.join([api.Layer_ID.BLE_GATT.value,
                                api.GATT_Event_ID.WRITE_RESP.value,
                                self.conninfo['connhandle']])

            errRsp  = b''.join([api.Layer_ID.BLE_GATT.value,
                                api.GATT_Event_ID.ERROR_RESP.value,
                                self.conninfo['connhandle']])

            rev = self.readEvent()

            if not rev:
                logger.error('uart event not received GATT write response...')
                return False

            if rev[:4] == errRsp:
                self.errRsp = rev
                return

            if rev[:4] == writeRsp:
                self.writeRsp = rev
                return

        else:
            return False

    def mmi108(self,descript):
        logger.info(f'\n{descript}\n')
        startHandle = b'\x00\x01'
        endHandle   = b'\xFF\xFF'
        uuidValue   = bytes.fromhex(descript[descript.find('UUID')+8:descript.find('O')-1])
        uuid        = b''.join([self.conninfo['connhandle'],
                                startHandle,
                                endHandle,
                                len(uuidValue).to_bytes(1,'big'),
                                uuidValue])

        if self.CommandRW(COMMAND = [api.Layer_ID.BLE_GATT,
                                     api.GATT_CMD_ID.READ_USING_UUID,
                                     uuid],
                          EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                     api.Layer_ID.BLE_GATT,
                                     api.GATT_CMD_ID.READ_USING_UUID]):

            rev = self.CommandRW(EVENT = [api.Layer_ID.BLE_GATT,
                                          api.GATT_Event_ID.READ_USING_UUID_RESP,
                                          self.conninfo['connhandle']],
                                 back  =  True)

            if not rev:
                return False

            pairLength  = int(bytes.hex(rev[4:5]),16)
            dataLength  = int(bytes.hex(rev[5:6]),16)*256 + int(bytes.hex(rev[6:7]),16)
            attrData    = rev[8:]
            groupNumber = int(len(attrData) / (dataLength / pairLength))
            services    = [attrData[i:i+groupNumber] for i in range(0,len(attrData),groupNumber)]

            for service in services:
                if len(service) == 0:
                    return False
                self.readRspUUID.append(service.hex().upper())

            return

        else:
            return False

    def mmi109(self,descript):
        logger.info(f'\n{descript}\n')
        startHandle = b'\x00\x01'
        endHandle   = b'\xFF\xFF'
        uuidValue   = bytes.fromhex(descript[descript.find('UUID')+8:descript.find('O')-1].replace('-',''))
        uuid        = b''.join([self.conninfo['connhandle'],
                                startHandle,
                                endHandle,
                                len(uuidValue).to_bytes(1,'big'),
                                uuidValue])

        if self.CommandRW(COMMAND = [api.Layer_ID.BLE_GATT,
                                     api.GATT_CMD_ID.READ_USING_UUID,
                                     uuid],
                          EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                     api.Layer_ID.BLE_GATT,
                                     api.GATT_CMD_ID.READ_USING_UUID]):

            rev = self.CommandRW(EVENT = [api.Layer_ID.BLE_GATT,
                                          api.GATT_Event_ID.READ_USING_UUID_RESP,
                                          self.conninfo['connhandle']],
                                 back  =  True)

            if not rev:
                return False

            pairLength = int(bytes.hex(rev[4:5]), 16)
            dataLength = int(bytes.hex(rev[5:6]), 16) * 256 + int(bytes.hex(rev[6:7]), 16)
            attrData = rev[8:]
            groupNumber = int(len(attrData) / (dataLength / pairLength))
            services = [attrData[i:i + groupNumber] for i in range(0, len(attrData), groupNumber)]

            for service in services:
                if len(service) == 0:
                    return False
                self.readRspUUID.append(service.hex().upper())

            return
        else:
            return False

    def mmi110(self,descript):
        logger.info(f'\n{descript}\n')
        return b'0052'

    def mmi111(self,descript):
        logger.info(f'\n{descript}\n')
        return b'0000b001000000000000000049535343'

    def mmi114(self,descript):
        logger.info(f'\n{descript}\n')
        return b'005E'

    def mmi115(self,descript):
        logger.info(f'\n{descript}\n')
        return b'0000B006000000000000000049535343'

    def mmi116(self,descript):
        logger.info(f'\n{descript}\n')
        return b'0062'

    def mmi117(self,descript):
        logger.info(f'\n{descript}\n')
        return b'0064'

    def mmi118(self,descript):
        logger.info(f'\n{descript}\n')
        return b'5566'

    def mmi119(self,descript):
        logger.info(f'\n{descript}\n')
        return b'181D'

    def mmi120(self,descript):
        logger.info(f'\n{descript}\n')
        return b'0052'

    def mmi121(self,descript):
        logger.info(f'\n{descript}\n')
        return b'005C'

    def mmi122(self,descript):
        logger.info(f'\n{descript}\n')
        return b'0000b005000000000000000049535343'

    def mmi130(self,descript):
        logger.info(f'\n{descript}\n')
        return True

    def mmi132(self,descript):
        logger.info(f'\n{descript}\n')

        if self.services:
            if self.CommandRW(COMMAND = [api.Layer_ID.BLE_GATT,
                                         api.GATT_CMD_ID.ADD_SERVICE,
                                         b''],
                              EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                         api.Layer_ID.BLE_GATT,
                                         api.GATT_CMD_ID.ADD_SERVICE]):

                if self.CommandRW(COMMAND = [api.Layer_ID.BLE_GATT,
                                             api.GATT_CMD_ID.SERVICE_CHANGE,
                                             b''],
                                  EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                             api.Layer_ID.BLE_GATT,
                                             api.GATT_CMD_ID.SERVICE_CHANGE]):
                    self.services = None
                    return [True,'mmi']

                else:
                    return False

            else:
                return False

        if self.CommandRW(COMMAND = [api.Layer_ID.BLE_GATT,
                                     api.GATT_CMD_ID.REMOVE_SERVICE,
                                     b''],
                          EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                     api.Layer_ID.BLE_GATT,
                                     api.GATT_CMD_ID.REMOVE_SERVICE]):

            if self.CommandRW(COMMAND = [api.Layer_ID.BLE_GATT,
                                         api.GATT_CMD_ID.SERVICE_CHANGE,
                                         b''],
                              EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                         api.Layer_ID.BLE_GATT,
                                         api.GATT_CMD_ID.SERVICE_CHANGE]):
                self.services = True
                return [True,'mmi']

            else:
                return False

        else:
            return False

    def mmi133(self,descript):
        logger.info(f'\n{descript}\n')
        return True

    def mmi134(self,descript):
        logger.info(f'\n{descript}\n')
        return True

    def mmi135(self,descript):
        logger.info(f'\n{descript}\n')
        charPoint    = descript.find('handle') + 10
        charHandle   = bytes.fromhex(descript[charPoint:charPoint+4])
        charValue    = b'\x01'
        valueOffset  = bytes(2)
        flag         = api.GATT_EXEC_WRITE_FLAGS.CANCEL_ALL.value
        writeData    = b''.join([self.conninfo['connhandle'],
                                 charHandle,
                                 len(charValue).to_bytes(2,'big'),
                                 charValue,
                                 api.GATT_WRITE_TYPES.WRITE_REQ.value,
                                 valueOffset,
                                 flag])

        if self.CommandRW(COMMAND = [api.Layer_ID.BLE_GATT,
                                     api.GATT_CMD_ID.WRITE,
                                     writeData],
                          EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                     api.Layer_ID.BLE_GATT,
                                     api.GATT_CMD_ID.WRITE]):
            writeRsp = b''.join([api.Layer_ID.BLE_GATT.value,
                                api.GATT_Event_ID.WRITE_RESP.value,
                                self.conninfo['connhandle']])

            errRsp  = b''.join([api.Layer_ID.BLE_GATT.value,
                                api.GATT_Event_ID.ERROR_RESP.value,
                                self.conninfo['connhandle']])

            rev = self.readEvent()

            if not rev:
                logger.error('uart event not received GATT write response...')
                return False

            if rev[:4] == errRsp:
                self.errRsp = rev
                return

            if rev[:4] == writeRsp:
                self.writeRsp = rev
                return

        else:
            return False

    def mmi136(self,descript):
        logger.info(f'\n{descript}\n')

        if self.services:
            if self.CommandRW(COMMAND = [api.Layer_ID.BLE_GATT,
                                         api.GATT_CMD_ID.ADD_SERVICE,
                                         b''],
                              EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                         api.Layer_ID.BLE_GATT,
                                         api.GATT_CMD_ID.ADD_SERVICE]):

                if self.CommandRW(COMMAND = [api.Layer_ID.BLE_GATT,
                                             api.GATT_CMD_ID.SERVICE_CHANGE,
                                             b''],
                                  EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                             api.Layer_ID.BLE_GATT,
                                             api.GATT_CMD_ID.SERVICE_CHANGE]):
                    self.services = None
                    return [None,'mmi']

            else:
                return False

        if self.CommandRW(COMMAND = [api.Layer_ID.BLE_GATT,
                                     api.GATT_CMD_ID.REMOVE_SERVICE,
                                     b''],
                          EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                     api.Layer_ID.BLE_GATT,
                                     api.GATT_CMD_ID.REMOVE_SERVICE]):

            if self.CommandRW(COMMAND = [api.Layer_ID.BLE_GATT,
                                         api.GATT_CMD_ID.SERVICE_CHANGE,
                                         b''],
                              EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                         api.Layer_ID.BLE_GATT,
                                         api.GATT_CMD_ID.SERVICE_CHANGE]):
                self.services = True
                return [None,'mmi']

            else:
                return False

    def mmi138(self,descript):
        logger.info(f'\n{descript}\n')
        charPoint    = descript.find('handle') + 9
        charHandle   = bytes.fromhex(descript[charPoint:charPoint+4])

        rev = self.CommandRW(COMMAND = [api.Layer_ID.BLE_GATT,
                                        api.GATT_CMD_ID.GET_ATTRIBUTE_VALUE,
                                        charHandle],
                             EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                        api.Layer_ID.BLE_GATT,
                                        api.GATT_CMD_ID.GET_ATTRIBUTE_VALUE],
                             back    = True)

        if not rev:
            logger.error('no received pts get attribute value event')
            return False

        self.readRsp = rev[5:]

        return True

    def mmi139(self,descript):
        logger.info(f'\n{descript}\n')
        charPoint    = descript.find('handle') + 9
        charHandle   = bytes.fromhex(descript[charPoint:charPoint+4])

        rev = self.CommandRW(COMMAND = [api.Layer_ID.BLE_GATT,
                                        api.GATT_CMD_ID.GET_ATTRIBUTE_VALUE,
                                        charHandle],
                             EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                        api.Layer_ID.BLE_GATT,
                                        api.GATT_CMD_ID.GET_ATTRIBUTE_VALUE],
                             back    = True)

        if not rev:
            logger.error('no received pts get attribute value event')
            return False

        if rev[5:] != self.readRsp:
            logger.error('attribute value event is diffence')
            logger.error('current attribute value : {0}'.format(rev[5:]))
            logger.error('before  attribute value : {0}'.format(self.readRsp))
            return False

        return True

class GAVDP(Common):
    def __init__(self,comport,profile,casename,ptsaddress_b,ixit,bleonly):
        Common.__init__(self,comport,profile,casename,ptsaddress_b,ixit,bleonly)
        self.id       = b'\x00'
        self.conninfo = None

    def mmi(self,descript):
        return

    def mmi1013(self,descript):
        logger.info(''.join(['\n', descript,'\n']))

        if self.casename_b == b'GAVDP/INT/APP/TRC/BV-01-C' or \
           self.casename_b == b'GAVDP/INT/APP/TRC/BV-02-C':
            return True

        conninfo = self.get_connetion_info()

        if not conninfo:
            return False

        self.conninfo = conninfo

        time.sleep(1)

        if self.CommandRW(EVENT = [api.Layer_ID.AVDTP,
                                   api.AVDTP_Event_ID.CONNECT_COMPLETE_CFM,
                                   self.id]):
                return True
        else:
            return False

    def mmi1016(self,descript):
        logger.info(''.join(['\n', descript,'\n']))

        conninfo = self.get_connetion_info()

        if not conninfo:
            return False

        self.conninfo = conninfo

        time.sleep(1)

        avdtpId = b'\x00'
        mtu     = bytes(2)
        connect_req = b''.join([self.conninfo['connhandle'],mtu])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVDTP,
                                     api.AVDTP_CMD_ID.CONNECT_REQ,
                                     connect_req],
                          EVENT   = [api.Layer_ID.AVDTP,
                                     api.AVDTP_Event_ID.CONNECT_COMPLETE_CFM,
                                     avdtpId]):
            return
        else:
            return False

    def mmi1020(self,descript):
        logger.info(''.join(['\n', descript,'\n']))
        avdtpId = b'\x00'
        acpSeid = b'\x01'
        req     = b''.join([avdtpId,acpSeid])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVDTP,
                                     api.AVDTP_CMD_ID.OPEN_REQ,
                                     req],
                          EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                     api.Layer_ID.AVDTP,
                                     api.AVDTP_CMD_ID.OPEN_REQ]):
            return
        else:
            return False

    def mmi1030(self,descript):
        logger.info(''.join(['\n', descript,'\n']))
        acpSeid = b'\x01'
        req     = b''.join([self.id, acpSeid])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVDTP,
                                     api.AVDTP_CMD_ID.SUSPEND_REQ,
                                     req],
                          EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                     api.Layer_ID.AVDTP,
                                     api.AVDTP_CMD_ID.SUSPEND_REQ]):

            time.sleep(1)
            if self.CommandRW(COMMAND = [api.Layer_ID.AVDTP,
                                         api.AVDTP_CMD_ID.RECONFIGURATION_REQ,
                                         req],
                              EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                         api.Layer_ID.AVDTP,
                                         api.AVDTP_CMD_ID.RECONFIGURATION_REQ]):
                return
            else:
                return False
        else:
            return False

    def mmi1031(self,descript):
        logger.info(''.join(['\n', descript,'\n']))

        avdtpId        = b'\x00'
        acpSeid        = b'\x01'
        intSeid        = b'\x02'
        NonDelayReport = b'\x00'
        config         = b''.join([avdtpId, acpSeid, intSeid, NonDelayReport])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVDTP,
                                     api.AVDTP_CMD_ID.SETCONFIGURATION_REQ,
                                     config],
                          EVENT   = [api.Layer_ID.AVDTP,
                                     api.AVDTP_Event_ID.SET_CONFIGURATION_CFM,
                                     avdtpId]):
            return
        else:
            return False

    def mmi1034(self,descript):
        logger.info(''.join(['\n', descript,'\n']))
        acpSeid = b'\x01'
        req     = b''.join([self.id, acpSeid])

        if self.CommandRW(COMMAND = [api.Layer_ID.AVDTP,
                                     api.AVDTP_CMD_ID.SUSPEND_REQ,
                                     req],
                          EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                     api.Layer_ID.AVDTP,
                                     api.AVDTP_CMD_ID.SUSPEND_REQ]):
            return
        else:
            return False

class HFP(Common):
    def __init__(self,comport,profile,casename,ptsaddress_b,ixit,bleonly):
        Common.__init__(self,comport,profile,casename,ptsaddress_b,ixit,bleonly)
        self.id          = b'\x00'
        self.conninfo    = None
        self.wait        = None
        self.active_sco  = None
        self.call_action = None
        self.back        = None
        self.gainValue   = None

    def mmi(self,descript):
        if self.wait:
            time.sleep(self.wait)
            self.wait = None
            return

        if self.casename_b == b'HFP/HF/ACS/BV-03-I' or \
           self.casename_b == b'HFP/HF/ICA/BV-05-I' or \
           self.casename_b == b'HFP/HF/ATH/BV-05-I' or \
           self.casename_b == b'HFP/HF/ACC/BV-02-I' or \
           self.casename_b == b'HFP/HF/ACC/BV-04-I' or \
           self.casename_b == b'HFP/HF/ACC/BV-05-I' or \
           self.casename_b == b'HFP/HF/ACC/BV-06-I' or \
           self.casename_b == b'HFP/HF/ACC/BV-07-I':
            if not self.conninfo:
                conninfo = self.get_connetion_info()

                if not conninfo:
                    return False

                self.conninfo = conninfo

                if self.CommandRW(EVENT = [api.Layer_ID.BT_GAP,
                                           api.BT_GAP_Event_ID.CONNECT_REQUEST,
                                           bytes.fromhex(self.pts_address_b.decode())[::-1]]):
                    transmitBandwidth = b'\x00\x10\x00\x00'
                    receiveBandwidth  = b'\x00\x10\x00\x00'
                    contentFormat     = b'\x00\x33'
                    packetType        = b'\x00\x3F'
                    acceptSyn         = b''.join([bytes.fromhex(self.pts_address_b.decode())[::-1],
                                                  transmitBandwidth,
                                                  receiveBandwidth,
                                                  api.BT_GAP_SYNC_CONN_MAX_LATENCY.LATENCY_MAX.value,
                                                  contentFormat,
                                                  api.BT_GAP_SYNC_CONN_RETRANSMIT_EFFORT.DONT_CARE.value,
                                                  packetType])

                    sync = self.CommandRW(COMMAND = [api.Layer_ID.BT_GAP,
                                                     api.BT_GAP_CMD_ID.ACCEPT_SYNCHRONOUS_CONNECTION,
                                                     acceptSyn],
                                          EVENT   = [api.Layer_ID.BT_GAP,
                                                     api.BT_GAP_Event_ID.SYNCHRONOUS_CONNECTION_COMPLETE,
                                                     api.BT_GAP_Status_ID.SUCCESS],
                                          back    =  True)

                    if not sync:
                        return False

                    self.active_sco = sync[4:5]

                    return
                else:
                    return

        if self.conninfo:
            if self.back:
                return

            if self.casename_b == b'HFP/HF/PSI/BV-01-C':
                return

            if self.casename_b == b'HFP/HF/TCA/BV-04-I' or \
               self.casename_b == b'HFP/HF/OCN/BV-01-I':
                phoneNumber = b''.join([len(self.ixit[b'TSPX_phone_number'][1]).to_bytes(2,'big'),
                                        self.ixit[b'TSPX_phone_number'][1]])

                if self.CommandRW(COMMAND = [api.Layer_ID.BT_HFP,
                                             api.HFP_CMD_ID.DIAL_NUMBER,
                                             phoneNumber],
                                  EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                             api.Layer_ID.BT_HFP,
                                             api.HFP_CMD_ID.DIAL_NUMBER]):

                    if self.CommandRW(EVENT = [api.Layer_ID.BT_GAP,
                                               api.BT_GAP_Event_ID.CONNECT_REQUEST,
                                               bytes.fromhex(self.pts_address_b.decode())[::-1]]):
                        transmitBandwidth = b'\x00\x10\x00\x00'
                        receiveBandwidth  = b'\x00\x10\x00\x00'
                        contentFormat     = b'\x00\x33'
                        packetType        = b'\x00\x3F'
                        acceptSyn = b''.join([bytes.fromhex(self.pts_address_b.decode())[::-1],
                                              transmitBandwidth,
                                              receiveBandwidth,
                                              api.BT_GAP_SYNC_CONN_MAX_LATENCY.LATENCY_MAX.value,
                                              contentFormat,
                                              api.BT_GAP_SYNC_CONN_RETRANSMIT_EFFORT.DONT_CARE.value,
                                              packetType])

                        sync = self.CommandRW(COMMAND = [api.Layer_ID.BT_GAP,
                                                         api.BT_GAP_CMD_ID.ACCEPT_SYNCHRONOUS_CONNECTION,
                                                         acceptSyn],
                                              EVENT   = [api.Layer_ID.BT_GAP,
                                                         api.BT_GAP_Event_ID.SYNCHRONOUS_CONNECTION_COMPLETE,
                                                         api.BT_GAP_Status_ID.SUCCESS],
                                              back    =  True)

                        if not sync:
                            return False

                        self.active_sco = sync[4:5]

                        if self.casename_b == b'HFP/HF/OCN/BV-01-I':
                            return

                        outgoingCallAlerting = b''.join([self.id,
                                                         api.HFP_CallSetupStatus.OUTGOING_CALL_ALERTING.value])

                        if self.CommandRW(EVENT = [api.Layer_ID.BT_HFP,
                                                   api.HFP_Event_ID.CALL_SETUP_IND,
                                                   outgoingCallAlerting]):
                            if self.CommandRW(COMMAND = [api.Layer_ID.BT_HFP,
                                                         api.HFP_CMD_ID.CALL_TERMINATE,
                                                         self.id],
                                              EVENT   = [api.Layer_ID.BT_HFP,
                                                         api.HFP_Event_ID.CALL_TERMINATE_CFM,
                                                         self.id]):
                                return
                            else:
                                return False
                        else:
                            return False
                else:
                    return False

            if self.casename_b == b'HFP/HF/OCL/BV-01-I' or \
               self.casename_b == b'HFP/HF/OCL/BV-02-I':

                if self.CommandRW(COMMAND = [api.Layer_ID.BT_HFP,
                                             api.HFP_CMD_ID.DIAL_LAST_NUMBER,
                                             self.id],
                                  EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                             api.Layer_ID.BT_HFP,
                                             api.HFP_CMD_ID.DIAL_LAST_NUMBER]):

                    if self.casename_b == b'HFP/HF/OCL/BV-02-I':
                        return

                    if self.CommandRW(EVENT = [api.Layer_ID.BT_GAP,
                                               api.BT_GAP_Event_ID.CONNECT_REQUEST,
                                               bytes.fromhex(self.pts_address_b.decode())[::-1]]):
                        transmitBandwidth = b'\x00\x10\x00\x00'
                        receiveBandwidth  = b'\x00\x10\x00\x00'
                        contentFormat     = b'\x00\x33'
                        packetType        = b'\x00\x3F'
                        acceptSyn = b''.join([bytes.fromhex(self.pts_address_b.decode())[::-1],
                                              transmitBandwidth,
                                              receiveBandwidth,
                                              api.BT_GAP_SYNC_CONN_MAX_LATENCY.LATENCY_MAX.value,
                                              contentFormat,
                                              api.BT_GAP_SYNC_CONN_RETRANSMIT_EFFORT.DONT_CARE.value,
                                              packetType])

                        sync = self.CommandRW(COMMAND = [api.Layer_ID.BT_GAP,
                                                         api.BT_GAP_CMD_ID.ACCEPT_SYNCHRONOUS_CONNECTION,
                                                         acceptSyn],
                                              EVENT   = [api.Layer_ID.BT_GAP,
                                                         api.BT_GAP_Event_ID.SYNCHRONOUS_CONNECTION_COMPLETE,
                                                         api.BT_GAP_Status_ID.SUCCESS],
                                              back    =  True)

                        if not sync:
                            return False

                        self.active_sco = sync[4:5]

                        return
                else:
                    return False

            if self.conninfo == 'reconnect':

                if self.casename_b == b'HFP/HF/SLC/BV-01-C' or \
                   self.casename_b == b'HFP/HF/SLC/BV-03-C':
                    conninfo = self.get_connetion_info()
                else:
                    conninfo = self.create_connection('BT')

                if not conninfo:
                    return False

                self.conninfo = conninfo

                time.sleep(1)

                req = b''.join([self.conninfo['connhandle'],
                                api.HFP_Profile.HANDSFREE.value])

                if self.CommandRW(COMMAND = [api.Layer_ID.BT_HFP,
                                             api.HFP_CMD_ID.CONNECT_REQ,
                                             req],
                                  EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                             api.Layer_ID.BT_HFP,
                                             api.HFP_CMD_ID.CONNECT_REQ]):
                    return
                else:
                    return False

            rev = self.readEvent()

            if not rev:
                return False

            ringInd      = b''.join([api.Layer_ID.BT_HFP.value,
                                     api.HFP_Event_ID.RING_IND.value,
                                     self.id])

            callIdInd    = b''.join([api.Layer_ID.BT_HFP.value,
                                     api.HFP_Event_ID.CALLERID_IND.value,
                                     self.id])

            if rev[0:3] == ringInd or rev[0:3] == callIdInd :

                if self.casename_b == b'HFP/HF/ACS/BI-13-I' or \
                   self.casename_b == b'HFP/HF/ICA/BV-01-I' or \
                   self.casename_b == b'HFP/HF/ICA/BV-05-I':
                    if self.CommandRW(COMMAND = [api.Layer_ID.BT_HFP,
                                                 api.HFP_CMD_ID.CALL_ANSWER_ACCEPT,
                                                 self.id],
                                      EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                                 api.Layer_ID.BT_HFP,
                                                 api.HFP_CMD_ID.CALL_ANSWER_ACCEPT]):
                        return
                    else:
                        return False

                if self.casename_b == b'HFP/HF/ICR/BV-01-I':
                    if self.CommandRW(COMMAND = [api.Layer_ID.BT_HFP,
                                                 api.HFP_CMD_ID.CALL_ANSWER_REJECT,
                                                 self.id],
                                      EVENT   = [api.Layer_ID.BT_HFP,
                                                 api.HFP_Event_ID.CALL_TERMINATE_CFM,
                                                 self.id]):
                        return
                    else:
                        return False

                if self.CommandRW(COMMAND = [api.Layer_ID.BT_HFP,
                                             api.HFP_CMD_ID.CALL_ANSWER_ACCEPT,
                                             self.id],
                                  EVENT   = [api.Layer_ID.BT_HFP,
                                             api.HFP_Event_ID.CALL_ANSWER_CFM,
                                             self.id]):

                    if self.casename_b == b'HFP/HF/ICA/BV-02-I':
                        connReq = b''.join([api.Layer_ID.BT_GAP.value,
                                            api.BT_GAP_Event_ID.CONNECT_REQUEST.value,
                                            bytes.fromhex(self.pts_address_b.decode())[::-1]])

                        rev = self.readEvent()

                        if not rev:
                            return False

                        if connReq in rev:
                            transmitBandwidth = b'\x00\x10\x00\x00'
                            receiveBandwidth  = b'\x00\x10\x00\x00'
                            contentFormat     = b'\x00\x33'
                            packetType        = b'\x00\x3F'
                            acceptSyn         = b''.join([bytes.fromhex(self.pts_address_b.decode())[::-1],
                                                          transmitBandwidth,
                                                          receiveBandwidth,
                                                          api.BT_GAP_SYNC_CONN_MAX_LATENCY.LATENCY_MAX.value,
                                                          contentFormat,
                                                          api.BT_GAP_SYNC_CONN_RETRANSMIT_EFFORT.DONT_CARE.value,
                                                          packetType])

                            sync = self.CommandRW(COMMAND = [api.Layer_ID.BT_GAP,
                                                             api.BT_GAP_CMD_ID.ACCEPT_SYNCHRONOUS_CONNECTION,
                                                             acceptSyn],
                                                  EVENT   = [api.Layer_ID.BT_GAP,
                                                             api.BT_GAP_Event_ID.SYNCHRONOUS_CONNECTION_COMPLETE,
                                                             api.BT_GAP_Status_ID.SUCCESS],
                                                  back    =  True)

                            if not sync:
                                return False

                            self.active_sco = sync[4:5]

                            return
                        else:
                            return

                    if self.CommandRW(EVENT = [api.Layer_ID.BT_GAP,
                                               api.BT_GAP_Event_ID.CONNECT_REQUEST,
                                               bytes.fromhex(self.pts_address_b.decode())[::-1]]):
                        transmitBandwidth = b'\x00\x10\x00\x00'
                        receiveBandwidth  = b'\x00\x10\x00\x00'
                        contentFormat     = b'\x00\x33'
                        packetType        = b'\x00\x3F'
                        acceptSyn = b''.join([bytes.fromhex(self.pts_address_b.decode())[::-1],
                                              transmitBandwidth,
                                              receiveBandwidth,
                                              api.BT_GAP_SYNC_CONN_MAX_LATENCY.LATENCY_MAX.value,
                                              contentFormat,
                                              api.BT_GAP_SYNC_CONN_RETRANSMIT_EFFORT.DONT_CARE.value,
                                              packetType])

                        sync = self.CommandRW(COMMAND = [api.Layer_ID.BT_GAP,
                                                         api.BT_GAP_CMD_ID.ACCEPT_SYNCHRONOUS_CONNECTION,
                                                         acceptSyn],
                                              EVENT   = [api.Layer_ID.BT_GAP,
                                                         api.BT_GAP_Event_ID.SYNCHRONOUS_CONNECTION_COMPLETE,
                                                         api.BT_GAP_Status_ID.SUCCESS],
                                              back    =  True)

                        if not sync:
                            return False

                        self.active_sco = sync[4:5]

                        return
                else:
                    return False

            elif self.casename_b == b'HFP/HF/OOR/BV-02-I' or \
                 self.casename_b == b'HFP/HF/ATH/BV-03-I' or \
                 self.casename_b == b'HFP/HF/ACC/BV-03-I':
                if self.CommandRW(EVENT = [api.Layer_ID.BT_HFP,
                                           api.HFP_Event_ID.CONNECT_CFM,
                                           self.id]):
                    transmitBandwidth = b'\x00\x10\x00\x00'
                    receiveBandwidth  = b'\x00\x10\x00\x00'
                    voiceSetting      = bytes(2)
                    packetType        = b'\x00\x3F'
                    setupSyn          = b''.join([self.conninfo['connhandle'],
                                                  transmitBandwidth,
                                                  receiveBandwidth,
                                                  api.BT_GAP_SYNC_CONN_MAX_LATENCY.LATENCY_MAX.value,
                                                  voiceSetting,
                                                  api.BT_GAP_SYNC_CONN_RETRANSMIT_EFFORT.DONT_CARE.value,
                                                  packetType])

                    sync = self.CommandRW(COMMAND = [api.Layer_ID.BT_GAP,
                                                     api.BT_GAP_CMD_ID.SETUP_SYNCHRONOUS_CONNECTION,
                                                     setupSyn],
                                          EVENT   = [api.Layer_ID.BT_GAP,
                                                     api.BT_GAP_Event_ID.SYNCHRONOUS_CONNECTION_COMPLETE,
                                                     api.BT_GAP_Status_ID.SUCCESS],
                                          back    =  True)

                    if not sync:
                        return False

                    self.active_sco = sync[4:5]

                    return
                else:
                    return False

            elif self.casename_b == b'HFP/HF/ACS/BV-07-I' or \
                 self.casename_b == b'HFP/HF/ACS/BV-12-I' or \
                 self.casename_b == b'HFP/HF/ACR/BV-01-I' or \
                 self.casename_b == b'HFP/HF/ACR/BV-02-I':
                count = 0
                while 1:
                    connReq = b''.join([api.Layer_ID.BT_GAP.value,
                                        api.BT_GAP_Event_ID.CONNECT_REQUEST.value,
                                        bytes.fromhex(self.pts_address_b.decode())[::-1]])

                    hfpDisConnInd = b''.join([api.Layer_ID.BT_HFP.value,
                                              api.HFP_Event_ID.DISCONNECT_IND.value,
                                              self.id])

                    rev = self.readEvent()

                    if count == 20:
                        logger.error('not received connecttion request over 20 uart event')
                        return False

                    if not rev:
                        logger.error('not received connecttion request event')
                        return False

                    if rev[:3] == hfpDisConnInd:
                        return

                    if connReq in rev:
                        transmitBandwidth = b'\x00\x10\x00\x00'
                        receiveBandwidth = b'\x00\x10\x00\x00'
                        contentFormat = b'\x00\x33'
                        packetType = b'\x00\x3F'
                        acceptSyn = b''.join([bytes.fromhex(self.pts_address_b.decode())[::-1],
                                              transmitBandwidth,
                                              receiveBandwidth,
                                              api.BT_GAP_SYNC_CONN_MAX_LATENCY.LATENCY_MAX.value,
                                              contentFormat,
                                              api.BT_GAP_SYNC_CONN_RETRANSMIT_EFFORT.DONT_CARE.value,
                                              packetType])

                        sync = self.CommandRW(COMMAND = [api.Layer_ID.BT_GAP,
                                                         api.BT_GAP_CMD_ID.ACCEPT_SYNCHRONOUS_CONNECTION,
                                                         acceptSyn],
                                              EVENT   = [api.Layer_ID.BT_GAP,
                                                         api.BT_GAP_Event_ID.SYNCHRONOUS_CONNECTION_COMPLETE,
                                                         api.BT_GAP_Status_ID.SUCCESS],
                                              back    =  True)

                        if not sync:
                            return False

                        self.active_sco = sync[4:5]

                        return

                    count += 1

            elif self.casename_b == b'HFP/HF/ICA/BV-02-I' or \
                 self.casename_b == b'HFP/HF/TCA/BV-01-I':

                if self.CommandRW(COMMAND = [api.Layer_ID.BT_HFP,
                                             api.HFP_CMD_ID.CALL_TERMINATE,
                                             self.id],
                                  EVENT   = [api.Layer_ID.BT_HFP,
                                             api.HFP_Event_ID.CALL_TERMINATE_CFM,
                                             self.id]):
                    return
                else:
                    return False

            elif self.casename_b == b'HFP/HF/ATH/BV-04-I':
                transmitBandwidth = b'\x00\x10\x00\x00'
                receiveBandwidth  = b'\x00\x10\x00\x00'
                voiceSetting      = bytes(2)
                packetType        = b'\x00\x3F'
                setupSyn          = b''.join([self.conninfo['connhandle'],
                                              transmitBandwidth,
                                              receiveBandwidth,
                                              api.BT_GAP_SYNC_CONN_MAX_LATENCY.LATENCY_MAX.value,
                                              voiceSetting,
                                              api.BT_GAP_SYNC_CONN_RETRANSMIT_EFFORT.DONT_CARE.value,
                                              packetType])

                sync = self.CommandRW(COMMAND = [api.Layer_ID.BT_GAP,
                                                 api.BT_GAP_CMD_ID.SETUP_SYNCHRONOUS_CONNECTION,
                                                 setupSyn],
                                      EVENT   = [api.Layer_ID.BT_GAP,
                                                 api.BT_GAP_Event_ID.SYNCHRONOUS_CONNECTION_COMPLETE,
                                                 api.BT_GAP_Status_ID.SUCCESS],
                                      back    =  True)

                if not sync:
                    return False

                self.active_sco = sync[4:5]

                return

            elif self.casename_b == b'HFP/HF/ATH/BV-06-I' or \
                 self.casename_b == b'HFP/HF/VRA/BV-02-I':
                if self.CommandRW(EVENT = [api.Layer_ID.BT_GAP,
                                           api.BT_GAP_Event_ID.CONNECT_REQUEST,
                                           bytes.fromhex(self.pts_address_b.decode())[::-1]]):
                    transmitBandwidth = b'\x00\x10\x00\x00'
                    receiveBandwidth  = b'\x00\x10\x00\x00'
                    contentFormat     = b'\x00\x33'
                    packetType        = b'\x00\x3F'
                    acceptSyn         = b''.join([bytes.fromhex(self.pts_address_b.decode())[::-1],
                                                  transmitBandwidth,
                                                  receiveBandwidth,
                                                  api.BT_GAP_SYNC_CONN_MAX_LATENCY.LATENCY_MAX.value,
                                                  contentFormat,
                                                  api.BT_GAP_SYNC_CONN_RETRANSMIT_EFFORT.DONT_CARE.value,
                                                  packetType])

                    sync = self.CommandRW(COMMAND = [api.Layer_ID.BT_GAP,
                                                     api.BT_GAP_CMD_ID.ACCEPT_SYNCHRONOUS_CONNECTION,
                                                     acceptSyn],
                                          EVENT   = [api.Layer_ID.BT_GAP,
                                                     api.BT_GAP_Event_ID.SYNCHRONOUS_CONNECTION_COMPLETE,
                                                     api.BT_GAP_Status_ID.SUCCESS],
                                          back    =  True)

                    if not sync:
                        return False

                    self.active_sco = sync[4:5]

                    return

            elif self.casename_b == b'HFP/HF/TWC/BV-01-I' or \
                 self.casename_b == b'HFP/HF/TWC/BV-02-I' or \
                 self.casename_b == b'HFP/HF/TWC/BV-03-I' or \
                 self.casename_b == b'HFP/HF/TWC/BV-04-I' or \
                 self.casename_b == b'HFP/HF/TWC/BV-05-I' or \
                 self.casename_b == b'HFP/HF/TWC/BV-06-I':
                holdAction = b''.join([self.id,
                                       self.call_action])

                if self.CommandRW(COMMAND = [api.Layer_ID.BT_HFP,
                                             api.HFP_CMD_ID.CALL_HOLD_ACTION_REQ,
                                             holdAction],
                                  EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                             api.Layer_ID.BT_HFP,
                                             api.HFP_CMD_ID.CALL_HOLD_ACTION_REQ]):
                    return
                else:
                    return False

            elif self.casename_b == b'HFP/HF/ACC/BV-01-I' or \
                 self.casename_b == b'HFP/HF/ACC/BV-02-I':

                if self.CommandRW(COMMAND = [api.Layer_ID.BT_HFP,
                                             api.HFP_CMD_ID.AUDIO_TRANSFER_REQ,
                                             self.id],
                                  EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                             api.Layer_ID.BT_HFP,
                                             api.HFP_CMD_ID.AUDIO_TRANSFER_REQ]):

                    if self.CommandRW(EVENT = [api.Layer_ID.BT_GAP,
                                               api.BT_GAP_Event_ID.CONNECT_REQUEST,
                                               bytes.fromhex(self.pts_address_b.decode())[::-1]]):
                        transmitBandwidth = b'\x00\x10\x00\x00'
                        receiveBandwidth  = b'\x00\x10\x00\x00'
                        contentFormat     = b'\x00\x33'
                        packetType        = b'\x00\x3F'
                        acceptSyn         = b''.join([bytes.fromhex(self.pts_address_b.decode())[::-1],
                                                      transmitBandwidth,
                                                      receiveBandwidth,
                                                      api.BT_GAP_SYNC_CONN_MAX_LATENCY.LATENCY_MAX.value,
                                                      contentFormat,
                                                      api.BT_GAP_SYNC_CONN_RETRANSMIT_EFFORT.DONT_CARE.value,
                                                      packetType])

                        sync = self.CommandRW(COMMAND = [api.Layer_ID.BT_GAP,
                                                         api.BT_GAP_CMD_ID.ACCEPT_SYNCHRONOUS_CONNECTION,
                                                         acceptSyn],
                                              EVENT   = [api.Layer_ID.BT_GAP,
                                                         api.BT_GAP_Event_ID.SYNCHRONOUS_CONNECTION_COMPLETE,
                                                         api.BT_GAP_Status_ID.SUCCESS],
                                              back    =  True)

                        if not sync:
                            return False

                        self.active_sco = sync[4:5]

                        return

        return

    def mmi0(self,descript):
        logger.info(''.join(['\n', descript,'\n']))
        return True

    def mmi1(self,descript):
        logger.info(''.join(['\n', descript,'\n']))

        self.conninfo = 'reconnect'

        return [True,'mmi']

    def mmi3(self,descript):
        logger.info(''.join(['\n', descript,'\n']))

        if self.casename_b == b'HFP/HF/ACC/BV-03-I':
            conninfo = self.get_connetion_info()

            if not conninfo:
                return False

            self.conninfo = conninfo

            time.sleep(1)

        return [True,'mmi']

    def mmi9(self,descript):
        logger.info(f'\n{descript}\n')

        if self.casename_b == b'HFP/HF/CLI/BV-01-I' or \
           self.casename_b == b'HFP/HF/ICA/BV-01-I' or \
           self.casename_b == b'HFP/HF/ICA/BV-02-I' or \
           self.casename_b == b'HFP/HF/ICA/BV-03-I' or \
           self.casename_b == b'HFP/HF/ICA/BV-04-I' or \
           self.casename_b == b'HFP/HF/ICA/BV-05-I' or \
           self.casename_b == b'HFP/HF/ENO/BV-01-I':

            if self.CommandRW(EVENT = [api.Layer_ID.BT_HFP,
                                       api.HFP_Event_ID.RING_IND,
                                       self.id]):
                return [True, 'mmi']
            else:
                return False

        if self.casename_b == b'HFP/HF/RSV/BV-03-I':
            if self.conninfo:
                if self.CommandRW(EVENT = [api.Layer_ID.BT_HFP,
                                           api.HFP_Event_ID.RING_IND,
                                           self.id]):
                    return [True, 'mmi']
                else:
                    return False

        conninfo = self.get_connetion_info()

        if not conninfo:
            return False

        self.conninfo = conninfo

        time.sleep(1)

        if self.CommandRW(EVENT = [api.Layer_ID.BT_HFP,
                                   api.HFP_Event_ID.RING_IND,
                                   self.id]):
            return [True,'mmi']
        else:
            return False

    def mmi10(self,descript):
        logger.info(f'\n{descript}\n')

        conninfo = self.get_connetion_info()

        if not conninfo:
            return False

        self.conninfo = conninfo

        time.sleep(1)

        if self.CommandRW(EVENT = [api.Layer_ID.BT_HFP,
                                   api.HFP_Event_ID.RING_IND,
                                   self.id]):
            return [True,'mmi']
        else:
            return False

    def mmi21(self,descript):
        logger.info(f'\n{descript}\n')

        conninfo = self.get_connetion_info()

        if not conninfo:
            return False

        self.conninfo = conninfo

        time.sleep(1)

        if self.CommandRW(EVENT = [api.Layer_ID.BT_HFP,
                                   api.HFP_Event_ID.CONNECT_CFM,
                                   self.id]):
            return [True,'mmi']
        else:
            return False

    def mmi24(self,descript):
        logger.info(f'\n{descript}\n')

        conninfo = self.get_connetion_info()

        if not conninfo:
            return False

        self.conninfo = conninfo

        time.sleep(1)

        if self.CommandRW(EVENT = [api.Layer_ID.BT_HFP,
                                   api.HFP_Event_ID.CONNECT_CFM,
                                   self.id]):
            return [True,'mmi']
        else:
            return False

    def mmi25(self,descript):
        logger.info(f'\n{descript}\n')
        return [True,'mmi']

    def mmi27(self,descript):
        logger.info(f'\n{descript}\n')

        self.call_action = api.HFP_CallHoldActionReq.RELEASE_HELD_REJECT_WAITING.value

        return [True,'mmi']

    def mmi28(self,descript):
        logger.info(f'\n{descript}\n')

        dialLastNumberCfm = self.CommandRW(EVENT = [api.Layer_ID.BT_HFP,
                                                    api.HFP_Event_ID.DIAL_LAST_NUMBER_CFM,
                                                    self.id],
                                           back  =  True)

        if not dialLastNumberCfm:
            return False

        if dialLastNumberCfm[3:] == api.HFP_AtCmdStatus.FAIL.value:
            return True
        else:
            return False

    def mmi29(self,descript):
        logger.info(f'\n{descript}\n')

        self.call_action = api.HFP_CallHoldActionReq.RELEASE_ACTIVE_ACCEPT_OTHER.value

        return [True,'mmi']

    def mmi30(self,descript):
        logger.info(f'\n{descript}\n')

        self.call_action = api.HFP_CallHoldActionReq.HOLD_ACTIVE_ACCEPT_OTHER.value

        return [True,'mmi']

    def mmi31(self, descript):
        logger.info(f'\n{descript}\n')

        self.call_action = api.HFP_CallHoldActionReq.ADD_HELD_TO_MULTIPARTY.value

        return [True, 'mmi']

    def mmi32(self, descript):
        logger.info(f'\n{descript}\n')

        self.call_action = api.HFP_CallHoldActionReq.JOIN_CALLS_AND_HANG_UP.value

        return [True, 'mmi']

    def mmi35(self,descript):
        logger.info(f'\n{descript}\n')

        if self.casename_b == b'HFP/HF/ICA/BV-01-I' or \
           self.casename_b == b'HFP/HF/ICA/BV-02-I' or \
           self.casename_b == b'HFP/HF/ICA/BV-05-I' or \
           self.casename_b == b'HFP/HF/TWC/BV-02-I' or \
           self.casename_b == b'HFP/HF/TWC/BV-03-I' or \
           self.casename_b == b'HFP/HF/TWC/BV-04-I' or \
           self.casename_b == b'HFP/HF/TWC/BV-05-I' or \
           self.casename_b == b'HFP/HF/TWC/BV-06-I':
            if self.active_sco:
                return True
            else:
                return False

        if self.CommandRW(EVENT = [api.Layer_ID.BT_GAP,
                                   api.BT_GAP_Event_ID.MANU_SCO_ACTIVE_STATUS,
                                   self.active_sco]):

            if self.casename_b == b'HFP/HF/ACS/BV-07-I' or \
               self.casename_b == b'HFP/HF/ACS/BV-12-I' or \
               self.casename_b == b'HFP/HF/ACR/BV-01-I' or \
               self.casename_b == b'HFP/HF/ACR/BV-02-I':
                return [True,'mmi']

            return True
        else:
            return False

    def mmi39(self,descript):
        logger.info(f'\n{descript}\n')

        if self.casename_b == b'HFP/HF/ATH/BV-04-I' or \
           self.casename_b == b'HFP/HF/ATA/BV-01-I':
            if self.CommandRW(EVENT = [api.Layer_ID.BT_GAP,
                                       api.BT_GAP_Event_ID.MANU_SCO_ACTIVE_STATUS,
                                       b'\x00']):
                return True
            else:
                return False

        if self.casename_b == b'HFP/HF/ATH/BV-06-I':
            if self.CommandRW(EVENT = [api.Layer_ID.BT_GAP,
                                       api.BT_GAP_Event_ID.MANU_SCO_ACTIVE_STATUS,
                                       b'\x00']):
                return [True,'mmi']
            else:
                return False

        if self.casename_b == b'HFP/HF/ATA/BV-02-I':
            if not self.conninfo:
                return True
            else:
                return False

        connReq = b''.join([api.Layer_ID.BT_GAP.value,
                            api.BT_GAP_Event_ID.CONNECT_REQUEST.value,
                            bytes.fromhex(self.pts_address_b.decode())[::-1]])

        rev = self.readEvent()

        if not rev:
            return False

        if connReq in rev:
            return False
        else:
            return [True, 'mmi']

    def mmi43(self,descript):
        logger.info(f'\n{descript}\n')

        button = b''.join([self.id,
                           descript[-1].encode()])

        if self.CommandRW(COMMAND = [api.Layer_ID.BT_HFP,
                                     api.HFP_CMD_ID.DTMF_TRANSMIT,
                                     button],
                          EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                     api.Layer_ID.BT_HFP,
                                     api.HFP_CMD_ID.DTMF_TRANSMIT]):
            self.back = True
            return [True,'mmi']
        else:
            return False

    def mmi45(self,descript):
        logger.info(f'\n{descript}\n')

        conninfo = self.get_connetion_info()

        if not conninfo:
            return False

        self.conninfo = conninfo

        if self.CommandRW(COMMAND = [api.Layer_ID.BT_HFP,
                                     api.HFP_CMD_ID.TURN_OFF_ECNR,
                                     self.id],
                          EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                     api.Layer_ID.BT_HFP,
                                     api.HFP_CMD_ID.TURN_OFF_ECNR]):
            return True
        else:
            return False

    def mmi48(self,descript):
        logger.info(f'\n{descript}\n')

        conninfo = self.get_connetion_info()

        if not conninfo:
            return False

        self.conninfo = conninfo

        if self.CommandRW(EVENT = [api.Layer_ID.BT_HFP,
                                   api.HFP_Event_ID.CONNECT_CFM,
                                   self.id]):
            if self.CommandRW(EVENT = [api.Layer_ID.BT_HFP,
                                       api.HFP_Event_ID.RING_IND,
                                       self.id]):
                return True
            else:
                return False

    def mmi49(self,descript):
        logger.info(f'\n{descript}\n')

        if self.casename_b == b'HFP/HF/ICA/BV-01-I':
            conninfo = self.get_connetion_info()

            if not conninfo:
                return False

            self.conninfo = conninfo

        if self.CommandRW(EVENT = [api.Layer_ID.BT_GAP,
                                   api.BT_GAP_Event_ID.CONNECT_REQUEST,
                                   bytes.fromhex(self.pts_address_b.decode())[::-1]]):
            transmitBandwidth = b'\x00\x10\x00\x00'
            receiveBandwidth  = b'\x00\x10\x00\x00'
            contentFormat     = b'\x00\x33'
            packetType        = b'\x00\x3F'
            acceptSyn         = b''.join([bytes.fromhex(self.pts_address_b.decode())[::-1],
                                  transmitBandwidth,
                                  receiveBandwidth,
                                  api.BT_GAP_SYNC_CONN_MAX_LATENCY.LATENCY_MAX.value,
                                  contentFormat,
                                  api.BT_GAP_SYNC_CONN_RETRANSMIT_EFFORT.DONT_CARE.value,
                                  packetType])

            sync = self.CommandRW(COMMAND = [api.Layer_ID.BT_GAP,
                                             api.BT_GAP_CMD_ID.ACCEPT_SYNCHRONOUS_CONNECTION,
                                             acceptSyn],
                                  EVENT   = [api.Layer_ID.BT_GAP,
                                             api.BT_GAP_Event_ID.SYNCHRONOUS_CONNECTION_COMPLETE,
                                             api.BT_GAP_Status_ID.SUCCESS],
                                  back    =  True)

            if not sync:
                return False

            self.active_sco = sync[4:5]

            return True
        else:
            return False

    def mmi50(self,descript):
        logger.info(f'\n{descript}\n')

        if self.casename_b == b'HFP/HF/ICA/BV-05-I':
            incomingCall = b''.join([self.id,
                                     api.HFP_CallSetupStatus.INCOMING_CALL_IN_PROGRESS.value])

            if self.CommandRW(EVENT = [api.Layer_ID.BT_HFP,
                                       api.HFP_Event_ID.CALL_SETUP_IND,
                                       incomingCall]):
                return True
            else:
                return False

        conninfo = self.get_connetion_info()

        if not conninfo:
            return False

        self.conninfo = conninfo

        time.sleep(1)

        if self.CommandRW(EVENT = [api.Layer_ID.BT_HFP,
                                   api.HFP_Event_ID.CONNECT_CFM,
                                   self.id]):
            incomingCall = b''.join([self.id,
                                     api.HFP_CallSetupStatus.INCOMING_CALL_IN_PROGRESS.value])

            if self.CommandRW(EVENT = [api.Layer_ID.BT_HFP,
                                       api.HFP_Event_ID.CALL_SETUP_IND,
                                       incomingCall]):
                return True
            else:
                return False

    def mmi51(self,descript):
        logger.info(f'\n{descript}\n')

        if self.casename_b == b'HFP/HF/ICA/BV-06-I':
            noCall = b''.join([self.id,
                               api.HFP_CallSetupStatus.NO_CALL_IN_PROGRESS.value])

            if self.CommandRW(EVENT = [api.Layer_ID.BT_HFP,
                                       api.HFP_Event_ID.CALL_SETUP_IND,
                                       noCall]):
                return True
            else:
                return False

        conninfo = self.get_connetion_info()

        if not conninfo:
            return False

        self.conninfo = conninfo

        time.sleep(1)

        if self.CommandRW(EVENT = [api.Layer_ID.BT_HFP,
                                   api.HFP_Event_ID.CONNECT_CFM,
                                   self.id]):
            noCall = b''.join([self.id,
                               api.HFP_CallSetupStatus.NO_CALL_IN_PROGRESS.value])

            if self.CommandRW(EVENT = [api.Layer_ID.BT_HFP,
                                       api.HFP_Event_ID.CALL_SETUP_IND,
                                       noCall]):
                return True
            else:
                return False

    def mmi53(self,descript):
        logger.info(f'\n{descript}\n')

        if not self.conninfo:
            conninfo = self.get_connetion_info()

            if not conninfo:
                return False

            self.conninfo = conninfo

            time.sleep(1)

            if self.CommandRW(EVENT = [api.Layer_ID.BT_HFP,
                                       api.HFP_Event_ID.CONNECT_CFM,
                                       self.id]):
                strength = self.CommandRW(EVENT = [api.Layer_ID.BT_HFP,
                                                   api.HFP_Event_ID.SIGNAL_STRENGTH,
                                                   self.id],
                                          back  =  True)
                if not strength:
                    logger.error('not receive signal strength uart event .. ')
                    return False

                if strength[3:4].hex()[1:] == descript[-1]:
                    return [True,'mmi']
                else:
                    logger.error('signal strength value {0} != descript {1} '.format(strength[4:].hex()[1:],
                                                                                     descript[-1]))
                    return False
            else:
                return False

        strength = self.CommandRW(EVENT = [api.Layer_ID.BT_HFP,
                                           api.HFP_Event_ID.SIGNAL_STRENGTH,
                                           self.id],
                                  back  =  True)

        if not strength:
            logger.error('not receive signal strength uart event .. ')
            return False

        if strength[3:4].hex()[1:] == descript[-1]:
            return [True, 'mmi']
        else:
            logger.error('signal strength value {0} != descript {1} '.format(strength[4:].hex()[1:],descript[-1]))
            return False

    def mmi54(self,descript):
        logger.info(f'\n{descript}\n')

        conninfo = self.get_connetion_info()

        if not conninfo:
            return False

        self.conninfo = conninfo

        time.sleep(1)

        if self.CommandRW(EVENT = [api.Layer_ID.BT_HFP,
                                   api.HFP_Event_ID.CONNECT_CFM,
                                   self.id]):
            roamingStatus = self.CommandRW(EVENT = [api.Layer_ID.BT_HFP,
                                                    api.HFP_Event_ID.ROAMING_STATUS,
                                                    self.id],
                                           back  =  True)
            if not roamingStatus:
                logger.error('not receive roaming status uart event .. ')
                return False

            if roamingStatus[3:] == b'\x01':
                return True
            else:
                logger.error('roaming status is {0} '.format(roamingStatus[3:]))
                return False
        else:
            return False

    def mmi55(self, descript):
        logger.info(f'\n{descript}\n')

        roamingStatus = self.CommandRW(EVENT = [api.Layer_ID.BT_HFP,
                                                api.HFP_Event_ID.ROAMING_STATUS,
                                                self.id],
                                       back  =  True)
        if not roamingStatus:
            logger.error('not receive roaming status uart event .. ')
            return False

        if roamingStatus[3:] == b'\x00':
            return True
        else:
            logger.error('roaming status is {0} '.format(roamingStatus[3:]))
            return False

    def mmi58(self,descript):
        logger.info(f'\n{descript}\n')

        battery = self.CommandRW(EVENT = [api.Layer_ID.BT_HFP,
                                          api.HFP_Event_ID.BATTERY_LEVEL,
                                          self.id],
                                 back  =  True)
        if not battery:
            logger.error('not receive battery level uart event .. ')
            return False

        if battery[3:4] != battery[4:]:
            return True
        else:
            logger.error('battery current level : {0} , max level : {1}'.format(battery[3:4],battery[4:]))
            return False

    def mmi59(self,descript):
        logger.info(f'\n{descript}\n')

        if not self.conninfo:
            conninfo = self.get_connetion_info()

            if not conninfo:
                return False

            self.conninfo = conninfo

            time.sleep(1)

            if self.CommandRW(EVENT = [api.Layer_ID.BT_HFP,
                                       api.HFP_Event_ID.CONNECT_CFM,
                                       self.id]):
                battery = self.CommandRW(EVENT = [api.Layer_ID.BT_HFP,
                                                  api.HFP_Event_ID.BATTERY_LEVEL,
                                                  self.id],
                                         back  =  True)
                if not battery:
                    logger.error('not receive battery level uart event .. ')
                    return False

                if battery[3:4] == battery[4:]:
                    return True
                else:
                    logger.error('battery current level : {0} , max level : {1}'.format(battery[3:4], battery[4:]))
                    return False
            else:
                return False

        battery = self.CommandRW(EVENT=[api.Layer_ID.BT_HFP,
                                        api.HFP_Event_ID.BATTERY_LEVEL,
                                        self.id],
                                 back=True)
        if not battery:
            logger.error('not receive battery level uart event .. ')
            return False

        if battery[3:4] == battery[4:]:
            return True
        else:
            logger.error('battery current level : {0} , max level : {1}'.format(battery[3:4],battery[4:]))
            return False

    def mmi67(self,descript):
        logger.info(f'\n{descript}\n')

        phoneHeld = self.CommandRW(EVENT = [api.Layer_ID.BT_HFP,
                                            api.HFP_Event_ID.CALL_HELD_IND,
                                            self.id],
                                   back  =  True)

        if phoneHeld[3:] == api.HFP_CallHeldStatus.CALL_ON_HOLD_ACTIVE_SWAP.value:
            return True
        else:
            return False

    def mmi72(self, descript):
        logger.info(f'\n{descript}\n')

        volume = b''.join([self.id, b'\x00'])

        if self.CommandRW(COMMAND = [api.Layer_ID.BT_HFP,
                                     api.HFP_CMD_ID.VOLUME_SYNC_SPEAKER,
                                     volume],
                          EVENT   = [api.Layer_ID.BT_HFP,
                                     api.HFP_Event_ID.GAIN_CFM,
                                     self.id]):
            return True
        else:
            return False

    def mmi76(self,descript):
        logger.info(f'\n{descript}\n')

        if self.casename_b == b'HFP/HF/RSV/BV-03-I':
            if self.gainValue != None:
                checkValue = int(descript[-2:].replace('.', '').strip())

                if checkValue == self.gainValue:
                    self.gainValue = None
                    self.back      = True
                    return [True,'mmi']
                else:
                    logger.error('checkValue : {0}, gainValue : {1}'.format(checkValue, self.gainValue))
                    return False


        gainInd = self.CommandRW(EVENT = [api.Layer_ID.BT_HFP,
                                          api.HFP_Event_ID.GAIN_IND,
                                          self.id],
                                 back  = True)

        if not gainInd:
            return False

        checkValue = int(descript[-2:].replace('.', '').strip())
        gainValue  = int.from_bytes(gainInd[4:],byteorder='big')

        if checkValue == gainValue:

            if self.casename_b == b'HFP/HF/RSV/BV-02-I':
                self.back = True
                return [True,'mmi']

            if self.casename_b == b'HFP/HF/RSV/BV-03-I':
                self.gainValue = gainValue

            return True
        else:
            logger.error('checkValue : {0}, gainValue : {1}'.format(checkValue,gainValue))
            return False

    def mmi78(self,descript):
        logger.info(f'\n{descript}\n')
        return True

    def mmi83(self,descript):
        logger.info(f'\n{descript}\n')

        conninfo = self.get_connetion_info()

        if not conninfo:
            return False

        self.conninfo = conninfo

        time.sleep(1)

        if self.CommandRW(EVENT = [api.Layer_ID.BT_HFP,
                                   api.HFP_Event_ID.CONNECT_CFM,
                                   self.id]):

            voiceEnable = b''.join([self.id,b'\x01'])

            if self.CommandRW(COMMAND = [api.Layer_ID.BT_HFP,
                                         api.HFP_CMD_ID.VOICE_RECOGNITION_ENABLE,
                                         voiceEnable],
                              EVENT   = [api.Layer_ID.BT_HFP,
                                         api.HFP_Event_ID.VOICE_RECOGNITION_ENABLE_CFM,
                                         self.id]):
                return
            else:
                return False

        else:
            return False

    def mmi84(self,descript):
        logger.info(f'\n{descript}\n')

        if self.CommandRW(EVENT=[api.Layer_ID.BT_GAP,
                                 api.BT_GAP_Event_ID.CONNECT_REQUEST,
                                 bytes.fromhex(self.pts_address_b.decode())[::-1]]):

            transmitBandwidth = b'\x00\x10\x00\x00'
            receiveBandwidth = b'\x00\x10\x00\x00'
            contentFormat = b'\x00\x33'
            packetType = b'\x00\x3F'
            acceptSyn = b''.join([bytes.fromhex(self.pts_address_b.decode())[::-1],
                                  transmitBandwidth,
                                  receiveBandwidth,
                                  api.BT_GAP_SYNC_CONN_MAX_LATENCY.LATENCY_MAX.value,
                                  contentFormat,
                                  api.BT_GAP_SYNC_CONN_RETRANSMIT_EFFORT.DONT_CARE.value,
                                  packetType])

            sync = self.CommandRW(COMMAND = [api.Layer_ID.BT_GAP,
                                             api.BT_GAP_CMD_ID.ACCEPT_SYNCHRONOUS_CONNECTION,
                                             acceptSyn],
                                  EVENT   = [api.Layer_ID.BT_GAP,
                                             api.BT_GAP_Event_ID.SYNCHRONOUS_CONNECTION_COMPLETE,
                                             api.BT_GAP_Status_ID.SUCCESS],
                                  back    =  True)

            if not sync:
                return False

            self.active_sco = sync[4:5]

            voiceDisable = b''.join([self.id, b'\x00'])

            if self.CommandRW(COMMAND = [api.Layer_ID.BT_HFP,
                                         api.HFP_CMD_ID.VOICE_RECOGNITION_ENABLE,
                                         voiceDisable],
                              EVENT   = [api.Layer_ID.BT_HFP,
                                         api.HFP_Event_ID.VOICE_RECOGNITION_ENABLE_CFM,
                                         self.id]):
                return
            else:
                return False

    def mmi86(self,descript):
        logger.info(f'\n{descript}\n')

        conninfo = self.get_connetion_info()

        if not conninfo:
            return False

        self.conninfo = conninfo

        time.sleep(1)

        return [True,'mmi']

    def mmi89(self,descript):
        logger.info(f'\n{descript}\n')

        conninfo = self.get_connetion_info()

        if not conninfo:
            return False

        self.conninfo = conninfo

        time.sleep(1)

        if self.CommandRW(EVENT = [api.Layer_ID.BT_HFP,
                                   api.HFP_Event_ID.CONNECT_CFM,
                                   self.id]):
            enable = b''.join([self.id,b'\x01'])

            if self.CommandRW(COMMAND = [api.Layer_ID.BT_HFP,
                                         api.HFP_CMD_ID.CALLERID_ENABLE,
                                         enable],
                              EVENT   = [api.Layer_ID.BT_HFP,
                                         api.HFP_Event_ID.CALLERID_ENABLE_CFM,
                                         self.id]):
                return True
            else:
                return False
        else:
            return False

    def mmi91(self,descript):
        logger.info(f'\n{descript}\n')
        return True

    def mmi94(self,descript):
        logger.info(f'\n{descript}\n')

        if self.iut_sw_reset():
            self.conninfo = None
            self.wait = 30
            return [True,'mmi']
        else:
            return False

    def mmi95(self, descript):
        logger.info(f'\n{descript}\n')

        if not self.iut_write_address():
            return False

        if not self.iut_write_local_name():
            return False

        if not self.iut_set_device_name():
            return False

        if not self.iut_erase_all_paired_device():
            return False

        return True

    def mmi98(self,descript):
        logger.info(f'\n{descript}\n')

        if self.iut_sw_reset():
            self.conninfo = None
            if self.casename_b == b'HFP/HF/ATA/BV-02-I':
                self.wait = 10
                return [True, 'mmi']
            self.wait = 30
            return [True,'mmi']
        else:
            return False

    def mmi115(self,descript):
        logger.info(f'\n{descript}\n')

        conninfo = self.get_connetion_info()

        if not conninfo:
            return False

        self.conninfo = conninfo

        time.sleep(1)

        if self.CommandRW(EVENT = [api.Layer_ID.BT_HFP,
                                   api.HFP_Event_ID.CONNECT_CFM,
                                   self.id]):
            return [True,'mmi']
        else:
            return False

    def mmi122(self,descript):
        logger.info(f'\n{descript}\n')
        return True

    def mmi123(self,descript):
        logger.info(f'\n{descript}\n')
        return True

    def mmi127(self,descript):
        logger.info(f'\n{descript}\n')

        self.call_action = api.HFP_CallHoldActionReq.RELEASE_ACTIVE_ACCEPT_OTHER.value

        return [True, 'mmi']

    def mmi168(self,descript):
        logger.info(f'\n{descript}\n')

        if self.casename_b == b'HFP/HF/ACC/BV-02-I':
            return [True, 'mmi']

        conninfo = self.get_connetion_info()

        if not conninfo:
            return False

        self.conninfo = conninfo

        time.sleep(1)

        return [True,'mmi']

    def mmi178(self,descript):
        logger.info(f'\n{descript}\n')
        self.wait = 20
        return [True,'mmi']

    def mmi219(self,descript):
        logger.info(f'\n{descript}\n')
        return True

    def mmi220(self,descript):
        logger.info(f'\n{descript}\n')
        return True

class HSP(Common):
    def __init__(self,comport,profile,casename,ptsaddress_b,ixit,bleonly):
        Common.__init__(self,comport,profile,casename,ptsaddress_b,ixit,bleonly)
        self.id          = b'\x00'
        self.conninfo    = None
        self.active_sco  = None

    def mmi(self,descript):
        if self.casename_b == b'HSP/HS/ACR/BV-01-I' or \
           self.casename_b == b'HSP/HS/ACR/BV-02-I' or \
           self.casename_b == b'HSP/HS/ACT/BV-02-I':
            if self.active_sco:
                if self.CommandRW(COMMAND = [api.Layer_ID.BT_HFP,
                                             api.HFP_CMD_ID.HS_BUTTON_PRESS,
                                             self.id],
                                  EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                             api.Layer_ID.BT_HFP,
                                             api.HFP_CMD_ID.HS_BUTTON_PRESS]):
                    return
                else:
                    return False

            conninfo = self.get_connetion_info()

            if not conninfo:
                return False

            self.conninfo = conninfo

            time.sleep(1)

            if self.CommandRW(EVENT = [api.Layer_ID.BT_GAP,
                                       api.BT_GAP_Event_ID.CONNECT_REQUEST,
                                       bytes.fromhex(self.pts_address_b.decode())[::-1]]):
                transmitBandwidth = b'\x00\x10\x00\x00'
                receiveBandwidth  = b'\x00\x10\x00\x00'
                contentFormat     = b'\x00\x33'
                packetType        = b'\x00\x3F'
                acceptSyn         = b''.join([bytes.fromhex(self.pts_address_b.decode())[::-1],
                                              transmitBandwidth,
                                              receiveBandwidth,
                                              api.BT_GAP_SYNC_CONN_MAX_LATENCY.LATENCY_MAX.value,
                                              contentFormat,
                                              api.BT_GAP_SYNC_CONN_RETRANSMIT_EFFORT.DONT_CARE.value,
                                              packetType])

                sync = self.CommandRW(COMMAND = [api.Layer_ID.BT_GAP,
                                                 api.BT_GAP_CMD_ID.ACCEPT_SYNCHRONOUS_CONNECTION,
                                                 acceptSyn],
                                      EVENT   = [api.Layer_ID.BT_GAP,
                                                 api.BT_GAP_Event_ID.SYNCHRONOUS_CONNECTION_COMPLETE,
                                                 api.BT_GAP_Status_ID.SUCCESS],
                                      back    =  True)

                if not sync:
                    return False

                self.active_sco = sync[4:5]

                return

        if self.conninfo:
            if self.casename_b == b'HSP/HS/IAC/BV-01-I':
                if self.CommandRW(COMMAND = [api.Layer_ID.BT_HFP,
                                             api.HFP_CMD_ID.CALL_ANSWER_ACCEPT,
                                             self.id],
                                  EVENT   = [api.Layer_ID.BT_HFP,
                                             api.HFP_Event_ID.CALL_ANSWER_CFM,
                                             self.id]):

                    if self.CommandRW(COMMAND = [api.Layer_ID.BT_HFP,
                                                 api.HFP_CMD_ID.HS_BUTTON_PRESS,
                                                 self.id],
                                      EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                                 api.Layer_ID.BT_HFP,
                                                 api.HFP_CMD_ID.HS_BUTTON_PRESS]):

                        if self.CommandRW(EVENT = [api.Layer_ID.BT_GAP,
                                                   api.BT_GAP_Event_ID.CONNECT_REQUEST,
                                                   bytes.fromhex(self.pts_address_b.decode())[::-1]]):
                            transmitBandwidth = b'\x00\x10\x00\x00'
                            receiveBandwidth  = b'\x00\x10\x00\x00'
                            contentFormat     = b'\x00\x33'
                            packetType        = b'\x00\x3F'
                            acceptSyn         = b''.join([bytes.fromhex(self.pts_address_b.decode())[::-1],
                                                          transmitBandwidth,
                                                          receiveBandwidth,
                                                          api.BT_GAP_SYNC_CONN_MAX_LATENCY.LATENCY_MAX.value,
                                                          contentFormat,
                                                          api.BT_GAP_SYNC_CONN_RETRANSMIT_EFFORT.DONT_CARE.value,
                                                          packetType])

                            sync = self.CommandRW(COMMAND = [api.Layer_ID.BT_GAP,
                                                             api.BT_GAP_CMD_ID.ACCEPT_SYNCHRONOUS_CONNECTION,
                                                             acceptSyn],
                                                  EVENT   = [api.Layer_ID.BT_GAP,
                                                             api.BT_GAP_Event_ID.SYNCHRONOUS_CONNECTION_COMPLETE,
                                                             api.BT_GAP_Status_ID.SUCCESS],
                                                  back    =  True)

                            if not sync:
                                return False

                            self.active_sco = sync[4:5]

                            return
                        else:
                            return False
                    else:
                        return False
                else:
                    return False

            if self.casename_b == b'HSP/HS/IAC/BV-02-I':
                if self.CommandRW(COMMAND = [api.Layer_ID.BT_HFP,
                                             api.HFP_CMD_ID.HS_BUTTON_PRESS,
                                             self.id],
                                  EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                             api.Layer_ID.BT_HFP,
                                             api.HFP_CMD_ID.HS_BUTTON_PRESS]):
                    return
                else:
                    return False

            if self.casename_b == b'HSP/HS/OAC/BV-01-I' or \
               self.casename_b == b'HSP/HS/ACT/BV-01-I':

                time.sleep(1)

                conninfo = self.create_connection('BT')

                if not conninfo:
                    return False

                self.conninfo = conninfo

                req = b''.join([self.conninfo['connhandle'],
                                api.HFP_Profile.HEADSET.value])

                if self.CommandRW(COMMAND = [api.Layer_ID.BT_HFP,
                                             api.HFP_CMD_ID.CONNECT_REQ,
                                             req],
                                  EVENT   = [api.Layer_ID.BT_HFP,
                                             api.HFP_Event_ID.CONNECT_CFM,
                                             self.id]):

                    if self.CommandRW(COMMAND = [api.Layer_ID.BT_HFP,
                                                 api.HFP_CMD_ID.HS_BUTTON_PRESS,
                                                 self.id],
                                      EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                                 api.Layer_ID.BT_HFP,
                                                 api.HFP_CMD_ID.HS_BUTTON_PRESS]):

                        if self.CommandRW(EVENT = [api.Layer_ID.BT_GAP,
                                                   api.BT_GAP_Event_ID.CONNECT_REQUEST,
                                                   bytes.fromhex(self.pts_address_b.decode())[::-1]]):
                            transmitBandwidth = b'\x00\x10\x00\x00'
                            receiveBandwidth  = b'\x00\x10\x00\x00'
                            contentFormat     = b'\x00\x33'
                            packetType        = b'\x00\x3F'
                            acceptSyn         = b''.join([bytes.fromhex(self.pts_address_b.decode())[::-1],
                                                          transmitBandwidth,
                                                          receiveBandwidth,
                                                          api.BT_GAP_SYNC_CONN_MAX_LATENCY.LATENCY_MAX.value,
                                                          contentFormat,
                                                          api.BT_GAP_SYNC_CONN_RETRANSMIT_EFFORT.DONT_CARE.value,
                                                          packetType])
                            sync = self.CommandRW(COMMAND = [api.Layer_ID.BT_GAP,
                                                             api.BT_GAP_CMD_ID.ACCEPT_SYNCHRONOUS_CONNECTION,
                                                             acceptSyn],
                                                  EVENT   = [api.Layer_ID.BT_GAP,
                                                             api.BT_GAP_Event_ID.SYNCHRONOUS_CONNECTION_COMPLETE,
                                                             api.BT_GAP_Status_ID.SUCCESS],
                                                  back    =  True)

                            if not sync:
                                return False

                            self.active_sco = sync[4:5]

                            return
                    else:
                        return False
                else:
                    return False

            if self.casename_b == b'IOPT/CL/HSP-HS/SFC/BV-17-I':

                conninfo = self.create_connection('BT')

                if not conninfo:
                    return False

                self.conninfo = conninfo

                time.sleep(1)

                req = b''.join([self.conninfo['connhandle'],
                                api.HFP_Profile.HEADSET.value])

                if self.CommandRW(COMMAND = [api.Layer_ID.BT_HFP,
                                             api.HFP_CMD_ID.CONNECT_REQ,
                                             req],
                                  EVENT   = [api.Layer_ID.BT_HFP,
                                             api.HFP_Event_ID.CONNECT_CFM,
                                             self.id]):
                    return
                else:
                    return False

        return

    def mmi0(self, descript):
        logger.info(f'\n{descript}\n')

        if self.casename_b == b'HSP/HS/IAC/BV-02-I':
            conninfo = self.get_connetion_info()

            if not conninfo:
                return False

            self.conninfo = conninfo

            time.sleep(1)

            return True

        return True

    def mmi1(self,descript):
        logger.info(f'\n{descript}\n')
        self.conninfo = True
        return [True, 'mmi']

    def mmi35(self,descript):
        logger.info(f'\n{descript}\n')

        if self.casename_b == b'HSP/HS/IAC/BV-02-I':
            if self.active_sco:
                return True
            else:
                return False

        if self.CommandRW(EVENT = [api.Layer_ID.BT_GAP,
                                   api.BT_GAP_Event_ID.MANU_SCO_ACTIVE_STATUS,
                                   self.active_sco]):
            return True
        else:
            return False

    def mmi203(self,descript):
        logger.info(f'\n{descript}\n')
        conninfo = self.get_connetion_info()

        if not conninfo:
            return False

        self.conninfo = conninfo

        time.sleep(1)

        if self.CommandRW(EVENT = [api.Layer_ID.BT_HFP,
                                   api.HFP_Event_ID.DISCONNECT_IND,
                                   self.id]):
            return [True, 'mmi']
        else:
            return False

    def mmi204(self,descript):
        logger.info(f'\n{descript}\n')

        conninfo = self.get_connetion_info()

        if not conninfo:
            return False

        self.conninfo = conninfo

        time.sleep(1)

        if self.CommandRW(EVENT = [api.Layer_ID.BT_HFP,
                                   api.HFP_Event_ID.RING_IND,
                                   self.id]):

            return [True,'mmi']
        else:
            return False

    def mmi205(self,descript):
        logger.info(f'\n{descript}\n')
        if self.CommandRW(EVENT = [api.Layer_ID.BT_GAP,
                                   api.BT_GAP_Event_ID.CONNECT_REQUEST,
                                   bytes.fromhex(self.pts_address_b.decode())[::-1]]):
            transmitBandwidth = b'\x00\x10\x00\x00'
            receiveBandwidth  = b'\x00\x10\x00\x00'
            contentFormat     = b'\x00\x33'
            packetType        = b'\x00\x3F'
            acceptSyn         = b''.join([bytes.fromhex(self.pts_address_b.decode())[::-1],
                                          transmitBandwidth,
                                          receiveBandwidth,
                                          api.BT_GAP_SYNC_CONN_MAX_LATENCY.LATENCY_MAX.value,
                                          contentFormat,
                                          api.BT_GAP_SYNC_CONN_RETRANSMIT_EFFORT.DONT_CARE.value,
                                          packetType])
            sync = self.CommandRW(COMMAND = [api.Layer_ID.BT_GAP,
                                             api.BT_GAP_CMD_ID.ACCEPT_SYNCHRONOUS_CONNECTION,
                                             acceptSyn],
                                  EVENT   = [api.Layer_ID.BT_GAP,
                                             api.BT_GAP_Event_ID.SYNCHRONOUS_CONNECTION_COMPLETE,
                                             api.BT_GAP_Status_ID.SUCCESS],
                                  back    =  True)
            if not sync:
                return False

            self.active_sco = sync[4:5]

            return [True,'mmi']
        else:
            return False

    def mmi206(self,descript):
        logger.info(f'\n{descript}\n')
        return [True, 'mmi']

    def mmi208(self,descript):
        logger.info(f'\n{descript}\n')
        conninfo = self.get_connetion_info()

        if not conninfo:
            return False

        self.conninfo = conninfo

        time.sleep(1)

        if self.CommandRW(EVENT = [api.Layer_ID.BT_HFP,
                                   api.HFP_Event_ID.DISCONNECT_IND,
                                   self.id]):
            return [True, 'mmi']
        else:
            return False

    def mmi250(self,descript):
        logger.info(f'\n{descript}\n')
        return True

class L2CAP(Common):
    def __init__(self,comport,profile,casename,ptsaddress_b,ixit,bleonly):
        Common.__init__(self,comport,profile,casename,ptsaddress_b,ixit,bleonly)
        self.id       = b'\x00'
        self.multiid  = [b'\x00',b'\x01']
        self.sdudata  = None
        self.dataInd  = list()
        self.conninfo = None
        self.wait     = None

    def mmi(self,descript):
        if self.wait:
            time.sleep(self.wait)
            self.wait = None
            return
        return

    def mmi14(self,descript):
        logger.info(f'\n{descript}\n')
        if self.conninfo['layer'] == api.Layer_ID.BLE_GAP.value:

            if self.CommandRW(COMMAND = [api.Layer_ID.BLE_L2CAP,
                                         api.BLE_L2CAP_CMD_ID.CB_DISCONNECT,
                                         self.id],
                              EVENT   = [api.Layer_ID.BLE_L2CAP,
                                         api.BLE_L2CAP_Event_ID.CB_DISC_IND,
                                         self.id]):
                return
            else:
                return False

        if self.CommandRW(COMMAND = [api.Layer_ID.BT_L2CAP,
                                     api.BT_L2CAP_CMD_ID.DISCONNECT,
                                     self.id],
                          EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                     api.Layer_ID.BT_L2CAP,
                                     api.BT_L2CAP_CMD_ID.DISCONNECT]):
            return
        else:
            return False

    def mmi15(self,descript):
        logger.info(f'\n{descript}\n')

        conninfo = self.get_connetion_info()

        if not conninfo:
            return False

        self.conninfo = conninfo

        time.sleep(2)

        if self.casename_b == b'L2CAP/COS/IEX/BV-02-C' or \
           self.casename_b == b'L2CAP/COS/ECH/BV-01-C' or \
           self.casename_b == b'L2CAP/CLS/UCD/BV-01-C' or \
           self.casename_b == b'L2CAP/EXF/BV-05-C':
            return

        openChanRsp = b''.join([self.id,
                                api.BT_L2CAP_CONN_RSP_RESULT.SUCCESSFUL.value,
                                api.BT_L2CAP_CONN_RSP_STATUS.AUTHENTICATION_PENDING.value,
                                len(api.BT_L2CAP_CONF_OPTIONS.MTU.value).to_bytes(1, 'big'),
                                api.BT_L2CAP_CONF_OPTIONS.MTU.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.BT_L2CAP,
                                     api.BT_L2CAP_CMD_ID.OPEN_CHAN_RSP,
                                     openChanRsp],
                          EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                     api.Layer_ID.BT_L2CAP,
                                     api.BT_L2CAP_CMD_ID.OPEN_CHAN_RSP]):

            if self.casename_b == b'L2CAP/COS/CFD/BV-02-C':
                time.sleep(2)
                if self.CommandRW(COMMAND = [api.Layer_ID.BT_GAP,
                                             api.BT_GAP_CMD_ID.DISCONNECT,
                                             self.conninfo['connhandle']],
                                  EVENT   = [api.Layer_ID.BT_GAP,
                                             api.BT_GAP_Event_ID.DISCONNECTED,
                                             api.BT_GAP_Status_ID.SUCCESS]):
                    return
                else:
                    return False

            return
        else:
            return False

    def mmi22(self,descript):
        logger.info(f'\n{descript}\n')

        if self.conninfo['layer'] == api.Layer_ID.BT_GAP.value:

            if self.CommandRW(COMMAND = [api.Layer_ID.BT_GAP,
                                         api.BT_GAP_CMD_ID.DISCONNECT,
                                         self.conninfo['connhandle']],
                              EVENT   = [api.Layer_ID.BT_GAP,
                                         api.BT_GAP_Event_ID.DISCONNECTED,
                                         api.BT_GAP_Status_ID.SUCCESS]):
                return
            else:
                return False

        Terminate = b''.join([self.conninfo['connhandle'],
                              api.BLE_GAP_DISC_REASON.REMOTE_TERMINATE.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.BLE_GAP,
                                     api.BLE_GAP_CMD_ID.TERMINATE_CONNECTION,
                                     Terminate],
                          EVENT   = [api.Layer_ID.BLE_GAP,
                                     api.BLE_GAP_Event_ID.DISCONNECTED,
                                     self.conninfo['connhandle']]):
            return
        else:
            return False

    def mmi23(self,descript):
        logger.info(f'\n{descript}\n')

        data = bytes.fromhex(self.iut_address_b.decode())

        if self.casename_b == b'L2CAP/COS/CFD/BV-09-C':
            data = data * 8

        if self.CommandRW(COMMAND = [api.Layer_ID.BT_L2CAP,
                                     api.BT_L2CAP_CMD_ID.SEND_DATA,
                                     data],
                          EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                     api.Layer_ID.BT_L2CAP,
                                     api.BT_L2CAP_CMD_ID.SEND_DATA]):
            return
        else:
            return False

    def mmi26(self,descript):
        logger.info(''.join(['\n', descript,'\n']))

        conninfo = self.create_connection('BT')

        if not conninfo:
            return False

        self.conninfo = conninfo

        time.sleep(2)

        echoData = b''.join([self.conninfo['connhandle'],
                             bytes.fromhex(self.iut_address_b.decode())])

        if self.CommandRW(COMMAND = [api.Layer_ID.BT_L2CAP,
                                     api.BT_L2CAP_CMD_ID.ECHO_REQ,
                                     echoData],
                          EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                     api.Layer_ID.BT_L2CAP,
                                     api.BT_L2CAP_CMD_ID.ECHO_REQ]):
            return
        else:
            return False

    def mmi36(self,descript):
        logger.info(f'\n{descript}\n')

        creditsNum = b'\x00\x05'
        credit     = b''.join([self.id,
                               creditsNum])

        if self.casename_b == b'L2CAP/COS/CFC/BV-05-C':
            if self.multiid:
                credit    = b''.join([self.multiid.pop(0),
                                      creditsNum])
            else:
                return False

        if self.CommandRW(COMMAND = [api.Layer_ID.BLE_L2CAP,
                                     api.BLE_L2CAP_CMD_ID.CB_ADD_CREDIT,
                                     credit],
                          EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                     api.Layer_ID.BLE_L2CAP,
                                     api.BLE_L2CAP_CMD_ID.CB_ADD_CREDIT]):

            if self.casename_b == b'L2CAP/COS/CFC/BV-05-C':
                rev = self.readEvent()

                self.dataInd.append(rev[5:].hex().upper())

                credit    = b''.join([self.multiid.pop(0),
                                      creditsNum])

                if self.CommandRW(COMMAND = [api.Layer_ID.BLE_L2CAP,
                                             api.BLE_L2CAP_CMD_ID.CB_ADD_CREDIT,
                                             credit],
                                  EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                             api.Layer_ID.BLE_L2CAP,
                                             api.BLE_L2CAP_CMD_ID.CB_ADD_CREDIT]):
                    rev = self.readEvent()

                    self.dataInd.append(rev[5:].hex().upper())
                    return
                else:
                    return False

            return
        else:
            return False

    def mmi37(self,descript):
        logger.info(''.join(['\n', descript,'\n']))

        if self.sdudata.hex().upper() in descript:
            return True
        else:
            logger.error(f'send to PTS sdu data is diffence , self.sdudata = {self.sdudata.hex().upper()}')
            return False

    def mmi39(self,descript):
        logger.info(''.join(['\n', descript,'\n']))

        if self.CommandRW(EVENT = [api.Layer_ID.BLE_L2CAP,
                                   api.BLE_L2CAP_Event_ID.CMD_REJECT_RSP,
                                   self.conninfo['connhandle']]):
            return True
        else:
            return False

    def mmi40(self,descript):
        logger.info(''.join(['\n', descript,'\n']))

        res_Data = self.CommandRW(EVENT = [api.Layer_ID.BLE_L2CAP,
                                           api.BLE_L2CAP_Event_ID.CB_SDU_IND,
                                           self.id],
                                  back  = True)

        if not res_Data:
            return False

        self.dataInd.append(res_Data[5:].hex().upper())

        if self.dataInd:
            return True
        else:
            logger.error('Not receive any data data')
            return False

    def mmi41(self,descript):
        logger.info(f'\n{descript}\n')
        psm = bytes()

        if b'TSPX_le_psm' in self.ixit.keys():
            psm = self.ixit[b'TSPX_le_psm'][1].decode()

        if b'TSPX_spsm' in self.ixit.keys():
            psm = self.ixit[b'TSPX_spsm'][1].decode()

        creditConnReq = b''.join([self.conninfo['connhandle'],
                                  bytes.fromhex(psm)])

        if self.casename_b == b'L2CAP/LE/CFC/BV-04-C':
            creditConnReq = b''.join([self.conninfo['connhandle'],
                                      bytes.fromhex(self.ixit[b'TSPX_psm_unsupported'][1].decode())])

        if self.CommandRW(COMMAND = [api.Layer_ID.BLE_L2CAP,
                                     api.BLE_L2CAP_CMD_ID.CB_CONN_REQ,
                                     creditConnReq],
                          EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                     api.Layer_ID.BLE_L2CAP,
                                     api.BLE_L2CAP_CMD_ID.CB_CONN_REQ]):

            if self.casename_b == b'L2CAP/COS/CFC/BV-03-C':
                if self.CommandRW(EVENT=[api.Layer_ID.BLE_L2CAP,
                                         api.BLE_L2CAP_Event_ID.CB_CHANNEL_OPEN_CFM,
                                         self.id]):

                    creditsNum = b'\x00\x05'
                    credit = b''.join([self.id,creditsNum])

                    if self.CommandRW(COMMAND = [api.Layer_ID.BLE_L2CAP,
                                                 api.BLE_L2CAP_CMD_ID.CB_ADD_CREDIT,
                                                 credit],
                                      EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                                 api.Layer_ID.BLE_L2CAP,
                                                 api.BLE_L2CAP_CMD_ID.CB_ADD_CREDIT]):
                        return
                    else:
                        return False

            if self.casename_b == b'L2CAP/COS/CFC/BV-05-C':
                if self.CommandRW(EVENT=[api.Layer_ID.BLE_L2CAP,
                                         api.BLE_L2CAP_Event_ID.CB_CHANNEL_OPEN_CFM,
                                         self.multiid[0]]):

                    if self.CommandRW(COMMAND = [api.Layer_ID.BLE_L2CAP,
                                                 api.BLE_L2CAP_CMD_ID.CB_CONN_REQ,
                                                 creditConnReq],
                                      EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                                 api.Layer_ID.BLE_L2CAP,
                                                 api.BLE_L2CAP_CMD_ID.CB_CONN_REQ]):

                        if self.CommandRW(EVENT = [api.Layer_ID.BLE_L2CAP,
                                                   api.BLE_L2CAP_Event_ID.CB_CHANNEL_OPEN_CFM,
                                                   self.multiid[1]]):

                            creditsNum = b'\x00\x05'
                            credit = b''.join([self.multiid[0],creditsNum])

                            if self.CommandRW(COMMAND = [api.Layer_ID.BLE_L2CAP,
                                                         api.BLE_L2CAP_CMD_ID.CB_ADD_CREDIT,
                                                         credit],
                                              EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                                         api.Layer_ID.BLE_L2CAP,
                                                         api.BLE_L2CAP_CMD_ID.CB_ADD_CREDIT]):

                                res_Data = self.CommandRW(EVENT = [api.Layer_ID.BLE_L2CAP,
                                                                   api.BLE_L2CAP_Event_ID.CB_SDU_IND,
                                                                   self.multiid[0]],
                                                          back  =  True)

                                if not res_Data:
                                    return False

                                self.dataInd.append(res_Data[5:])

                                credit = b''.join([self.multiid[1], creditsNum])

                                if self.CommandRW(COMMAND = [api.Layer_ID.BLE_L2CAP,
                                                             api.BLE_L2CAP_CMD_ID.CB_ADD_CREDIT,
                                                             credit],
                                                  EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                                             api.Layer_ID.BLE_L2CAP,
                                                             api.BLE_L2CAP_CMD_ID.CB_ADD_CREDIT]):

                                    res_Data = self.CommandRW(EVENT = [api.Layer_ID.BLE_L2CAP,
                                                                       api.BLE_L2CAP_Event_ID.CB_SDU_IND,
                                                                       self.multiid[1]],
                                                              back  =  True)

                                    if not res_Data:
                                        return False

                                    self.dataInd.append(res_Data[5:])

                                    return
                                else:
                                    return False
                            else:
                                return False
                        else:
                            return False
                    else:
                        return False
                else:
                    return False

            if self.casename_b == b'L2CAP/LE/CFC/BV-07-C':
                res_Data = self.CommandRW(EVENT = [api.Layer_ID.BLE_L2CAP,
                                                   api.BLE_L2CAP_Event_ID.CB_SDU_IND,
                                                   self.id],
                                          back  =  True)

                if not res_Data:
                    return False

                self.dataInd.append(res_Data[5:].hex().upper())

                creditsNum = b'\x00\x05'
                credit = b''.join([self.id,creditsNum])

                if self.CommandRW(COMMAND = [api.Layer_ID.BLE_L2CAP,
                                             api.BLE_L2CAP_CMD_ID.CB_ADD_CREDIT,
                                             credit],
                                  EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                             api.Layer_ID.BLE_L2CAP,
                                             api.BLE_L2CAP_CMD_ID.CB_ADD_CREDIT]):

                    cb_disconnect = b''.join([api.Layer_ID.BLE_L2CAP.value,
                                              api.BLE_L2CAP_Event_ID.CB_DISC_IND.value,
                                              self.id])

                    res = b''

                    res_count = 0

                    while res != cb_disconnect or res_count < 10:
                        res = self.readEvent()

                        if res == cb_disconnect:
                            return

                        sdu_Ind = b''.join([api.Layer_ID.BLE_L2CAP.value,
                                            api.BLE_L2CAP_Event_ID.CB_SDU_IND.value,
                                            self.id])

                        if not res:
                            return False

                        if res[:3] == sdu_Ind:
                            self.dataInd.append(res_Data[5:].hex().upper())

                        res_count += 1

                else:
                    return False

            return [None,'mmi']
        else:
            return False

    def mmi42(self,descript):
        logger.info(f'\n{descript}\n')

        res = self.readEvent()

        if res[:1] == api.Layer_ID.BLE_L2CAP.value and \
           res[1:2] == api.BLE_L2CAP_Event_ID.CB_CHANNEL_OPEN_CFM.value:
            if res[9:].hex().upper() in descript:
                return True
            else:
                return False
        else:
            return False

    def mmi43(self,descript):
        logger.info(''.join(['\n', descript,'\n']))

        self.sdudata = bytes.fromhex(self.iut_address_b.decode())

        data = b''.join([self.id,
                         self.sdudata])

        if self.CommandRW(COMMAND = [api.Layer_ID.BLE_L2CAP,
                                     api.BLE_L2CAP_CMD_ID.CB_SEND_SDU,
                                     data],
                          EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                     api.Layer_ID.BLE_L2CAP,
                                     api.BLE_L2CAP_CMD_ID.CB_SEND_SDU]):
            return
        else:
            return False

    def mmi45(self,descript):
        logger.info(f'\n{descript}\n')

        res = self.readEvent()

        if res[:1] == api.Layer_ID.BLE_L2CAP.value and \
           res[1:2] == api.BLE_L2CAP_Event_ID.CB_CHANNEL_OPEN_CFM.value:
            if res[9:].hex().upper() in descript:
                return True
            else:
                logger.error(f'the receive error code = {res[9:].hex().upper()}')
                return False
        else:
            return False

    def mmi46(self,descript):
        logger.info(f'\n{descript}\n')

        res = self.readEvent()

        if res[:1] == api.Layer_ID.BLE_L2CAP.value and \
           res[1:2] == api.BLE_L2CAP_Event_ID.CB_CHANNEL_OPEN_CFM.value:
            if res[9:].hex().upper() in descript:
                return True
            else:
                logger.error('the receive error code = {0}'.format(res[9:].hex().upper()))
                return False
        else:
            return False

    def mmi47(self,descript):
        logger.info(f'\n{descript}\n')

        res = self.readEvent()

        if res[:1] == api.Layer_ID.BLE_L2CAP.value and \
           res[1:2] == api.BLE_L2CAP_Event_ID.CB_CHANNEL_OPEN_CFM.value:
            if res[9:].hex().upper() in descript:
                return True
            else:
                logger.error('the receive error code = {0}'.format(res[9:].hex().upper()))
                return False
        else:
            return False

    def mmi48(self,descript):
        logger.info(f'\n{descript}\n')

        res = self.readEvent()

        if res[:1] == api.Layer_ID.BLE_L2CAP.value and \
           res[1:2] == api.BLE_L2CAP_Event_ID.CB_CHANNEL_OPEN_CFM.value:
            if res[9:].hex().upper() in descript:
                return True
            else:
                return False
        else:
            return False

    def mmi49(self,descript):
        logger.info(''.join(['\n', descript,'\n']))

        conninfo = self.create_connection('BT')

        if not conninfo:
            return False

        self.conninfo = conninfo

        time.sleep(2)

        if self.casename_b == b'L2CAP/COS/IEX/BV-01-C' or \
           self.casename_b == b'L2CAP/FIX/BV-01-C':
            infoType = b''.join([self.conninfo['connhandle'],
                                 api.BT_L2CAP_INFO_TYPE.EXTENDED_FEATURES.value])

            if self.CommandRW(COMMAND = [api.Layer_ID.BT_L2CAP,
                                         api.BT_L2CAP_CMD_ID.INFO_REQ,
                                         infoType],
                              EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                         api.Layer_ID.BT_L2CAP,
                                         api.BT_L2CAP_CMD_ID.INFO_REQ]):

                if self.casename_b == b'L2CAP/FIX/BV-01-C':

                    infoType = b''.join([self.conninfo['connhandle'],
                                         api.BT_L2CAP_INFO_TYPE.FIX_CHANNELS.value])

                    if self.CommandRW(COMMAND = [api.Layer_ID.BT_L2CAP,
                                                 api.BT_L2CAP_CMD_ID.INFO_REQ,
                                                 infoType],
                                      EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                                 api.Layer_ID.BT_L2CAP,
                                                 api.BT_L2CAP_CMD_ID.INFO_REQ]):
                        return
                    else:
                        return False

                return
            else:
                return False

        OpenChanReq  = b''.join([self.conninfo['connhandle'],
                                 bytes.fromhex(self.ixit[b'TSPX_psm'][1].decode()),
                                 len(api.BT_L2CAP_CONF_OPTIONS.MTU.value).to_bytes(1,'big'),
                                 api.BT_L2CAP_CONF_OPTIONS.MTU.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.BT_L2CAP,
                                     api.BT_L2CAP_CMD_ID.OPEN_CHAN_REQ,
                                     OpenChanReq],
                          EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                     api.Layer_ID.BT_L2CAP,
                                     api.BT_L2CAP_CMD_ID.OPEN_CHAN_REQ]):
            return
        else:
            return False

    def mmi51(self,descript):
        logger.info(f'\n{descript}\n')

        if self.ixit[b'TSPX_iut_role_initiator'][1] == b'TRUE':
            mtu = api.GATT_MTU_LENGTH.DEFAULT_MTU_LEN.value.to_bytes(2,'big')

            if not self.CommandRW(COMMAND = [api.Layer_ID.BLE_GATT,
                                             api.GATT_CMD_ID.SET_PREFERRED_MTU,
                                             mtu],
                                  EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                             api.Layer_ID.BLE_GATT,
                                             api.GATT_CMD_ID.SET_PREFERRED_MTU]):
                return False

        psm = bytes()

        if b'TSPX_le_psm' in self.ixit.keys():
            psm = self.ixit[b'TSPX_le_psm'][1].decode()

        if b'TSPX_spsm' in self.ixit.keys():
            psm = self.ixit[b'TSPX_spsm'][1].decode()

        mtu           = b'\x00\xFA'
        initialCredit = b'\x00\x02'
        spsm          = b''.join([bytes.fromhex(psm),
                                  mtu,
                                  bytes.fromhex(self.ixit[b'TSPX_tester_mps'][1].decode()),
                                  initialCredit,
                                  api.BLE_L2CAP_SPSM.PERMISSION_AUTH.value])

        if self.casename_b == b'L2CAP/LE/CFC/BV-04-C':
            spsm = b''.join([bytes.fromhex(self.ixit[b'TSPX_psm_unsupported'][1].decode()),
                             mtu,
                             bytes.fromhex(self.ixit[b'TSPX_tester_mps'][1].decode()),
                             initialCredit,
                             api.BLE_L2CAP_SPSM.PERMISSION_AUTH.value])

        if self.casename_b == b'L2CAP/LE/CFC/BV-11-C':
            spsm = b''.join([bytes.fromhex(self.ixit[b'TSPX_psm_authentication_required'][1].decode()),
                             mtu,
                             bytes.fromhex(self.ixit[b'TSPX_tester_mps'][1].decode()),
                             initialCredit,
                             api.BLE_L2CAP_SPSM.PERMISSION_AUTH.value])

        if self.casename_b == b'L2CAP/LE/CFC/BV-13-C':
            spsm = b''.join([bytes.fromhex(self.ixit[b'TSPX_psm_authorization_required'][1].decode()),
                             mtu,
                             bytes.fromhex(self.ixit[b'TSPX_tester_mps'][1].decode()),
                             initialCredit,
                             api.BLE_L2CAP_SPSM.PERMISSION_AUTH.value])

        if self.casename_b == b'L2CAP/LE/CFC/BV-15-C':
            spsm = b''.join([bytes.fromhex(self.ixit[b'TSPX_psm_encryption_key_size_required'][1].decode()),
                             mtu,
                             bytes.fromhex(self.ixit[b'TSPX_tester_mps'][1].decode()),
                             initialCredit,
                             api.BLE_L2CAP_SPSM.PERMISSION_AUTH.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.BLE_L2CAP,
                                     api.BLE_L2CAP_CMD_ID.SPSM_REGISTER,
                                     spsm],
                          EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                     api.Layer_ID.BLE_L2CAP,
                                     api.BLE_L2CAP_CMD_ID.SPSM_REGISTER]):

            conninfo = self.create_connection('BLE')

            if not conninfo:
                return False

            self.conninfo = conninfo

            res = self.readEvent()

            if not res:
                return

            channel_open_req = b''.join([api.Layer_ID.BLE_L2CAP.value,
                                         api.BLE_L2CAP_Event_ID.CB_CHANNEL_OPEN_REQ.value,
                                         self.conninfo['connhandle']])

            if res[:4] == channel_open_req:
                rsp = b''.join([self.conninfo['connhandle'],
                                api.BT_L2CAP_CONN_RSP_RESULT.SUCCESSFUL.value])

                if self.CommandRW(COMMAND = [api.Layer_ID.BLE_L2CAP,
                                             api.BLE_L2CAP_CMD_ID.CB_CONN_RSP,
                                             rsp],
                                  EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                             api.Layer_ID.BLE_L2CAP,
                                             api.BLE_L2CAP_CMD_ID.CB_CONN_RSP]):
                    return

        else:
            return False

    def mmi52(self,descript):
        logger.info(f'\n{descript}\n')

        res = self.readEvent()

        if res[:1] == api.Layer_ID.BLE_L2CAP.value and \
           res[1:2] == api.BLE_L2CAP_Event_ID.CB_CHANNEL_OPEN_CFM.value:
            # line 16377 ~ 16341 work around PTS7.6.2 issue
            if self.casename_b == b'L2CAP/LE/CFC/BV-19-C':
                if res[9:].hex().upper() == '000A':
                    return True
                else:
                    return False

            if res[9:].hex().upper() in descript:
                return True
            else:
                logger.error('the receive error code = {0}'.format(res[9:].hex().upper()))
                return False
        else:
            return False

    def mmi53(self,descript):
        logger.info(f'\n{descript}\n')

        res = self.readEvent()

        if res[:1] == api.Layer_ID.BLE_L2CAP.value and \
           res[1:2] == api.BLE_L2CAP_Event_ID.CB_CHANNEL_OPEN_CFM.value:
            if res[9:].hex().upper() in descript:
                return True
            else:
                logger.error('the receive error code = {0}'.format(res[9:].hex().upper()))
                return False
        else:
            return False

    def mmi54(self,descript):
        logger.info(f'\n{descript}\n')

        res = self.readEvent()

        if res[:1] == api.Layer_ID.BLE_L2CAP.value and \
           res[1:2] == api.BLE_L2CAP_Event_ID.CB_CHANNEL_OPEN_CFM.value:
            if res[9:].hex().upper() in descript:
                return True
            else:
                logger.error('the receive error code = {0}'.format(res[9:].hex().upper()))
                return False
        else:
            return False

    def mmi55(self,descript):
        logger.info(''.join(['\n', descript,'\n']))

        mps = self.ixit[b'TSPX_tester_mps'][1]

        self.sdudata = b''.join([i.to_bytes(1,'big') for i in range(int(mps,16))])

        data = b''.join([self.id,
                         self.sdudata])

        if self.CommandRW(COMMAND = [api.Layer_ID.BLE_L2CAP,
                                     api.BLE_L2CAP_CMD_ID.CB_SEND_SDU,
                                     data],
                          EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                     api.Layer_ID.BLE_L2CAP,
                                     api.BLE_L2CAP_CMD_ID.CB_SEND_SDU]):
            return
        else:
            return False

    def mmi56(self,descript):
        logger.info(''.join(['\n', descript,'\n']))

        psm = bytes()

        if b'TSPX_le_psm' in self.ixit.keys():
            psm = self.ixit[b'TSPX_le_psm'][1].decode()

        if b'TSPX_spsm' in self.ixit.keys():
            psm = self.ixit[b'TSPX_spsm'][1].decode()

        mtu           = b'\x00\xFA'
        initialCredit = b'\x00\x02'
        spsm          = b''.join([bytes.fromhex(psm),
                                  mtu,
                                  bytes.fromhex(self.ixit[b'TSPX_tester_mps'][1].decode()),
                                  initialCredit,
                                  api.BLE_L2CAP_SPSM.PERMISSION_AUTH.value])

        if self.casename_b == b'L2CAP/LE/CFC/BV-04-C':
            spsm = b''.join([bytes.fromhex(self.ixit[b'TSPX_psm_unsupported'][1].decode()),
                             mtu,
                             bytes.fromhex(self.ixit[b'TSPX_tester_mps'][1].decode()),
                             initialCredit,
                             api.BLE_L2CAP_SPSM.PERMISSION_AUTH.value])

        if self.casename_b == b'L2CAP/LE/CFC/BV-11-C':
            spsm = b''.join([bytes.fromhex(self.ixit[b'TSPX_psm_authentication_required'][1].decode()),
                             mtu,
                             bytes.fromhex(self.ixit[b'TSPX_tester_mps'][1].decode()),
                             initialCredit,
                             api.BLE_L2CAP_SPSM.PERMISSION_AUTH.value])

        if self.casename_b == b'L2CAP/LE/CFC/BV-13-C':
            spsm = b''.join([bytes.fromhex(self.ixit[b'TSPX_psm_authorization_required'][1].decode()),
                             mtu,
                             bytes.fromhex(self.ixit[b'TSPX_tester_mps'][1].decode()),
                             initialCredit,
                             api.BLE_L2CAP_SPSM.PERMISSION_AUTH.value])

        if self.casename_b == b'L2CAP/LE/CFC/BV-15-C':
            spsm = b''.join([bytes.fromhex(self.ixit[b'TSPX_psm_encryption_key_size_required'][1].decode()),
                             mtu,
                             bytes.fromhex(self.ixit[b'TSPX_tester_mps'][1].decode()),
                             initialCredit,
                             api.BLE_L2CAP_SPSM.PERMISSION_AUTH.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.BLE_L2CAP,
                                     api.BLE_L2CAP_CMD_ID.SPSM_REGISTER,
                                     spsm],
                          EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                     api.Layer_ID.BLE_L2CAP,
                                     api.BLE_L2CAP_CMD_ID.SPSM_REGISTER]):

            AdvData = b''.join([len(api.BLE_GAP_ADV.DATATYPE_Flags.value
                                    + api.BLE_GAP_ADV.Flags_General_Discover.value).to_bytes(1, 'big'),
                                api.BLE_GAP_ADV.DATATYPE_Flags.value,
                                api.BLE_GAP_ADV.Flags_General_Discover.value])

            AdvParam = b''.join([b'\x00\x20\x00\x20',
                                 api.BLE_GAP_ADV.TYPE_ADV_IND.value,
                                 api.BLE_GAP_ADDR_TYPE.PUBLIC.value,
                                 api.BLE_GAP_ADDR_TYPE.PUBLIC.value,
                                 bytes.fromhex(self.pts_address_b.decode())[::-1],
                                 api.BLE_GAP_ADV.CHANNEL_ALL.value,
                                 api.BLE_GAP_ADV.FILTER_POLICY_DEFAULT.value])

            if not self.advertising(advData=AdvData, advParam=AdvParam, EnDisable=api.BLE_GAP_ADV.ENABLE):
                return False

            conninfo = self.get_connetion_info()

            if not conninfo:
                return False

            self.conninfo = conninfo

            if self.casename_b == b'L2CAP/LE/REJ/BI-02-C':
                self.wait = 40
                return [None,'mmi']

            res = self.readEvent()

            if not res:
                return

            channel_open_req = b''.join([api.Layer_ID.BLE_L2CAP.value,
                                         api.BLE_L2CAP_Event_ID.CB_CHANNEL_OPEN_REQ.value,
                                         self.conninfo['connhandle']])

            if res[:4] == channel_open_req:
                rsp = b''.join([self.conninfo['connhandle'],
                                api.BT_L2CAP_CONN_RSP_RESULT.SUCCESSFUL.value])

                if self.CommandRW(COMMAND = [api.Layer_ID.BLE_L2CAP,
                                             api.BLE_L2CAP_CMD_ID.CB_CONN_RSP,
                                             rsp],
                                  EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                             api.Layer_ID.BLE_L2CAP,
                                             api.BLE_L2CAP_CMD_ID.CB_CONN_RSP]):

                    if self.casename_b == b'L2CAP/COS/CFC/BV-03-C':
                        creditsNum = b'\x00\x05'
                        credit = b''.join([self.id,
                                           creditsNum])

                        if self.CommandRW(COMMAND = [api.Layer_ID.BLE_L2CAP,
                                                     api.BLE_L2CAP_CMD_ID.CB_ADD_CREDIT,
                                                     credit],
                                          EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                                     api.Layer_ID.BLE_L2CAP,
                                                     api.BLE_L2CAP_CMD_ID.CB_ADD_CREDIT]):
                            return
                        else:
                            return False

                    if self.casename_b == b'L2CAP/LE/CFC/BV-07-C':
                        res_Data = self.CommandRW(EVENT = [api.Layer_ID.BLE_L2CAP,
                                                           api.BLE_L2CAP_Event_ID.CB_SDU_IND,
                                                           self.id],
                                                  back  =  True)

                        if not res_Data:
                            return False

                        self.dataInd.append(res_Data[5:].hex().upper())

                        creditsNum = b'\x00\x05'
                        credit = b''.join([self.id,creditsNum])

                        if self.CommandRW(COMMAND = [api.Layer_ID.BLE_L2CAP,
                                                     api.BLE_L2CAP_CMD_ID.CB_ADD_CREDIT,
                                                     credit],
                                          EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                                     api.Layer_ID.BLE_L2CAP,
                                                     api.BLE_L2CAP_CMD_ID.CB_ADD_CREDIT]):

                            cb_disconnect = b''.join([api.Layer_ID.BLE_L2CAP.value,
                                                      api.BLE_L2CAP_Event_ID.CB_DISC_IND.value,
                                                      self.id])

                            res = b''

                            res_count = 0

                            while res != cb_disconnect or res_count < 10:
                                res = self.readEvent()

                                if res == cb_disconnect:
                                    return

                                sdu_Ind = b''.join([api.Layer_ID.BLE_L2CAP.value,
                                                    api.BLE_L2CAP_Event_ID.CB_SDU_IND.value,
                                                    self.id])

                                if not res:
                                    return False

                                if res[:3] == sdu_Ind:
                                    self.dataInd.append(res_Data[5:].hex().upper())

                                res_count += 1

                        else:
                            return False

                    if self.casename_b == b'L2CAP/LE/CFC/BV-17-C':
                        if self.CommandRW(EVENT = [api.Layer_ID.BLE_L2CAP,
                                                   api.BLE_L2CAP_Event_ID.CB_CHANNEL_OPEN_REQ,
                                                   self.conninfo['connhandle']]):

                            rsp = b''.join([self.conninfo['connhandle'],
                                            api.BT_L2CAP_CONN_RSP_RESULT.REFUSED_NRA.value])

                            if self.CommandRW(COMMAND = [api.Layer_ID.BLE_L2CAP,
                                                         api.BLE_L2CAP_CMD_ID.CB_CONN_RSP,
                                                         rsp],
                                              EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                                         api.Layer_ID.BLE_L2CAP,
                                                         api.BLE_L2CAP_CMD_ID.CB_CONN_RSP]):
                                return
                            else:
                                return False
        else:
            return False

    def mmi57(self,descript):
        logger.info(''.join(['\n', descript,'\n']))

        data = b''.join([self.id,
                         bytes.fromhex(self.iut_address_b.decode())])

        if self.CommandRW(COMMAND = [api.Layer_ID.BLE_L2CAP,
                                     api.BLE_L2CAP_CMD_ID.CB_SEND_SDU,
                                     data],
                          EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                     api.Layer_ID.BLE_L2CAP,
                                     api.BLE_L2CAP_CMD_ID.CB_SEND_SDU]):
            return
        else:
            return False

    def mmi58(self,descript):
        logger.info(''.join(['\n', descript,'\n']))

        data = b''.join([self.id,
                         bytes.fromhex(self.iut_address_b.decode())])

        if self.CommandRW(COMMAND = [api.Layer_ID.BLE_L2CAP,
                                     api.BLE_L2CAP_CMD_ID.CB_SEND_SDU,
                                     data],
                          EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                     api.Layer_ID.BLE_L2CAP,
                                     api.BLE_L2CAP_CMD_ID.CB_SEND_SDU]):
            return [None,'mmi']
        else:
            return False

    def mmi59(self,descript):
        logger.info(''.join(['\n', descript,'\n']))

        parameter = b''.join([self.conninfo['connhandle'],
                              bytes.fromhex(self.ixit[b'TSPX_tester_conn_interval_min'][1].decode()),
                              bytes.fromhex(self.ixit[b'TSPX_tester_conn_interval_max'][1].decode()),
                              bytes.fromhex(self.ixit[b'TSPX_tester_conn_latency'][1].decode()),
                              self.conninfo['connpara']])

        if self.CommandRW(COMMAND = [api.Layer_ID.BLE_L2CAP,
                                     api.BLE_L2CAP_CMD_ID.BLE_CPU,
                                     parameter],
                          EVENT   = [api.Layer_ID.BLE_L2CAP,
                                     api.BLE_L2CAP_Event_ID.CONN_PARA_UPDATE_RSP,
                                     self.conninfo['connhandle']]):
            return
        else:
            return False

    def mmi112(self,descript):
        logger.info(f'\n{descript}\n')

        if self.dataInd:
            for dataInd in [set(i) for i in self.dataInd]:
                if len(dataInd) != 1:
                    logger.error('channel data not all same , the data have {0}'.format(dataInd))
                    return False

                data = ''.join(['0x',dataInd.pop().to_bytes(1,'big').hex().upper()])
                if data not in descript:
                    logger.error('channel data {0} not consists'.format(data))
        else:
            return False

        return True

    def mmi252(self,descript):
        logger.info(f'\n{descript}\n')

        res = self.readEvent()

        if res[:1] == api.Layer_ID.BLE_L2CAP.value and \
           res[1:2] == api.BLE_L2CAP_Event_ID.CB_CHANNEL_OPEN_CFM.value:
            if res[9:].hex().upper() in descript:
                return True
            else:
                logger.error('the receive error code = {0}'.format(res[9:].hex().upper()))
                return False
        else:
            return False

    def mmi253(self,descript):
        logger.info(f'\n{descript}\n')

        res = self.readEvent()

        if res[:1] == api.Layer_ID.BLE_L2CAP.value and \
           res[1:2] == api.BLE_L2CAP_Event_ID.CB_CHANNEL_OPEN_CFM.value:
            if res[9:].hex().upper() in descript:
                return True
            else:
                logger.error('the receive error code = {0}'.format(res[9:].hex().upper()))
                return False
        else:
            return False

    def mmi254(self,descript):
        logger.info(f'\n{descript}\n')

        res = self.readEvent()

        if res[:1] == api.Layer_ID.BLE_L2CAP.value and \
           res[1:2] == api.BLE_L2CAP_Event_ID.CB_CHANNEL_OPEN_CFM.value:
            if res[9:].hex().upper() in descript:
                return True
            else:
                logger.error('the receive error code = {0}'.format(res[9:].hex().upper()))
                return False
        else:
            return False

    def mmi256(self,descript):
        logger.info(''.join(['\n', descript,'\n']))

        if self.CommandRW(EVENT=[api.Layer_ID.BLE_L2CAP,
                                 api.BLE_L2CAP_Event_ID.CB_CHANNEL_OPEN_REQ,
                                 self.conninfo['connhandle']]):

            rsp = b''.join([self.conninfo['connhandle'],
                            api.BT_L2CAP_CONN_RSP_RESULT.SUCCESSFUL.value])

            if self.CommandRW(COMMAND=[api.Layer_ID.BLE_L2CAP,
                                       api.BLE_L2CAP_CMD_ID.CB_CONN_RSP,
                                       rsp],
                              EVENT=[api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                     api.Layer_ID.BLE_L2CAP,
                                     api.BLE_L2CAP_CMD_ID.CB_CONN_RSP]):
                return
        else:
            return False

class PBAP(Common):
    def __init__(self,comport,profile,casename,ptsaddress_b,ixit,bleonly):
        Common.__init__(self,comport,profile,casename,ptsaddress_b,ixit,bleonly)
        self.id       = b'\x00'
        self.conninfo = None

    def mmi(self,descript):
        return

    def mmi1(self,descript):
        logger.info(''.join(['\n', descript,'\n']))
        readCount = 0
        srmWait   = b'\x00'
        pullPB    = b''.join([self.id,
                              srmWait,
                              api.PBAP_PhoneBookFolder.TELECOM.value,
                              api.PBAP_ObjectType.PB.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.PBAP,
                                     api.PBAP_CMD_ID.PULL_PHONEBOOK,
                                     pullPB],
                          EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                     api.Layer_ID.PBAP,
                                     api.PBAP_CMD_ID.PULL_PHONEBOOK]):

            if self.casename_b == b'PBAP/PCE/PDF/BV-06-I':
                return

            while 1:
                pullPBCfm = self.CommandRW(EVENT = [api.Layer_ID.PBAP,
                                                    api.PBAP_Event_ID.PULL_PHONEBOOK_CFM,
                                                    self.id],
                                           back  =  True)

                if not pullPBCfm:
                    logger.error('not received pull phone book comfirmation..')
                    return False

                if pullPBCfm[4:5] == b'\x01':
                    return

                if readCount > 200:
                    logger.error('over 200 time phone book not end ..')
                    return False

                readCount += 1
        else:
            return False

    def mmi9(self,descript):
        logger.info(''.join(['\n', descript,'\n']))
        srmWait = b'\x01'
        pullVcardList = b''.join([self.id,
                                  srmWait,
                                  api.PBAP_PhoneBookFolder.PB.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.PBAP,
                                     api.PBAP_CMD_ID.PULL_VCARD_LISTING,
                                     pullVcardList],
                          EVENT   = [api.Layer_ID.PBAP,
                                     api.PBAP_Event_ID.PULL_VCARD_LISTING_CFM,
                                     self.id]):
            return
        else:
            return False

    def mmi15(self,descript):
        logger.info(''.join(['\n', descript,'\n']))

        setTelecom = b''.join([self.id,
                               api.PBAP_PhoneBookAction.GO_DOWN_1_ELVEL.value,
                               api.PBAP_PhoneBookFolder.TELECOM.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.PBAP,
                                     api.PBAP_CMD_ID.SET_PHONEBOOK,
                                     setTelecom],
                          EVENT   = [api.Layer_ID.PBAP,
                                     api.PBAP_Event_ID.SET_PHONEBOOK_CFM,
                                     self.id]):
            setPB = b''.join([self.id,
                              api.PBAP_PhoneBookAction.GO_DOWN_1_ELVEL.value,
                              api.PBAP_PhoneBookFolder.PB.value])

            if self.CommandRW(COMMAND = [api.Layer_ID.PBAP,
                                         api.PBAP_CMD_ID.SET_PHONEBOOK,
                                         setPB],
                              EVENT   = [api.Layer_ID.PBAP,
                                         api.PBAP_Event_ID.SET_PHONEBOOK_CFM,
                                         self.id]):
                srmWait = b'\x00'
                pullVcardEntry = b''.join([self.id,
                                           srmWait,
                                           api.PBAP_NAME_OPT.VCF.value,
                                           len(api.PBAP_STATUS.VCE_NO_NAME_RESOURCES.value).to_bytes(1,'big'),
                                           api.PBAP_STATUS.VCE_NO_NAME_RESOURCES.value])

                if self.CommandRW(COMMAND = [api.Layer_ID.PBAP,
                                             api.PBAP_CMD_ID.PULL_VCARD_ENTRY,
                                             pullVcardEntry],
                                  EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                             api.Layer_ID.PBAP,
                                             api.PBAP_CMD_ID.PULL_VCARD_ENTRY]):
                    return
                else:
                    return False
            else:
                return False
        else:
            return False

    def mmi18(self,descript):
        logger.info(''.join(['\n', descript,'\n']))

        setTelecom = b''.join([self.id,
                               api.PBAP_PhoneBookAction.GO_DOWN_1_ELVEL.value,
                               api.PBAP_PhoneBookFolder.TELECOM.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.PBAP,
                                     api.PBAP_CMD_ID.SET_PHONEBOOK,
                                     setTelecom],
                          EVENT   = [api.Layer_ID.PBAP,
                                     api.PBAP_Event_ID.SET_PHONEBOOK_CFM,
                                     self.id]):
            return
        else:
            return False

    def mmi37(self,descript):
        logger.info(''.join(['\n', descript,'\n']))
        return True

    def mmi4031(self,descript):
        logger.info(''.join(['\n', descript,'\n']))

        if self.CommandRW(COMMAND = [api.Layer_ID.PBAP,
                                     api.PBAP_CMD_ID.DISCONNECT,
                                     self.id],
                          EVENT   = [api.Layer_ID.PBAP,
                                     api.PBAP_Event_ID.DISCONNECT_CFM,
                                     self.id]):
            return
        else:
            return False

    def mmi4034(self,descript):
        logger.info(''.join(['\n', descript,'\n']))
        readCount = 0

        while 1:
            srmWait = b'\x01'
            pullPB  = b''.join([self.id,
                                srmWait,
                                api.PBAP_PhoneBookFolder.TELECOM.value,
                                api.PBAP_ObjectType.PB.value])

            if not self.CommandRW(COMMAND = [api.Layer_ID.PBAP,
                                             api.PBAP_CMD_ID.PULL_PHONEBOOK,
                                             pullPB],
                                  EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                             api.Layer_ID.PBAP,
                                             api.PBAP_CMD_ID.PULL_PHONEBOOK]):
                return False

            pullPBCfm = self.CommandRW(EVENT = [api.Layer_ID.PBAP,
                                                api.PBAP_Event_ID.PULL_PHONEBOOK_CFM,
                                                self.id],
                                       back  =  True)

            if not pullPBCfm:
                logger.error('not received pull phone book comfirmation..')
                return False

            if pullPBCfm[4:5] == b'\x01':
                return

            if readCount > 200:
                logger.error('over 200 time phone book not end ..')
                return False

            readCount += 1

    def mmi4035(self,descript):
        logger.info(''.join(['\n', descript,'\n']))
        readCount = 0

        if self.casename_b == b'PBAP/PCE/GOEP/SRM/BV-05-C':
            while 1:
                srmWait = b'\x00'
                pullPB  = b''.join([self.id,
                                    srmWait,
                                    api.PBAP_PhoneBookFolder.TELECOM.value,
                                    api.PBAP_ObjectType.PB.value])

                if not self.CommandRW(COMMAND = [api.Layer_ID.PBAP,
                                                 api.PBAP_CMD_ID.PULL_PHONEBOOK,
                                                 pullPB],
                                      EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                                 api.Layer_ID.PBAP,
                                                 api.PBAP_CMD_ID.PULL_PHONEBOOK]):
                    return False

                pullPBCfm = self.CommandRW(EVENT = [api.Layer_ID.PBAP,
                                                    api.PBAP_Event_ID.PULL_PHONEBOOK_CFM,
                                                    self.id],
                                           back  =  True)

                if not pullPBCfm:
                    logger.error('not received pull phone book comfirmation..')
                    return False

                if pullPBCfm[4:5] == b'\x01':
                    return

                if readCount > 200:
                    logger.error('over 200 time phone book not end ..')
                    return False

                readCount += 1

        while 1:
            srmWait = b'\x00'
            pullPB  = b''.join([self.id,
                                srmWait,
                                api.PBAP_PhoneBookFolder.TELECOM.value,
                                api.PBAP_ObjectType.PB.value])

            if not self.CommandRW(COMMAND = [api.Layer_ID.PBAP,
                                             api.PBAP_CMD_ID.PULL_PHONEBOOK,
                                             pullPB],
                                  EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                             api.Layer_ID.PBAP,
                                             api.PBAP_CMD_ID.PULL_PHONEBOOK]):
                return False

            pullPBCfm = self.CommandRW(EVENT = [api.Layer_ID.PBAP,
                                                api.PBAP_Event_ID.PULL_PHONEBOOK_CFM,
                                                self.id],
                                       back  =  True)
            if not pullPBCfm:
                logger.error('not received pull phone book comfirmation..')
                return False

            if pullPBCfm[3:4] == b'\x00':
                while 1:
                    pullPBCfm = self.CommandRW(EVENT = [api.Layer_ID.PBAP,
                                                        api.PBAP_Event_ID.PULL_PHONEBOOK_CFM,
                                                        self.id],
                                               back  =  True)

                    if not pullPBCfm:
                        logger.error('not received pull phone book comfirmation..')
                        return False

                    if pullPBCfm[4:5] == b'\x01':
                        return

                    if readCount > 200:
                        logger.error('over 200 time phone book not end ..')
                        return False

                    readCount += 1

            if readCount > 200:
                logger.error('over 200 time phone book not end ..')
                return False

            readCount += 1

    def mmi4047(self,descript):
        logger.info(''.join(['\n', descript,'\n']))

        conninfo = self.create_connection('BT')

        if not conninfo:
            return False

        self.conninfo = conninfo

        time.sleep(1)

        if self.CommandRW(COMMAND = [api.Layer_ID.PBAP,
                                     api.PBAP_CMD_ID.CONNECT,
                                     self.conninfo['connhandle']],
                          EVENT   = [api.Layer_ID.PBAP,
                                     api.PBAP_Event_ID.CONNECT_CFM,
                                     self.id]):
            return
        else:
            return False

    def mmi4048(self,descript):
        logger.info(''.join(['\n', descript,'\n']))

        conninfo = self.create_connection('BT')

        if not conninfo:
            return False

        self.conninfo = conninfo

        time.sleep(1)

        if self.CommandRW(COMMAND = [api.Layer_ID.PBAP,
                                     api.PBAP_CMD_ID.CONNECT,
                                     self.conninfo['connhandle']],
                          EVENT   = [api.Layer_ID.PBAP,
                                     api.PBAP_Event_ID.CONNECT_CFM,
                                     self.id]):
            return
        else:
            return False

    def mmi4049(self,descript):
        logger.info(''.join(['\n', descript,'\n']))

        if self.CommandRW(COMMAND = [api.Layer_ID.PBAP,
                                     api.PBAP_CMD_ID.DISCONNECT,
                                     self.id],
                          EVENT   = [api.Layer_ID.PBAP,
                                     api.PBAP_Event_ID.DISCONNECT_IND,
                                     self.id]):
            return
        else:
            return False

    def mmi4051(self, descript):
        logger.info(f'\n{descript}\n')

        return True

    def mmi4088(self,descript):
        logger.info(''.join(['\n', descript,'\n']))

        if self.CommandRW(COMMAND = [api.Layer_ID.PBAP,
                                     api.PBAP_CMD_ID.ABORT,
                                     self.id],
                          EVENT   = [api.Layer_ID.PBAP,
                                     api.PBAP_Event_ID.ABORT_CFM,
                                     self.id]):
            return
        else:
            return False

    def mmi4100(self,descript):
        logger.info(''.join(['\n', descript,'\n']))

        conninfo = self.create_connection('BT')

        if not conninfo:
            return False

        self.conninfo = conninfo

        time.sleep(1)

        if self.CommandRW(COMMAND = [api.Layer_ID.PBAP,
                                     api.PBAP_CMD_ID.CONNECT,
                                     self.conninfo['connhandle']],
                          EVENT   = [api.Layer_ID.PBAP,
                                     api.PBAP_Event_ID.CONNECT_CFM,
                                     self.id]):
            return
        else:
            return False

    def mmi4800(self,descript):
        logger.info(''.join(['\n', descript,'\n']))
        return True

class RFCOMM(Common):
    def __init__(self,comport,profile,casename,ptsaddress_b,ixit,bleonly):
        Common.__init__(self,comport,profile,casename,ptsaddress_b,ixit,bleonly)
        self.id       = b'\x00'
        self.conninfo = None

    def mmi(self,descript):
        if self.casename_b == b'RFCOMM/DEVA/RFC/BV-01-C' or \
           self.casename_b == b'RFCOMM/DEVA/RFC/BV-05-C':
            return

        if not self.conninfo:
            conninfo = self.get_connetion_info()

            if not conninfo:
                return False

            self.conninfo = conninfo

            init_credit = b'\x02'
            constructSession = b''.join([self.conninfo['connhandle'],
                                         bytes.fromhex(bytes.decode(self.ixit[b'TSPX_server_channel_iut'][1])),
                                         (int(self.ixit[b'TSPX_max_frame_size_iut'][1]) - 1).to_bytes(2, 'big'),
                                         init_credit,
                                         api.RFCOMM_ROLE.RESPONDER.value])

            if self.CommandRW(COMMAND = [api.Layer_ID.RFCOMM,
                                         api.RFCOMM_CMD_ID.CONSTRUCT_SESSION,
                                         constructSession],
                              EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                         api.Layer_ID.RFCOMM,
                                         api.RFCOMM_CMD_ID.CONSTRUCT_SESSION]):
                return
            else:
                return False

        return

    def mmi6(self,descript):
        logger.info(''.join(['\n', descript,'\n']))

        if self.CommandRW(COMMAND = [api.Layer_ID.RFCOMM,
                                     api.RFCOMM_CMD_ID.RESPOND_INITIATE_SESSION,
                                     self.id],
                          EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                     api.Layer_ID.RFCOMM,
                                     api.RFCOMM_CMD_ID.RESPOND_INITIATE_SESSION]):
            return
        else:
            return False

    def mmi9(self, descript):
        logger.info(f'\n{descript}\n')

        rcvCreditInd = b''.join([api.Layer_ID.RFCOMM.value,
                                 api.RFCOMM_Event_ID.RCV_CREDIT_IND.value,
                                 self.conninfo['connhandle']])

        rev = self.readEvent()

        if not rev:
            return False

        if rev == rcvCreditInd:
            data = b'\x01\x02\x03\x04'
            uihData = b''.join([self.id,
                                len(data).to_bytes(2, 'big'),
                                data])

            if self.CommandRW(COMMAND = [api.Layer_ID.RFCOMM,
                                         api.RFCOMM_CMD_ID.SEND_UIH_DATA,
                                         uihData],
                              EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                         api.Layer_ID.RFCOMM,
                                         api.RFCOMM_CMD_ID.SEND_UIH_DATA]):
                return
            else:
                return False

        return

    def mmi14(self,descript):
        logger.info(''.join(['\n', descript,'\n']))

        if self.CommandRW(COMMAND = [api.Layer_ID.RFCOMM,
                                     api.RFCOMM_CMD_ID.SEND_DISC_DLC,
                                     self.id],
                          EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                     api.Layer_ID.RFCOMM,
                                     api.RFCOMM_CMD_ID.SEND_DISC_DLC]):
            return
        else:
            return False

    def mmi15(self,descript):
        logger.info(''.join(['\n', descript,'\n']))

        if self.CommandRW(COMMAND = [api.Layer_ID.RFCOMM,
                                     api.RFCOMM_CMD_ID.SEND_DISC_DLC,
                                     self.id],
                          EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                     api.Layer_ID.RFCOMM,
                                     api.RFCOMM_CMD_ID.SEND_DISC_DLC]):
            return
        else:
            return False

    def mmi20(self,descript):
        logger.info(''.join(['\n', descript,'\n']))

        conninfo = self.create_connection('BT')

        if not conninfo:
            return False

        self.conninfo = conninfo

        time.sleep(1)

        init_credit      = b'\x02'
        constructSession = b''.join([self.conninfo['connhandle'],
                                     bytes.fromhex(bytes.decode(self.ixit[b'TSPX_server_channel_iut'][1])),
                                     (int(self.ixit[b'TSPX_max_frame_size_iut'][1])-1).to_bytes(2,'big'),
                                     init_credit,
                                     api.RFCOMM_ROLE.INITIATOR.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.RFCOMM,
                                     api.RFCOMM_CMD_ID.CONSTRUCT_SESSION,
                                     constructSession],
                          EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                     api.Layer_ID.RFCOMM,
                                     api.RFCOMM_CMD_ID.CONSTRUCT_SESSION]):

            initiateSession = b''.join([self.conninfo['connhandle'],
                                         bytes.fromhex(bytes.decode(self.ixit[b'TSPX_server_channel_iut'][1])),
                                         api.RFCOMM_ROLE.INITIATOR.value])

            if self.CommandRW(COMMAND = [api.Layer_ID.RFCOMM,
                                         api.RFCOMM_CMD_ID.INITIATE_SESSION,
                                         initiateSession],
                              EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                         api.Layer_ID.RFCOMM,
                                         api.RFCOMM_CMD_ID.INITIATE_SESSION]):
                return
            else:
                return False
        else:
            return False

    def mmi22(self, descript):
        logger.info(f'\n{descript}\n')

        if self.CommandRW(EVENT=[api.Layer_ID.RFCOMM,
                                 api.RFCOMM_Event_ID.OPEN_SESSION_CFM,
                                 self.id]):

            data = b'\x01\x02\x03\x04'
            uihData = b''.join([self.id,
                                len(data).to_bytes(2, 'big'),
                                data])

            if self.CommandRW(COMMAND = [api.Layer_ID.RFCOMM,
                                         api.RFCOMM_CMD_ID.SEND_UIH_DATA,
                                         uihData],
                              EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                         api.Layer_ID.RFCOMM,
                                         api.RFCOMM_CMD_ID.SEND_UIH_DATA]):
                return
            else:
                return False
        else:
            return False

    def mmi23(self,descript):
        logger.info(''.join(['\n', descript,'\n']))

        rlsData = b''.join([self.id,
                            api.RFCOMM_RLS_STATUS.FRAMING_ERROR.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.RFCOMM,
                                     api.RFCOMM_CMD_ID.SEND_RLS,
                                     rlsData],
                          EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                     api.Layer_ID.RFCOMM,
                                     api.RFCOMM_CMD_ID.SEND_RLS]):
            return
        else:
            return False

class SDP(Common):
    def __init__(self,comport,profile,casename,ptsaddress_b,ixit,bleonly):
        Common.__init__(self,comport,profile,casename,ptsaddress_b,ixit,bleonly)
        self.id       = b'\x00'
        self.conninfo = None

    def mmi(self,descript):
        return

class SM(Common):
    def __init__(self,comport,profile,casename,ptsaddress_b,ixit,bleonly):
        Common.__init__(self,comport,profile,casename,ptsaddress_b,ixit,bleonly)
        self.id          = b'\x00'
        self.conninfo    = None
        self.wait        = None
        self.oob_confirm = None
        self.oob_random  = None

    def mmi(self,descript):
        if self.wait:
            time.sleep(self.wait)
            self.wait = None
            return

        if self.casename_b == b'SM/CEN/KDU/BI-01-C' or \
           self.casename_b == b'SM/CEN/SIP/BV-02-C':
            if self.conninfo:
                if self.CommandRW(EVENT = [api.Layer_ID.BLE_SMP,
                                           api.SMP_Event_ID.SECURITY_REQUEST,
                                           self.conninfo['connhandle']]):
                    if self.CommandRW(COMMAND = [api.Layer_ID.BLE_SMP,
                                                 api.SMP_CMD_ID.INIT_PAIR,
                                                 self.conninfo['connhandle']],
                                      EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                                 api.Layer_ID.BLE_SMP,
                                                 api.SMP_CMD_ID.INIT_PAIR]):
                        return
                    else:
                        return False
                else:
                    return
            else:
                return

        if self.casename_b == b'SM/PER/SCPK/BI-04-C':
            if self.conninfo:
                AdvData = b''.join([len(api.BLE_GAP_ADV.DATATYPE_Flags.value
                                        + api.BLE_GAP_ADV.Flags_Non_Discover.value).to_bytes(1, 'big'),
                                    api.BLE_GAP_ADV.DATATYPE_Flags.value,
                                    api.BLE_GAP_ADV.Flags_Non_Discover.value])

                AdvParam = b''.join([b'\x00\x20\x00\x20',
                                     api.BLE_GAP_ADV.TYPE_ADV_IND.value,
                                     api.BLE_GAP_ADDR_TYPE.PUBLIC.value,
                                     api.BLE_GAP_ADDR_TYPE.PUBLIC.value,
                                     bytes.fromhex(self.pts_address_b.decode())[::-1],
                                     api.BLE_GAP_ADV.CHANNEL_ALL.value,
                                     api.BLE_GAP_ADV.FILTER_POLICY_DEFAULT.value])

                if not self.advertising(advData=AdvData, advParam=AdvParam, EnDisable=api.BLE_GAP_ADV.ENABLE):
                    return False

        return

    def mmi100(self,descript):
        logger.info(''.join(['\n', descript,'\n']))
        config = bytes()

        if self.casename_b == b'SM/CEN/PROT/BV-01-C' or \
           self.casename_b == b'SM/CEN/JW/BV-05-C'   or\
           self.casename_b == b'SM/CEN/JW/BI-01-C'   or \
           self.casename_b == b'SM/CEN/EKS/BV-01-C'  or \
           self.casename_b == b'SM/CEN/EKS/BI-01-C'  or \
           self.casename_b == b'SM/CEN/KDU/BV-04-C' or \
           self.casename_b == b'SM/CEN/KDU/BV-05-C' or \
           self.casename_b == b'SM/CEN/KDU/BV-06-C':
            config = b''.join([api.SMP_IoCapability.NOINPUTNOOUTPUT.value,
                               api.SMP_AuthReqFlag.NOBONDING.value,
                               api.SMP_OOB.NOT_PRESENT.value,
                               api.SMP_SECURE_SET.NOSECURE.value])

        if self.casename_b == b'SM/CEN/PKE/BV-01-C' or \
           self.casename_b == b'SM/CEN/PKE/BV-04-C' or \
           self.casename_b == b'SM/CEN/PKE/BI-01-C' or \
           self.casename_b == b'SM/CEN/PKE/BI-02-C' or \
           self.casename_b == b'SM/CEN/OOB/BV-05-C' or \
           self.casename_b == b'SM/CEN/OOB/BV-07-C':
            config = b''.join([api.SMP_IoCapability.DISPLAYONLY.value,
                               api.SMP_AuthReqFlag.NOBONDING.value,
                               api.SMP_OOB.NOT_PRESENT.value,
                               api.SMP_SECURE_SET.NOSECURE.value])

        if self.casename_b == b'SM/CEN/OOB/BV-01-C' or \
           self.casename_b == b'SM/CEN/OOB/BV-03-C' or \
           self.casename_b == b'SM/CEN/OOB/BV-09-C' or \
           self.casename_b == b'SM/CEN/OOB/BI-01-C':
            config = b''.join([api.SMP_IoCapability.KEYBOARDDISPLAY.value,
                               api.SMP_AuthReqFlag.BONDINGMITM.value,
                               api.SMP_OOB.PRESENT.value,
                               api.SMP_SECURE_SET.NOSECURE.value])

        if self.casename_b == b'SM/CEN/KDU/BV-10-C' or \
           self.casename_b == b'SM/CEN/KDU/BI-01-C':
            config = b''.join([api.SMP_IoCapability.NOINPUTNOOUTPUT.value,
                               api.SMP_AuthReqFlag.BONDSECCNT.value,
                               api.SMP_OOB.NOT_PRESENT.value,
                               api.SMP_SECURE_SET.NOSECURE.value])

        if self.casename_b == b'SM/CEN/SIP/BV-02-C':
            config = b''.join([api.SMP_IoCapability.KEYBOARDDISPLAY.value,
                               api.SMP_AuthReqFlag.NOBONDING.value,
                               api.SMP_OOB.NOT_PRESENT.value,
                               api.SMP_SECURE_SET.NOSECURE.value])

        if self.casename_b == b'SM/CEN/SCJW/BV-01-C' or \
           self.casename_b == b'SM/CEN/SCJW/BV-04-C' or \
           self.casename_b == b'SM/CEN/SCJW/BI-01-C':
            config = b''.join([api.SMP_IoCapability.NOINPUTNOOUTPUT.value,
                               api.SMP_AuthReqFlag.SECCNT.value,
                               api.SMP_OOB.NOT_PRESENT.value,
                               api.SMP_SECURE_SET.NOSECURE.value])

        if self.casename_b == b'SM/CEN/SCPK/BV-01-C' or \
           self.casename_b == b'SM/CEN/SCPK/BV-04-C' or \
           self.casename_b == b'SM/CEN/SCPK/BI-01-C':
            config = b''.join([api.SMP_IoCapability.DISPLAYONLY.value,
                               api.SMP_AuthReqFlag.SECCNT.value,
                               api.SMP_OOB.NOT_PRESENT.value,
                               api.SMP_SECURE_SET.NOSECURE.value])

        if self.casename_b == b'SM/CEN/SCPK/BI-02-C':
            config = b''.join([api.SMP_IoCapability.DISPLAYONLY.value,
                               api.SMP_AuthReqFlag.BONDSECCNT.value,
                               api.SMP_OOB.NOT_PRESENT.value,
                               api.SMP_SECURE_SET.NOSECURE.value])

        if self.casename_b == b'SM/CEN/SCOB/BV-01-C' or \
           self.casename_b == b'SM/CEN/SCOB/BV-04-C':
            conninfo = self.create_connection('BLE')

            if not conninfo:
                return False

            self.conninfo = conninfo

            return

        if self.casename_b == b'SM/CEN/SCOB/BI-01-C' or \
           self.casename_b == b'SM/CEN/SCOB/BI-04-C':
            config = b''.join([api.SMP_IoCapability.KEYBOARDDISPLAY.value,
                               api.SMP_AuthReqFlag.BONDSECCNT.value,
                               api.SMP_OOB.PRESENT.value,
                               api.SMP_SECURE_SET.NOSECURE.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.BLE_SMP,
                                     api.SMP_CMD_ID.CONFIG,
                                     config],
                          EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                     api.Layer_ID.BLE_SMP,
                                     api.SMP_CMD_ID.CONFIG]):

            conninfo = self.create_connection('BLE')

            if not conninfo:
                return False

            self.conninfo = conninfo

            if self.casename_b == b'SM/CEN/KDU/BI-01-C' or \
               self.casename_b == b'SM/CEN/SIP/BV-02-C':
                return [None,'mmi']

            return

        else:
            return False

    def mmi102(self,descript):
        logger.info(''.join(['\n', descript,'\n']))
        if self.casename_b == b'SM/CEN/JW/BV-05-C'   or \
           self.casename_b == b'SM/CEN/JW/BI-01-C'   or \
           self.casename_b == b'SM/CEN/PKE/BI-01-C'  or \
           self.casename_b == b'SM/CEN/PKE/BI-02-C'  or \
           self.casename_b == b'SM/CEN/OOB/BI-01-C' or \
           self.casename_b == b'SM/CEN/EKS/BI-01-C'  or \
           self.casename_b == b'SM/CEN/KDU/BI-01-C'  or \
           self.casename_b == b'SM/CEN/SCJW/BI-01-C' or \
           self.casename_b == b'SM/CEN/SCPK/BI-01-C' or \
           self.casename_b == b'SM/CEN/SCOB/BI-01-C' or \
           self.casename_b == b'SM/CEN/SCOB/BI-04-C':
            return

        Terminate = b''.join([self.conninfo['connhandle'],
                              api.BLE_GAP_DISC_REASON.REMOTE_TERMINATE.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.BLE_GAP,
                                     api.BLE_GAP_CMD_ID.TERMINATE_CONNECTION,
                                     Terminate],
                          EVENT   = [api.Layer_ID.BLE_GAP,
                                     api.BLE_GAP_Event_ID.DISCONNECTED,
                                     self.conninfo['connhandle']]):
            return
        else:
            return False

    def mmi104(self,descript):
        logger.info(''.join(['\n', descript,'\n']))

        passkey = self.CommandRW(EVENT = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                          api.Layer_ID.BLE_SMP,
                                          api.SMP_CMD_ID.GEN_PASSKEY],
                                 back  = True)
        if not passkey:
            return False

        if self.CommandRW(EVENT = [api.Layer_ID.BLE_SMP,
                                   api.SMP_Event_ID.DISPLAY_PASSKEY_REQUEST,
                                   self.conninfo['connhandle']]):

            logger.debug('PassKey :{0}'.format(passkey[5:]))

            return passkey[5:]

    def mmi106(self,descript):
        logger.info(''.join(['\n', descript,'\n']))
        return b'000000'

    def mmi108(self,descript):
        logger.info(''.join(['\n', descript,'\n']))

        if self.CommandRW(COMMAND = [api.Layer_ID.BLE_SMP,
                                     api.SMP_CMD_ID.INIT_PAIR,
                                     self.conninfo['connhandle']],
                          EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                     api.Layer_ID.BLE_SMP,
                                     api.SMP_CMD_ID.INIT_PAIR]):

            if self.casename_b == b'SM/CEN/OOB/BV-01-C' or \
               self.casename_b == b'SM/CEN/OOB/BI-01-C':

                if self.CommandRW(EVENT = [api.Layer_ID.BLE_SMP,
                                           api.SMP_Event_ID.INPUT_OOB_DATA_REQUEST,
                                           self.conninfo['connhandle']]):

                    oob_Data = b''.join([self.conninfo['connhandle'],
                                         bytes.fromhex(self.ixit[b'TSPX_OOB_Data'][1].decode())])

                    if self.CommandRW(COMMAND = [api.Layer_ID.BLE_SMP,
                                                 api.SMP_CMD_ID.SET_PRIVACY_KEY,
                                                 oob_Data],
                                      EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                                 api.Layer_ID.BLE_SMP,
                                                 api.SMP_CMD_ID.SET_PRIVACY_KEY]):
                        return
                    else:
                        return False
                else:
                    return False

            return
        else:
            return False

    def mmi109(self,descript):
        logger.info(''.join(['\n', descript,'\n']))

        if self.CommandRW(COMMAND = [api.Layer_ID.BLE_SMP,
                                     api.SMP_CMD_ID.INIT_PAIR,
                                     self.conninfo['connhandle']],
                          EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                     api.Layer_ID.BLE_SMP,
                                     api.SMP_CMD_ID.INIT_PAIR]):
            return
        else:
            return False

    def mmi115(self,descript):
        logger.info(''.join(['\n', descript,'\n']))
        config = bytes()

        if self.casename_b == b'SM/PER/PROT/BV-02-C' or \
           self.casename_b == b'SM/PER/JW/BV-02-C'   or \
           self.casename_b == b'SM/PER/JW/BI-03-C'   or \
           self.casename_b == b'SM/PER/OOB/BV-08-C'  or \
           self.casename_b == b'SM/PER/EKS/BV-02-C'  or \
           self.casename_b == b'SM/PER/EKS/BI-02-C'  or \
           self.casename_b == b'SM/PER/KDU/BV-01-C'  or \
           self.casename_b == b'SM/PER/KDU/BV-02-C':
            config = b''.join([api.SMP_IoCapability.NOINPUTNOOUTPUT.value,
                               api.SMP_AuthReqFlag.NOBONDING.value,
                               api.SMP_OOB.NOT_PRESENT.value,
                               api.SMP_SECURE_SET.NOSECURE.value])

        if self.casename_b == b'SM/PER/JW/BI-02-C'  or \
           self.casename_b == b'SM/PER/KDU/BV-07-C' or \
           self.casename_b == b'SM/PER/SIE/BV-01-C':
            config = b''.join([api.SMP_IoCapability.NOINPUTNOOUTPUT.value,
                               api.SMP_AuthReqFlag.BONDING.value,
                               api.SMP_OOB.NOT_PRESENT.value,
                               api.SMP_SECURE_SET.NOSECURE.value])

        if self.casename_b == b'SM/PER/PKE/BV-02-C' or \
           self.casename_b == b'SM/PER/PKE/BI-03-C' or \
           self.casename_b == b'SM/PER/OOB/BV-06-C':
            config = b''.join([api.SMP_IoCapability.DISPLAYONLY.value,
                               api.SMP_AuthReqFlag.NOBONDING.value,
                               api.SMP_OOB.NOT_PRESENT.value,
                               api.SMP_SECURE_SET.NOSECURE.value])

        if self.casename_b == b'SM/PER/PKE/BV-05-C':
            config = b''.join([api.SMP_IoCapability.NOINPUTNOOUTPUT.value,
                               api.SMP_AuthReqFlag.MITM.value,
                               api.SMP_OOB.NOT_PRESENT.value,
                               api.SMP_SECURE_SET.NOSECURE.value])

        if self.casename_b == b'SM/PER/OOB/BV-02-C' or \
           self.casename_b == b'SM/PER/OOB/BV-04-C' or \
           self.casename_b == b'SM/PER/OOB/BV-10-C' or \
           self.casename_b == b'SM/PER/OOB/BI-02-C':
            config = b''.join([api.SMP_IoCapability.DISPLAYONLY.value,
                               api.SMP_AuthReqFlag.BONDINGMITM.value,
                               api.SMP_OOB.PRESENT.value,
                               api.SMP_SECURE_SET.NOSECURE.value])

        if self.casename_b == b'SM/PER/KDU/BV-08-C':
            config = b''.join([api.SMP_IoCapability.NOINPUTNOOUTPUT.value,
                               api.SMP_AuthReqFlag.BONDSECCNT.value,
                               api.SMP_OOB.NOT_PRESENT.value,
                               api.SMP_SECURE_SET.NOSECURE.value])

        if self.casename_b == b'SM/PER/KDU/BI-01-C'  or \
           self.casename_b == b'SM/PER/SCJW/BV-02-C' or \
           self.casename_b == b'SM/PER/SCJW/BV-03-C' or \
           self.casename_b == b'SM/PER/SCJW/BI-02-C':
            config = b''.join([api.SMP_IoCapability.NOINPUTNOOUTPUT.value,
                               api.SMP_AuthReqFlag.SECCNT.value,
                               api.SMP_OOB.NOT_PRESENT.value,
                               api.SMP_SECURE_SET.NOSECURE.value])

        if self.casename_b == b'SM/PER/SIP/BV-01-C':
            config = b''.join([api.SMP_IoCapability.KEYBOARDDISPLAY.value,
                               api.SMP_AuthReqFlag.NOBONDING.value,
                               api.SMP_OOB.NOT_PRESENT.value,
                               api.SMP_SECURE_SET.NOSECURE.value])

        if self.casename_b == b'SM/PER/SCPK/BV-02-C' or \
           self.casename_b == b'SM/PER/SCPK/BV-03-C' or \
           self.casename_b == b'SM/PER/SCPK/BI-03-C':
            config = b''.join([api.SMP_IoCapability.DISPLAYONLY.value,
                               api.SMP_AuthReqFlag.SECCNT.value,
                               api.SMP_OOB.NOT_PRESENT.value,
                               api.SMP_SECURE_SET.NOSECURE.value])

        if self.casename_b == b'SM/PER/SCPK/BI-04-C':
            config = b''.join([api.SMP_IoCapability.KEYBOARDONLY.value,
                               api.SMP_AuthReqFlag.MITMSECCNT.value,
                               api.SMP_OOB.NOT_PRESENT.value,
                               api.SMP_SECURE_SET.NOSECURE.value])

        if self.casename_b == b'SM/PER/SCOB/BV-02-C' or \
           self.casename_b == b'SM/PER/SCOB/BV-03-C':

            AdvData = b''.join([len(api.BLE_GAP_ADV.DATATYPE_Flags.value
                                    + api.BLE_GAP_ADV.Flags_Non_Discover.value).to_bytes(1, 'big'),
                                api.BLE_GAP_ADV.DATATYPE_Flags.value,
                                api.BLE_GAP_ADV.Flags_Non_Discover.value])

            AdvParam = b''.join([b'\x00\x20\x00\x20',
                                 api.BLE_GAP_ADV.TYPE_ADV_IND.value,
                                 api.BLE_GAP_ADDR_TYPE.PUBLIC.value,
                                 api.BLE_GAP_ADDR_TYPE.PUBLIC.value,
                                 bytes.fromhex(self.pts_address_b.decode())[::-1],
                                 api.BLE_GAP_ADV.CHANNEL_ALL.value,
                                 api.BLE_GAP_ADV.FILTER_POLICY_DEFAULT.value])

            if not self.advertising(advData=AdvData, advParam=AdvParam, EnDisable=api.BLE_GAP_ADV.ENABLE):
                return False

            time.sleep(1)

            conninfo = self.get_connetion_info()
            if not conninfo:
                return False

            self.conninfo = conninfo

            return

        if self.casename_b == b'SM/PER/SCOB/BI-02-C' or \
           self.casename_b == b'SM/PER/SCOB/BI-03-C':
            config = b''.join([api.SMP_IoCapability.DISPLAYONLY.value,
                               api.SMP_AuthReqFlag.BONDSECCNT.value,
                               api.SMP_OOB.PRESENT.value,
                               api.SMP_SECURE_SET.NOSECURE.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.BLE_SMP,
                                     api.SMP_CMD_ID.CONFIG,
                                     config],
                          EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                     api.Layer_ID.BLE_SMP,
                                     api.SMP_CMD_ID.CONFIG]):

            AdvData = b''.join([len(api.BLE_GAP_ADV.DATATYPE_Flags.value
                                    + api.BLE_GAP_ADV.Flags_Non_Discover.value).to_bytes(1, 'big'),
                                api.BLE_GAP_ADV.DATATYPE_Flags.value,
                                api.BLE_GAP_ADV.Flags_Non_Discover.value])

            AdvParam = b''.join([b'\x00\x20\x00\x20',
                                 api.BLE_GAP_ADV.TYPE_ADV_IND.value,
                                 api.BLE_GAP_ADDR_TYPE.PUBLIC.value,
                                 api.BLE_GAP_ADDR_TYPE.PUBLIC.value,
                                 bytes.fromhex(self.pts_address_b.decode())[::-1],
                                 api.BLE_GAP_ADV.CHANNEL_ALL.value,
                                 api.BLE_GAP_ADV.FILTER_POLICY_DEFAULT.value])

            if not self.advertising(advData=AdvData, advParam=AdvParam, EnDisable=api.BLE_GAP_ADV.ENABLE):
                return False

            time.sleep(1)

            conninfo = self.get_connetion_info()
            if not conninfo:
                return False

            self.conninfo = conninfo

            if self.casename_b == b'SM/PER/OOB/BV-02-C' or \
               self.casename_b == b'SM/PER/OOB/BI-02-C':

                if self.CommandRW(EVENT = [api.Layer_ID.BLE_SMP,
                                           api.SMP_Event_ID.INPUT_OOB_DATA_REQUEST,
                                           self.conninfo['connhandle']]):

                    oob_Data = b''.join([self.conninfo['connhandle'],
                                         bytes.fromhex(self.ixit[b'TSPX_OOB_Data'][1].decode())])

                    if self.CommandRW(COMMAND = [api.Layer_ID.BLE_SMP,
                                                 api.SMP_CMD_ID.SET_PRIVACY_KEY,
                                                 oob_Data],
                                      EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                                 api.Layer_ID.BLE_SMP,
                                                 api.SMP_CMD_ID.SET_PRIVACY_KEY]):
                        return
                    else:
                        return False
                else:
                    return False

            if self.casename_b == b'SM/PER/SIE/BV-01-C' or \
               self.casename_b == b'SM/PER/SCPK/BI-04-C' or \
               self.casename_b == b'SM/PER/SCOB/BI-02-C':
                return [None,'mmi']

            else:
                return

        else:
            return False

    def mmi143(self,descript):
        logger.info(''.join(['\n', descript,'\n']))
        if self.iut_initial(self.bleonly):
            return True
        else:
            return False

    def mmi145(self,descript):
        logger.info(''.join(['\n', descript,'\n']))

        config = b''.join([api.SMP_IoCapability.KEYBOARDDISPLAY.value,
                           api.SMP_AuthReqFlag.BONDSECCNT.value,
                           api.SMP_OOB.NOT_PRESENT.value,
                           api.SMP_SECURE_SET.NOSECURE.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.BLE_SMP,
                                     api.SMP_CMD_ID.CONFIG,
                                     config],
                          EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                     api.Layer_ID.BLE_SMP,
                                     api.SMP_CMD_ID.CONFIG]):
            return True
        else:
            return False

    def mmi146(self,descript):
        logger.info(''.join(['\n', descript,'\n']))

        config = b''.join([api.SMP_IoCapability.KEYBOARDDISPLAY.value,
                           api.SMP_AuthReqFlag.BONDSECCNT.value,
                           api.SMP_OOB.PRESENT.value,
                           api.SMP_SECURE_SET.NOSECURE.value])

        if self.CommandRW(COMMAND = [api.Layer_ID.BLE_SMP,
                                     api.SMP_CMD_ID.CONFIG,
                                     config],
                          EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                     api.Layer_ID.BLE_SMP,
                                     api.SMP_CMD_ID.CONFIG]):
            return True
        else:
            return False

    def mmi147(self, descript):
        logger.info(''.join(['\n', descript,'\n']))
        if self.oob_confirm:
            return self.oob_confirm

        oob_data =  self.CommandRW(COMMAND = [api.Layer_ID.BLE_SMP,
                                              api.SMP_CMD_ID.GEN_OOB_DATA,
                                              b''],
                                   EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                              api.Layer_ID.BLE_SMP,
                                              api.SMP_CMD_ID.GEN_OOB_DATA],
                                   back    = True)

        if not oob_data:
            return False

        self.oob_confirm = oob_data[5:21].hex().upper().encode()
        self.oob_random  = oob_data[21:].hex().upper().encode()

        return self.oob_confirm

    def mmi148(self, descript):
        logger.info(f'\n{descript}\n')

        if self.oob_random:
            return self.oob_random

        oob_data =  self.CommandRW(COMMAND = [api.Layer_ID.BLE_SMP,
                                              api.SMP_CMD_ID.GEN_OOB_DATA,
                                              b''],
                                   EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                              api.Layer_ID.BLE_SMP,
                                              api.SMP_CMD_ID.GEN_OOB_DATA],
                                   back    = True)

        if not oob_data:
            return False

        self.oob_confirm = oob_data[5:21].hex().upper().encode()
        self.oob_random  = oob_data[21:].hex().upper().encode()

        return self.oob_random

    def mmi149(self, descript):
        logger.info(f'\n{descript}\n')

        index = [i for i,v in enumerate(descript) if v == '[' or v == ']']

        if len(index) != 4:
            logger.error('could not parser oob data')
            return False

        oob_comfirm = bytes.fromhex(descript[index[0]+1:index[1]])
        oob_random   = bytes.fromhex(descript[index[2]+1:index[3]])

        oob_data = b''.join([oob_comfirm,oob_random])

        if self.CommandRW(COMMAND = [api.Layer_ID.BLE_SMP,
                                     api.SMP_CMD_ID.SET_LESC_OOB_DATA,
                                     oob_data],
                          EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                     api.Layer_ID.BLE_SMP,
                                     api.SMP_CMD_ID.SET_LESC_OOB_DATA]):
            return True
        else:
            return False

    def mmi154(self,descript):
        logger.info(''.join(['\n', descript,'\n']))
        self.wait = 18
        return [True,'mmi']

    def mmi155(self,descript):
        logger.info(''.join(['\n', descript,'\n']))
        return True

class SPP(Common):
    def __init__(self,comport,profile,casename,ptsaddress_b,ixit,bleonly):
        Common.__init__(self,comport,profile,casename,ptsaddress_b,ixit,bleonly)
        self.id       = b'\x00'
        self.conninfo = None

    def mmi(self,descript):
        return

    def mmi1(self,descript):
        logger.info(''.join(['\n', descript,'\n']))

        conninfo = self.create_connection('BT')

        if not conninfo:
            return False

        self.conninfo = conninfo

        time.sleep(1)

        if self.CommandRW(COMMAND = [api.Layer_ID.SPP,
                                     api.SPP_CMD_ID.INITIATOR_CONNECT_REQ,
                                     self.conninfo['connhandle']],
                          EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                     api.Layer_ID.SPP,
                                     api.SPP_CMD_ID.INITIATOR_CONNECT_REQ]):
            return
        else:
            return False

    def mmi2(self,descript):
        logger.info(''.join(['\n', descript,'\n']))

        if self.CommandRW(COMMAND = [api.Layer_ID.RFCOMM,
                                     api.RFCOMM_CMD_ID.SEND_DISC_DLC,
                                     self.id],
                          EVENT   = [api.Layer_ID.EVENT_COMMAND_COMPLETE,
                                     api.Layer_ID.RFCOMM,
                                     api.RFCOMM_CMD_ID.SEND_DISC_DLC]):
            return
        else:
            return False

    def mmi3(self,descript):
        logger.info(''.join(['\n', descript,'\n']))
        return True

    def mmi4(self,descript):
        logger.info(''.join(['\n', descript,'\n']))
        return True