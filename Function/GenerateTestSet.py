import os
import sys
import json
import shutil
import traceback
from PtsFileConverter import PtsFileConverter

if __name__ == '__main__':
    try:
        project_dir = os.path.abspath('..')
        ptsconfig = PtsFileConverter(project_dir)

        # region generate new pts config file
        if os.path.isdir(ptsconfig.directory):
            shutil.rmtree(ptsconfig.directory)
        if not os.path.isdir(ptsconfig.directory):
            os.mkdir(ptsconfig.directory)
        # os.mkdir(os.path.join(project_dir,'ProfilesConfigs'))
        shutil.copy(ptsconfig.pts_new_file, ptsconfig.directory)
        ptsconfig.CreateConfigJsonFile()
        # endregion

        if os.path.isfile(os.path.join(project_dir,'TestSet.json')):
            os.rename(os.path.join(project_dir,'TestSet.json'),
                      os.path.join(project_dir,'TestSet_old.json'))

        set_old = json.load(open(os.path.join(project_dir,'TestSet_old.json'),'r'))
        # set_new = json.load(open(os.path.join(project_dir,'TestSet.json'),'w+'))
        Comport = set_old['Comport']
        BleOnly = set_old['BleOnly']
        Capture = set_old['Capture_Uart']
        Profile = set_old['Profile']

        # region Profiles object
        A2DP    = set_old['A2DP']
        AVCTP   = set_old['AVCTP']
        AVDTP   = set_old['AVDTP']
        AVRCP   = set_old['AVRCP']
        GAP     = set_old['GAP']
        GATT    = set_old['GATT']
        GAVDP   = set_old['GAVDP']
        HFP     = set_old['HFP']
        HSP     = set_old['HSP']
        L2CAP   = set_old['L2CAP']
        PBAP    = set_old['PBAP']
        RFCOMM  = set_old['RFCOMM']
        SDP     = set_old['SDP']
        SM      = set_old['SM']
        SPP     = set_old['SPP']
        #endregion

        for jfile in os.listdir(os.path.join(project_dir,'ProfilesConfigs')):
            if '.json' in jfile:
                profilename = jfile.replace('.json', '').upper()
                data = json.load(open(os.path.join(ptsconfig.directory, jfile), 'r'))
                if profilename == 'A2DP':
                    A2DP = data['ixit']
                if profilename == 'AVCTP':
                    AVCTP = data['ixit']
                if profilename == 'AVDTP':
                    AVDTP = data['ixit']
                if profilename == 'AVRCP':
                    AVRCP = data['ixit']
                if profilename == 'GAP':
                    GAP = data['ixit']
                if profilename == 'GATT':
                    GATT = data['ixit']
                if profilename == 'GAVDP':
                    GAVDP = data['ixit']
                if profilename == 'HFP':
                    HFP = data['ixit']
                if profilename == 'HSP':
                    HSP = data['ixit']
                if profilename == 'L2CAP':
                    L2CAP = data['ixit']
                if profilename == 'PBAP':
                    PBAP = data['ixit']
                if profilename == 'RFCOMM':
                    RFCOMM = data['ixit']
                if profilename == 'SDP':
                    SDP = data['ixit']
                if profilename == 'SM':
                    SM = data['ixit']
                if profilename == 'SPP':
                    SPP = data['ixit']

        with open(os.path.join(project_dir,'TestSet.json'),'a+') as outfile:
            json.dump({'Comport'     : Comport,
                       'BleOnly'     : BleOnly,
                       'Capture_Uart': Capture,
                       'Profile'     : Profile,
                       'A2DP'        : A2DP,
                       'AVCTP'       : AVCTP,
                       'AVDTP'       : AVDTP,
                       'AVRCP'       : AVRCP,
                       'GAP'         : GAP,
                       'GATT'        : GATT,
                       'GAVDP'       : GAVDP,
                       'HFP'         : HFP,
                       'HSP'         : HSP,
                       'L2CAP'       : L2CAP,
                       'PBAP'        : PBAP,
                       'RFCOMM'      : RFCOMM,
                       'SDP'         : SDP,
                       'SM'          : SM,
                       'SPP'         : SPP},
                      outfile, indent = 4)

        outfile.close()

    except:
        cl, exc, tb = sys.exc_info()
        for lastCallStack in traceback.extract_tb(tb):
            errMessage =''.join(['\n######################## Error Message #############################\n'
                                 '    Error class        : {}\n'.format(cl),
                                 '    Error info         : {}\n'.format(exc),
                                 '    Error fileName     : {}\n'.format(lastCallStack[0]),
                                 '    Error fileLine     : {}\n'.format(lastCallStack[1]),
                                 '    Error fileFunction : {}'.format(lastCallStack[2])])
            print(errMessage)