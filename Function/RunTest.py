import os
import sys
import time
import logging
import importlib
from Setting import Setting
from PtsFunction import PtsFunction

# region Set Looger
logger = logging.getLogger(os.path.basename(__file__))
logger.setLevel(logging.INFO)
DisplayHandle = logging.StreamHandler()
DisplayHandle.setLevel(logging.INFO)
formatter = logging.Formatter("[%(name)s][%(levelname)s]".ljust(30) + '%(message)s')
DisplayHandle.setFormatter(formatter)
logger.addHandler(DisplayHandle)
if os.path.isdir(os.path.join(os.getcwd(),'WorkDirectory')):
    Writeformatter = logging.Formatter("[%(name)s][%(levelname)s]".ljust(30) + '%(message)s')
    WriteHandle = logging.FileHandler(os.path.join(os.getcwd(),'WorkDirectory','Daily.log'))
    WriteHandle.setLevel(logging.DEBUG)
    WriteHandle.setFormatter(Writeformatter)
    logger.addHandler(WriteHandle)
# endregion

if __name__ == '__main__':
    # region confirm input parameter numbers
    if len(sys.argv) != 7:
        logger.error('''
                        the input parameter numbers not right
                        please check the parameter numbers match 
                        python "RunTestpy",
                               "TestSet.json file path",
                               "work diretory"
                               "test case log folder",
                               "profile name of upper",
                               "test case name",
                      ''')
        sys.exit(1)

    testset_file      = sys.argv[1]
    work_dir          = sys.argv[2]
    config_path       = sys.argv[3]
    caselog_dir       = sys.argv[4]
    profile           = sys.argv[5]
    testcase          = sys.argv[6]

    if not os.path.exists(testset_file):
        logger.error(f'{testset_file} not found , please check input parameter')
        sys.exit(1)
    # endregion

    # region generate PTS test config
    testset     = Setting(testset_file)
    bleonly     = testset.bleonly()
    DutCom      = testset.ComportSet()

    Config = testset.GenConfigs(profile, config_path)
    if Config == False:
        logger.error(f'{profile} config ics / ixit error')
        sys.exit(1)

    ics = Config[0]
    ixit = Config[1]
    # endregion

    pts = PtsFunction(profile, ics, ixit)

    os.chdir(work_dir)

    pts_address_b = pts.getPtsAddress()

    if not pts.SetIcsIxitParemeter(pts_address_b):
        logger.error(f'PTS Set {profile} ICS/IXIT Prepare Failure ..')
        sys.exit()

    if not pts.InitStackETS(pts_address_b, work_dir):
        logger.error(f'PTS Init {profile} Stack/ETS Failure ...')
        sys.exit()

    mmi_operate = getattr(importlib.import_module('MmiOperate'),profile)(DutCom,
                                                                         profile,
                                                                         testcase,
                                                                         pts_address_b,
                                                                         ixit,
                                                                         bleonly)

    if not mmi_operate.iut_initial(bleonly):
        logger.error('... iut initial failure , please check iut status...')
        sys.exit()

    result = pts.runtest(mmi_operate, caselog_dir)

    time.sleep(1)

    logger.info(f"***  Test case {testcase} : {result}    ***")
    print('\n\n')
    time.sleep(1)

    pts.UnInitStackETS()
    pts.unloadDLL()

    if result != "PASS":
        if result == 'FAIL':
            sys.exit(2)
        elif result == 'INCONC':
            sys.exit(3)
        elif result == 'INCOMP':
            sys.exit(4)
        elif result == 'NONE':
            sys.exit(5)
