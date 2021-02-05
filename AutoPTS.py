import os
import sys
import time
import json
import shutil
import logging
import traceback
import subprocess
from Function.Setting import Setting
from Function.PtsFileConverter import PtsFileConverter

# region set Looger
logger = logging.getLogger(os.path.basename(__file__))
logger.setLevel(logging.INFO)
DisplayHandle = logging.StreamHandler()
DisplayHandle.setLevel(logging.INFO)
formatter = logging.Formatter("[%(name)s][%(levelname)s]%(asctime)s %(message)s")
DisplayHandle.setFormatter(formatter)
logger.addHandler(DisplayHandle)
if os.path.isdir(os.path.join(os.getcwd(),'WorkDirectory')):
    Writeformatter = logging.Formatter(('*'*30) + " %(asctime)s "+ ('*'*30) + '\n'
                                        + "[%(name)s][%(levelname)s]".ljust(40) + "%(message)s")
    WriteHandle = logging.FileHandler(os.path.join(os.getcwd(),'WorkDirectory','Daily.log'))
    WriteHandle.setLevel(logging.DEBUG)
    WriteHandle.setFormatter(Writeformatter)
    logger.addHandler(WriteHandle)
# endregion

if __name__ == '__main__':
    try:
        logger.info('*** Start AutoPTS Test ***')

        project_dir = os.getcwd()
        report_dir  = os.path.join(project_dir,'WorkDirectory','Report')

        if not os.path.isdir(report_dir):
            os.mkdir(report_dir)

        # region base on pics file to generate new pts config
        ptsconfig = PtsFileConverter(project_dir)
        if not ptsconfig.PicsFilesCompare():
            logger.info('Start generste new  PTS config')
            if os.path.isdir(ptsconfig.directory):
                shutil.rmtree(ptsconfig.directory)

            if not os.path.isdir(ptsconfig.directory):
                os.mkdir(ptsconfig.directory)

            shutil.copy(ptsconfig.pts_new_file, ptsconfig.directory)

            if ptsconfig.CreateConfigJsonFile():
                logger.info('PTS config generate successfully')
        # endregion

        # region gererate test profiles and test case
        testcases = dict()

        # all profiles test case form pts config file to 'testcases' this dict
        for jfile in os.listdir(ptsconfig.directory):
            if '.json' in jfile:
                profilename = jfile.replace('.json', '').upper()
                data = json.load(open(os.path.join(ptsconfig.directory, jfile), 'r'))
                testcases[profilename] = data['tc']

        # if has input case define file , replace test case from input file
        if len(sys.argv) == 2:
            if os.path.isfile(sys.argv[1]):
                testcases = json.load(open(sys.argv[1], 'r'))
            else:
                logger.error(f"{sys.argv[1]} not found , please files location ..")
        # endregion

        # region create test summary log file
        summary_file_path     = os.path.join(report_dir,time.strftime('%Y_%m_%d_%H_%M_%S_Report.txt'))
        summary_log = open(summary_file_path,'w')
        summary_log.write(f"{'*'*35}{time.strftime('     %Y_%m_%d_%H_%M_%S     ')}Start AutoPTS Test     {'*'*35}\n")
        summary_log.write(f"{'Profile Name'.ljust(30)}{'Test Start Time'.center(22)}"
                          f"{'Test Case Name'.center(78)}Result\n")
        summary_log.close()
        # endregion

        # region setup test environment
        # all pts log or data save in this folder
        work_dir = os.path.join(project_dir,'WorkDirectory')
        if not os.path.isdir(work_dir):
            os.mkdir(work_dir)

        config_path  = os.path.join(project_dir, 'ProfilesConfigs')
        testset_file = os.path.join(project_dir, 'TestSet.json')

        if not os.path.isdir(config_path):
            logger.error(f'{config_path} not found , please check PTS Config files is exists')

        if not os.path.exists(testset_file):
            logger.error(f'{testset_file} not found , please check TestSet.json is exists')
            sys.exit()

        testset      = Setting(testset_file)
        profiles     = testset.testProfile()
        cature       = testset.captureUart()

        # endregion

        for profile in profiles.keys():
            PROFILE = profile.upper()

            if PROFILE not in testcases:
                summary_log = open(summary_file_path, 'a+')
                summary_log.write(f'{PROFILE} not in profiles list , please check case define\n')
                summary_log.close()
                logger.error(f'{PROFILE} not in profiles list , please check case define')
                continue

            logger.info(f" *** start {PROFILE} test *** \n")

            # each profile protocol view log file will save in this folder
            profileDir = f"{time.strftime('%Y_%m_%d_%H_%M_%S')}_{PROFILE}"
            ProfileLogDir = os.path.join(work_dir, profileDir)
            if not os.path.isdir(ProfileLogDir):
                os.mkdir(ProfileLogDir)

            for runtimes in range(profiles[PROFILE]):
                for testcase in testcases[PROFILE]:
                    logger.info(f" *** test case {testcase} *** \n")

                    # region prepare run test script and parameter
                    case_dir_name = (f"{testcase.replace('/', '_').replace('-', '_')}_"
                                     f"{time.strftime('%Y_%m_%d_%H_%M_%S')}")

                    caselog_dir = os.path.join(ProfileLogDir, case_dir_name)
                    if not os.path.isdir(caselog_dir):
                        os.mkdir(caselog_dir)

                    RunTest = os.path.join(project_dir,'Function','RunTest.py')
                    if not os.path.exists:
                        logger.error(f'{RunTest} python script file not found , please check RunTest.py files path')
                        sys.exit()

                    runtest_argv = ['python', RunTest,
                                              testset_file,
                                              work_dir,
                                              config_path,
                                              caselog_dir,
                                              PROFILE,
                                              testcase]
                    # endregion

                    for bout in range(3):
                        runtest = subprocess.run(runtest_argv,capture_output=cature)

                        if runtest.returncode == 0:
                            summary_log = open(summary_file_path, 'a+')
                            summary_log.write(f"{profile.center(10)}"
                                              f"{time.strftime('%Y_%m_%d_%H_%M_%S').center(65)}"
                                              f"{testcase.ljust(30)}"
                                              f"{'PASS'.center(35)}\n")

                            summary_log.close()

                            if cature:
                                print('\n')
                                logger.info(runtest.stdout.decode())
                                logger.info(runtest.stderr.decode())

                                uart_log = open(os.path.join(caselog_dir,case_dir_name+'.txt'),'w')
                                uart_log.write(runtest.stdout.decode())
                                uart_log.write(runtest.stderr.decode())
                                uart_log.close()

                            break

                        elif runtest.returncode != 0 and bout < 2:
                            shutil.rmtree(caselog_dir)
                            os.mkdir(caselog_dir)

                            print('\n')
                            logger.error(f"***  Test case {testcase} : retest ...{bout + 1}  ***")
                            print('\n')

                        else:
                            result = ''
                            if runtest.returncode == 2:
                                result = 'FAIL'

                            if runtest.returncode == 3:
                                result = 'INCONC'

                            if runtest.returncode == 4:
                                result = 'INCOMP'

                            if runtest.returncode == 5:
                                result = 'NONE'

                            summary_log = open(summary_file_path, 'a+')
                            summary_log.write(f"{profile.center(10)}"
                                              f"{time.strftime('%Y_%m_%d_%H_%M_%S').center(65)}"
                                              f"{testcase.ljust(30)}"
                                              f"{result.center(35)}\n")

                            summary_log.close()

                            if cature:
                                print('\n')
                                logger.info(runtest.stdout.decode())
                                logger.info(runtest.stderr.decode())

                                uart_log = open(os.path.join(caselog_dir,case_dir_name+'.txt'),'w')
                                uart_log.write(runtest.stdout.decode())
                                uart_log.write(runtest.stderr.decode())
                                uart_log.close()

                    logger.info(f" *** test case {testcase} end *** \n")

            logger.info(f" *** {PROFILE} test end *** \n")

    except KeyboardInterrupt:
        logger.error('user stop')

    except:
        cl, exc, tb = sys.exc_info()
        for lastCallStack in traceback.extract_tb(tb):
            errMessage = (f'\n######################## Error Message #############################\n'
                          f'    Error class        : {cl}\n'
                          f'    Error info         : {exc}\n'
                          f'    Error fileName     : {lastCallStack[0]}\n'
                          f'    Error fileLine     : {lastCallStack[1]}\n'
                          f'    Error fileFunction : {lastCallStack[2]}')
            logger.error(errMessage)