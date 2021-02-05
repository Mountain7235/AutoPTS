import os
import sys
import traceback
from PtsFileConverter import PtsFileConverter

if __name__ == '__main__':
    try:
        if len(sys.argv) != 2:
            print('No any pics file ..\n'
                  'please follow the command flow as below\n'
                  'python ..\GeneratePtsConfig ..\picsfile.pts ')
            sys.exit()

        if not os.path.isfile(sys.argv[1]):
            print('\n*** {0} not found'.format(sys.argv[1]),
                  'please comfirm the pics file location ***\n')
            sys.exit()

        project_folder = os.path.abspath('..')


        pics_file = os.path.join(project_folder,sys.argv[1])
        ptsconfig = PtsFileConverter(project_folder,pics_file)
        if ptsconfig.CreateConfigJsonFile():
            print('PTS config generate successfully')

    except:
        cl, exc, tb = sys.exc_info()
        for lastCallStack in traceback.extract_tb(tb):
            errMessage = f'\n######################## Error Message #############################\n' \
                         f'    Error class        : {cl}\n' \
                         f'    Error info         : {exc}\n' \
                         f'    Error fileName     : {lastCallStack[0]}\n' \
                         f'    Error fileLine     : {lastCallStack[1]}\n' \
                         f'    Error fileFunction : {lastCallStack[2]}'
            print(errMessage)