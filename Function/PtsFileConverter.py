import sys
import json
import os
import re
import shutil
from antlr4 import *
from xml.etree.ElementTree import *

if 'Function' in os.getcwd():
    from etsAssetProvider import etsAssetProvider
    from antlr4.InputStream import InputStream
    from antlrParser.AntlrGrammerLexer import AntlrGrammerLexer
    from antlrParser.AntlrGrammerParser import AntlrGrammerParser
    from antlrParser.AbstractTreeVisitor import AbstractTreeVisitor
else:
    from .etsAssetProvider import etsAssetProvider
    from antlr4.InputStream import InputStream
    from .antlrParser.AntlrGrammerLexer import AntlrGrammerLexer
    from .antlrParser.AntlrGrammerParser import AntlrGrammerParser
    from .antlrParser.AbstractTreeVisitor import AbstractTreeVisitor

class PtsFileConverter:

    ############################################################   
    ############################################################
    def __init__(self,projectdir,specific_pics = None):
        self.directory    = os.path.join(projectdir,'ProfilesConfigs') # Mountain add
        self.pts_new_file = os.path.join(projectdir,'pics.pts')        # Mountain add
        self.pts_file     = os.path.join(self.directory,'pics.pts')    # Mountain add
        self.pts_dir      = "C:\\Program Files (x86)\\Bluetooth SIG\\Bluetooth PTS\\bin"
        self.etsName      = ''
        self.icsDic       = {}
        self.ixitDic      = {}
        self.tcs          = []

        if not os.path.isdir(self.directory):
            os.mkdir(self.directory)

        if specific_pics:
            self.pts_file = specific_pics
            shutil.copy(specific_pics, self.directory)

    ####################################################
    ####################################################
    def CreatePicsTable(self, elementsTree):
        ics = []
        etsName = self.etsName
        if (etsName == 'HCRP'):
            etsName = 'HCRP12'
        for item in elementsTree:
            table = item.find('table').text
            row = item.find('row').text
            ics.append(("TSPC_" + etsName + '_' + table + '_' + row).upper())
        return ics

    ####################################################
    ####################################################
    def GetAssets(self, profile):
        icsTable = profile.findall('item')
        icsSupported = self.CreatePicsTable(icsTable)
        ets_assets = etsAssetProvider(self.pts_dir, self.etsName)
        #ICS
        for icsItem in ets_assets.getIcsAsset():
            icsItem = icsItem.upper()
            if icsItem in icsSupported:
                self.icsDic[icsItem] = "TRUE"
            else:
                self.icsDic[icsItem] = "FALSE"
            # Mountain edit : add not etsName but need check other profile ics
            if self.etsName not in icsItem and 'ALL' not in icsItem:
                sp = re.compile('TSPC_(.*)_(.*)_(.*)')
                pfile,table,row = sp.findall(icsItem)[0]
                pics = open(self.pts_file,'r',encoding = 'utf8')
                for line in pics:
                    if '<name>'+pfile+'</name>' in line:
                        for item in pics:
                            if '</profile>' in item:break
                            elif '<table>'+table+'</table>' in item:
                                for i in pics:
                                    if '</item>' in i:break
                                    elif '<row>'+row+'</row>' in i:
                                        self.icsDic[icsItem] = "TRUE"
                pics.close()

        #IXIT
        ixitAsset = ets_assets.getIxitAsset()
        for ixit_key in ixitAsset:
            ixit_type = ixitAsset[ixit_key]['type']
            ixit_value = ixitAsset[ixit_key]['value']
            self.ixitDic[ixit_key] = ixit_type,ixit_value

        #TC
        tcs = ets_assets.getTcAsset()
        # create a visitor
        visitor = AbstractTreeVisitor(self.icsDic)
        for tcName in tcs:
            mapping = tcs[tcName]['mapping']

            result = self.CheckTcStatus(visitor, mapping)
            if (result == True):
                self.tcs.append(tcName)
         
            
    ####################################################
    ####################################################
    def CheckTcStatus(self, visitor, mapping):
        if visitor is None:
            return False

        input = InputStream(mapping)
        lexer = AntlrGrammerLexer(input)
        stream = CommonTokenStream(lexer)
        parser = AntlrGrammerParser(stream)
        tc_mapping = parser.prog()

        #Use Antlr Parser to check if test case is locked or not
        return visitor.visit(tc_mapping)


    ####################################################
    ####################################################
    def WriteToFile(self):
        if not os.path.exists(self.directory):
            os.makedirs(self.directory)

        with open(os.path.join(self.directory , self.etsName + '.json'), 'w+') as outfile:
            json.dump({"ets":self.etsName, "tc":self.tcs, "ics":self.icsDic, "ixit":self.ixitDic},
            outfile, indent = 4, sort_keys=True)
        outfile.close()

    ####################################################
    ####################################################
    def GetMatchEtsName(self, name):
        etsName = name
        #there are some mismatch in .pts profile name and ets name PTS uses
        if (etsName == 'IOP'):
            etsName = 'IOPT'
        elif (etsName == 'HID 1.1'):
            etsName = 'HID11' 
        elif (etsName == 'SCPP'):
            etsName = 'ScPP' 
        elif (etsName == 'HCI' or etsName == 'SUM ICS' or etsName == 'PROD' or etsName == 'ATT'):
            etsName = ''
        return etsName
        

    ####################################################
    ####################################################
    def CreateConfigJsonFile(self):
        
        tree = parse(self.pts_file).getroot()
        for profiles in tree.findall('pics'):
            for profile in profiles:
                # ETS name supported
                etsName = profile.find('name').text
                self.etsName = self.GetMatchEtsName(etsName)
                if (self.etsName == ''):
                    continue
                self.icsDic = {}
                self.ixitDic = {}
                self.tcs = []
                self.GetAssets(profile)
                self.WriteToFile()

        return True
        
    ####################################################
    ####################################################
    '''Microchip Mountain add Function'''
    def PicsFilesCompare(self):
        if os.path.isfile(self.pts_new_file) and os.path.isfile(self.pts_file):
            news = open(self.pts_new_file,'r',encoding="utf-8")
            olds = open(self.pts_file,'r',encoding="utf-8")
            newfile = [new for new in news]
            oldfile = [old for old in olds]
            if len(newfile) != len(oldfile):
                return False
            else:
                for x in zip(newfile,oldfile):
                    if x[0] != x[1]:
                        return False
            return True
        else:
            print('pics file not exist')
            sys.exit()