import os
import sys
import logging
import codecs
from lxml import etree
from os.path import join, dirname
import collections

class etsAssetProvider:
    def __init__(self, pts_dir, ets_name):

        self.log      = logging.getLogger("Logger")
        self.pts_dir  = pts_dir
        self.ets_name = ets_name
        
        self.__init()

    #############################################################
    #############################################################
    def getIcsAsset(self):
        return self.ets_ics

    #############################################################
    #############################################################
    def getIxitAsset(self):
        return self.ets_ixit

    #############################################################
    #############################################################
    def getTcAsset(self):
        return self.ets_tc

    #############################################################
    #############################################################
    
    def __init(self):
        
        locations = []
        locations.append(os.path.join(self.pts_dir, 'Bluetooth\Ets'))
        locations.append(os.path.join(self.pts_dir, 'Bluetooth\PICSX'))
        locations.append(os.path.join(self.pts_dir, 'Bluetooth\PIXITX'))

        self.ets_db_file_info = collections.OrderedDict()
        for location in locations:
            for file in os.listdir(location):
                fileinfo = os.path.splitext(file)
                if fileinfo[0] == self.ets_name:
                    self.ets_db_file_info[fileinfo[1][1:].lower()] = os.path.join(location, file)
        
        self.__construct_tc()
        self.__construct_ics()
        self.__construct_ixit()

    #############################################################
    #############################################################

    def __construct_tc(self):
        self.ets_tc = collections.OrderedDict()
        fp = codecs.open(self.ets_db_file_info['xml'], 'r', 'UTF-8') #open(self.ets_db_file_info['xml'])
        tree = etree.parse(fp)
        for el in tree.findall('//TestCase'):
            name      = el.attrib['Name']
            if 'Description' in el.attrib:
                desc = el.attrib['Description']
            else:
                desc = ''
            if 'Mapping' in el.attrib:
                mapping = el.attrib['Mapping']    
            else:
                mapping = ''  
            reference = el.attrib['Reference']
            if not name.endswith('_HELPER'):
                self.ets_tc[name] = { 'desc' : desc, 'mapping' : mapping, 'reference': reference}

    #############################################################
    #############################################################

    def __construct_ics(self):
        self.ets_ics = collections.OrderedDict()
        fp = codecs.open(self.ets_db_file_info['picsx'], 'r', 'UTF-8') #fp = open(self.ets_db_file_info['picsx'])
        tree = etree.parse(fp)
        for el in tree.findall('//Row'):
            name  = el.findtext('Name',        default = 'None')
            desc  = el.findtext('Description', default = 'None')
            value = el.findtext('Value',       default = 'None')    
            mand  = el.findtext('Mandatory',   default = 'None')    
            self.ets_ics[name] = { 'desc' : desc, 'value' : value, 'mand': mand}

    #############################################################
    #############################################################

    def __construct_ixit(self):
        self.ets_ixit = collections.OrderedDict()
        fp = codecs.open(self.ets_db_file_info['pixitx'], 'r', 'UTF-8') #fp = open(self.ets_db_file_info['pixitx'])
        tree = etree.parse(fp)
        for el in tree.findall('//Row'):
            name   = el.findtext('Name',        default = 'None')
            desc   = el.findtext('Description', default = 'None')
            value  = el.findtext('Value',       default = 'None')    
            elType = el.findtext('Type',        default = 'None')    
            self.ets_ixit[name] = { 'desc' : desc, 'value' : value, 'type': elType}
