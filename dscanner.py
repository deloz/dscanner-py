#! /usr/bin/env python
#coding=utf-8
# Filename: dscanner.py

import os
import sys
import time
import threading

version = '0.0.01'
lock = threading.Lock()

def run():    
    print r'''
        Scanner files for checking if they contain virus...
        '''
    while True:
        scan_path = raw_input(r'Select a local path: ')
        if not os.path.exists(scan_path):
            print r'wrong type, eg: f:\www\tool\  /home/www/tool, try again.'
            print
            continue
        break
    while True:
        try:
            max_depth = int(raw_input(r'input MAX depth that will be scan: '))
        except BaseException:
            print r'wrong type. number please, try agin.'
            print
            continue
        break
    
    while True:
        try:
            file_type = int(raw_input(r'select file type to scan:(1-> php  2->asx 3->jpg 4->gif_bmp 5->txt) '))
            if not file_type in range(1, 6):
                print r'select a number between 1-5 please, try again.'
                print
                continue
            file_types = {1: 'php', 2: 'asx', 3: 'jpg', 4: 'gif_bmp', 5: 'txt'}
            file_type = file_types[file_type]
            break
        except BaseException:
            print r'valid number'
            break
    while True:
        try:
            debug = int(raw_input(r'do you need debug(1 or 0): '))
            if debug not in [1, 0]:
                print r'the value could be 1 or 0, please select.'
                print
                continue
            break
        except BaseException:
            print r'wrong type. 1 or 0 please, try agin.'
            print
            continue
        break
    print r'now Input OK, beginning...'
    print r':::::FILE SCAN START::::::'
    print
    print r'MAX_DEPTH: %s  DEBUG: %s  ' % (max_depth, debug)
    print r'scanning: %s' % (scan_path)
    
    log_file = os.path.join(os.getcwd(), r'logs')
    mkdir(log_file)
    log_file = os.path.join(log_file, time.strftime('%Y-%m-%d') + r'-log.txt')
    print r'Log File: %s' % (log_file)

    file_list = scan(scan_path, file_type, max_depth, log_file, debug);    
    print
    print r':::::FILE SCAN END::::::::'
#    runThread(file_list, log_file)
    checkVirus(file_list, log_file)
    
def scan(scan_path, file_type, max_depth, log_file, debug = True):
    '''Scan a local path.

    the path MUST be a local path,can not be remote.'''
    
    file_list = list()
    file_types = getScanFileTypes(file_type)
    for cur_path, sub_folders, files in os.walk(scan_path, topdown = True):
        for file_name in files:
            scan_file = os.path.join(cur_path, file_name)
            if not any(scan_file.endswith(x) for x in file_types):
                continue
            file_list.append(scan_file)
            print 'scan_file: %s' % scan_file
        current_depth = os.path.join(cur_path).count(os.sep)            
        print 'current depth: %s' % current_depth
#        if max_depth < current_depth:
#            break
    return file_list

def getScanFileTypes(file_type):
    file_types = {'php': ['php', 'inc', 'phtml'],
                  'asx': ['asp', 'asa', 'cer', 'aspx', 'ascx'],
                  'jpg': ['jpg', 'jpeg'],
                  'gif_bmp': ['bmp', 'gif', 'png'],
                  'txt': ['txt']}
    if file_types.has_key(file_type):
        return file_types[file_type]
    else:
        return False

def runThread(file_list, log_file):
    '''more threads

    use multil threads'''
    thread_list = list()
    for i in range(0, 20):
        thread_name = 'thread_%s' % (i)
        thread_list.append(threading.Thread(
            target = checkVirus,
            args = (file_list, log_file),
            name = thread_name))
        
    for thread in thread_list:
        thread.start()
    for thread in thread_list:
        thread.join()
        
def checkVirus(file_list, log_file):
    '''check if a file contains the feature virus

    need virus featrues, check and write to a log file that name like 2013-04-28-log, save at current directory "logs" '''
    
    virus_features = {'base64_decode': 'base64 加密', 'UDF提权2': 'c:\\windows\\system32', '一句话特征50': 'php://input'}
#    global lock
#    lock.acquire()
    for scan_file in file_list:
        with open(log_file, 'a') as log:
            
            with open(scan_file, 'r') as check_file:
                file_content = check_file.read()

                for feature, virus in virus_features.iteritems():
                    if feature in file_content:
                        print 'File: %s    - virus: %s' % (scan_file, virus)
                        log.write(r'%s %s %s %s %s' % (time.strftime('%Y-%m-%d %H:%M:%S'),
                                                time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(os.path.getmtime(scan_file))),
                                                scan_file,
                                                virus,
                                                os.linesep))
                        print
    #lock.release()            
    
def mkdir(path):
    if not os.path.exists(path):
        return os.mkdir(path)
    return False

def show_error(msg):
    print
    print r'Error: %s' % (msg)
    print

if __name__ == '__main__':
    run()
else:
    print 'dscanner.py can not be wrapped...'
