import argparse
import os
import multiprocessing
import hashlib
import threading
from concurrent.futures import ThreadPoolExecutor

if __name__ == '__main__':

    print('''
 _               _     _____
| |             | |   /  ___|
| |__   __ _ ___| |__ \ `--.  ___ __ _ _ __  _ __   ___ _ __
| '_ \ / _` / __| '_ \ `--. \/ __/ _` | '_ \| '_ \ / _ \ '__|
| | | | (_| \__ \ | | /\__/ / (_| (_| | | | | | | |  __/ |
|_| |_|\__,_|___/_| |_\____/ \___\__,_|_| |_|_| |_|\___|_|

''')

    parser = argparse.ArgumentParser(description='Hash Scanner')

    #Creating mutuallu exclusive group
    page_group = parser.add_mutually_exclusive_group(required=False)
    page_group.add_argument('-p', '--path', help='Specify the path of the file')
    page_group.add_argument('-d', '--dir', help='Specify the folder')

    parser.add_argument('-md5', action='store_true', help='scan md5')
    parser.add_argument('-sha1', action='store_true', help='scan sha1')
    parser.add_argument('-sha224', action='store_true', help='scan sha224')
    parser.add_argument('-sha256', action='store_true', help='scan sha256')
    parser.add_argument('-sha512', action='store_true', help='scan sha512')

    parser.add_argument('-op', help='output path of the file', required=True)
    parser.add_argument('-a', '--all', action='store_true', help='perform all scans')
    parser.add_argument('-x', '--exclude', type=str, help='which scans to exclude')
    parser.add_argument('-j', '--json', action='store_true', help='output the file in json')
    parser.add_argument('-c', '--csv', action='store_true', help='output the file in csv')
    parser.add_argument('-t', '--txt', action='store_true', help='output the file in text format')
    parser.add_argument('-ds', '--deep_scan', action='store_true', help='whether to scan the files in the subfolder or not')

    args = parser.parse_args()

    LIST_OF_SCANS = []

    if not args.all:
        if args.md5:
            LIST_OF_SCANS.append('md5')
        if args.sha1:
            LIST_OF_SCANS.append('sha1')
        if args.sha224:
            LIST_OF_SCANS.append('sha224')
        if args.sha256:
            LIST_OF_SCANS.append('sha256')
        if args.sha512:
            LIST_OF_SCANS.append('sha512')
    else:
        LIST_OF_SCANS = ['md5', 'sha1', 'sha224', 'sha256', 'sha512']

    if args.exclude:
        to_ignore = [mode for mode in (args.exclude).split(' ')]
        try:
            for mode in to_ignore:
                LIST_OF_SCANS.remove(mode)
        except:
            pass

    #print(LIST_OF_SCANS)

    if args.path:
        FILE_PATH = args.path
    elif args.dir:
        FILE_PATH = args.dir
    else:
        FILE_PATH = os.getcwd()

    #print(FILE_PATH)

    output_path = args.op

    #print('Output path -> ',output_path)

    exports_list = []

    if args.json:
        exports_list.append('json')
    if args.csv:
        exports_list.append('csv')
    if args.txt:
        exports_list.append('txt')

    if args.deep_scan:
        deep_scan = True
    else:
        deep_scan = False

    #print(exports_list)

    if len(LIST_OF_SCANS) == 0:
        print('Please enter a scan mode...')

###****Argument Parsed****####

"""Passing values : 1. LIST_OF_SCANS
                    2. deep_scan
                    3. exports_list
                    4. output_path
                    5. FILE_PATH """

###*** Scanner class ***####

class Scanner(object):

    def __init__(self, list_scans, deep_scan=False, exports_list=None, output_path=None, file_path=None):
        self.list_scans = list_scans
        self.deep_scan = deep_scan
        self.exports_list = exports_list
        self.output_path = output_path
        self.file_path = file_path
        self.file_list = []
        self.main_dict = {}
        self.main_list = []

    def extractBytes(self, file_path):
        #print('Extracting')
        with open(file_path) as file:
            file_bytes = file.read()
            file_bytes = file_bytes.encode()

        return file_bytes

    def scanDirectory(self):
        file_path = self.file_path
        if file_path:
            for root, dirs, files in os.walk(file_path):
                if files:
                    for file in files:
                        temp_path = os.path.join(root, file)
                        self.file_list.append(temp_path)

    def startEngine(self):
        #number of process to start for the scan
        m = multiprocessing.Manager()
        sharedList = m.list()

        processes = []

        for mode in self.list_scans:
            myProcess = multiprocessing.Process(target=self.modeScan, args=(mode, sharedList))
            myProcess.start()
            processes.append(myProcess)

        for process in processes:
            process.join()

    def modeScan(self, mode, sharedList):

        # threads = []
        #
        # for dir in self.file_list:
        #     thread = threading.Thread(target=self.scanFile, args=(dir, mode, sharedList))
        #     thread.start()
        #     threads.append(thread)
        #
        # for thread in threads:
        #     thread.join()

        mode_list = []
        mode_list.append(mode)

        # print(mode_list)

        with ThreadPoolExecutor(max_workers=20) as executor:
                executor.map(self.scanFile, self.file_list, mode_list * len(self.file_list))

    def scanFile(self, dir, mode):
        # print(threading.current_thread())
        # print(mode)
        #print(dir)
        bytes = self.extractBytes(dir)
        #print(bytes)
        temp_dict = {dir : eval('hashlib.{}(bytes)'.format(mode)).hexdigest()}
        print(temp_dict)
        #sharedList.append(temp_dict)
        #print(sharedList)
        #self.main_list = sharedList

    def printResult(self):
        for item in self.main_list:
            print(item)

obj = Scanner(list_scans=LIST_OF_SCANS, file_path=FILE_PATH)
obj.scanDirectory()
obj.startEngine()
obj.printResult()
