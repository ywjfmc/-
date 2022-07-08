import configparser
import os
import sys
import datetime
import feature_list
from matplotlib.backends.backend_pdf import PdfPages


class Config:
    """
        Config has following attributes:
        load_style      : str, file or online
        filename_set    : str, f11&f12&...|f21&f22&...|...，不同批次分析的文件用“|”隔开，同一批次中的文件用“&”隔开。
        is_graph        : bool, True or False
        pdf_file        : opened_PdfPages
        is_text         : bool, True or False
        out_file        : opened_file or sys.stdout
        is_csv          : bool, True or False
        csv_file        : opened_file
        is_tqdm         : bool, True or False
        flow_g          : tuple, (int,int,int,int,int)
        feature_list    : tuple of feature
        process_style   : str, all or slice or window
        div_basis       : str, time or packet
        split_number    : int, >0
        min_flow_length : int, >=0
        wnd_size        : int, >0
        wnd_speed       : int, >0
    """

    def __init__(self, filename):
        conf = configparser.ConfigParser()
        conf.read(filename, encoding='utf-8-sig')
        # 1.数据加载方式
        inputstyle = conf.get('LOADED DATA', 'inputstyle')
        if inputstyle == 'file':
            self.load_style = 'file'
            self.filename_set = conf.get('LOADED DATA', 'filename')
        elif inputstyle == 'directory':
            self.load_style = 'file'
            isautocomb = int(conf.get('LOADED DATA', 'autocombine'))
            directory = conf.get('LOADED DATA', 'directory')
            fileindir = []
            if isautocomb:
                for root, dirs, files in os.walk(directory):
                    autocombdict = {}
                    for f in files:
                        if f.endswith('.pcap') or f.endswith('.cap'):
                            fn_fs = f.rsplit('.', 1)
                            if fn_fs[0].rstrip('0123456789').endswith('_') or fn_fs[0].rstrip('0123456789').endswith(
                                    '-'):
                                try:
                                    autocombdict[fn_fs[0].rstrip('0123456789')].append(root + '\\' + f)
                                except KeyError:
                                    autocombdict[fn_fs[0].rstrip('0123456789')] = [root + '\\' + f]
                            else:
                                fileindir.append(root + '\\' + f)
                    for comb in autocombdict.keys():
                        fileindir.append('&'.join(autocombdict[comb]))
            else:
                for root, dirs, files in os.walk(directory):
                    for f in files:
                        if f.endswith('.pcap') or f.endswith('.cap'):
                            fileindir.append(root + '\\' + f)
            self.filename_set = '|'.join(fileindir)
        else:
            print('wrong INPUT STYLE!')
            exit(1)

        # 2.数据输出方式
        now_dt = datetime.datetime.now()
        now_str = now_dt.ctime().replace(' ', '_').replace(':', '_')

        isgraph = conf.get('OUT STYLE', 'isgraph')
        if isgraph == '0':
            self.is_graph = False
        elif isgraph == '1':
            self.is_graph = True
            outfilename = conf.get('OUT STYLE', 'pdfname')
            if outfilename == '$datetime$':
                try:
                    outfile = PdfPages(r'result\feamatrix_' + now_str + '.pdf')
                except FileNotFoundError:
                    os.mkdir('result')
                    outfile = PdfPages(r'result\feamatrix_' + now_str + '.pdf')
            elif outfilename:
                outfile = PdfPages(outfilename)
            else:
                print('wrong PDFName!')
                exit(1)
            self.pdf_file = outfile
        else:
            print('wrong IsGraph!')
            exit(1)

        istext = conf.get('OUT STYLE', 'istext')
        if istext == '0':
            self.is_text = False
        elif istext == '1':
            self.is_text = True
            outfilename = conf.get('OUT STYLE', 'outfile')
            if outfilename == '$datetime$':
                try:
                    outfile = open(r'result\feamatrix_' + now_str + '.txt', 'w')
                except FileNotFoundError:
                    os.mkdir('result')
                    outfile = open(r'result\feamatrix_' + now_str + '.txt', 'w')
            elif outfilename:
                outfile = open(outfilename, 'w')
            else:
                outfile = sys.stdout
            self.out_file = outfile
        else:
            print('wrong IsText!')
            exit(1)

        iscsv = conf.get('OUT STYLE', 'iscsv')
        if iscsv == '0':
            self.is_csv = False
        elif iscsv == '1':
            self.is_csv = True
            outfilename = conf.get('OUT STYLE', 'csvname')
            if outfilename == '$datetime$':
                try:
                    outfile = open(r'result\feamatrix_' + now_str + '.csv', 'w', newline='')
                except FileNotFoundError:
                    os.mkdir('result')
                    outfile = open(r'result\feamatrix_' + now_str + '.csv', 'w', newline='')
            elif outfilename:
                outfile = open(outfilename, 'w', newline='')
            else:
                print('wrong CSVName!')
                exit(1)
            self.csv_file = outfile
        else:
            print('wrong IsCSV!')
            exit(1)

        # 3.载入进度条
        self.is_tqdm = bool(int(conf.get('OTHER', 'istqdm')))

        # 4.流划分属性集
        flowg = []
        sdsdp = ('srcip', 'dstip', 'srcport', 'dstport', 'protocol')
        for i in sdsdp:
            flow_g_bit = conf.get('FLOW ID', i)
            if flow_g_bit in ('0', '1', '2'):
                flowg.append(int(flow_g_bit))
            else:
                print('wrong FLOW ID!')
                exit(1)
        flowg = tuple(flowg)
        if (2 in flowg) and (flowg != (2, 2, 0, 0, 0) and flowg != (2, 2, 2, 2, 1)):
            print('wrong FLOW ID!')
            exit(1)
        self.flow_g = flowg

        # 5.特征集
        myfeaturelist = []
        for feature in feature_list.featurelist:
            if not feature.check_condition(self):
                continue
            f_of_features = []
            for j in range(len(feature.names)):
                if conf.get('SELECT FEATURE', feature.names[j]) == '1':
                    f_of_features.append(j)
            if f_of_features:
                myfeaturelist.append((feature, tuple(f_of_features)))
        self.feature_list = tuple(myfeaturelist)

        # 6.工作方式
        process_style = conf.get('PROCESS', 'processstyle')
        if process_style == '0':
            self.process_style = 'all'
            if self.is_graph:
                self.is_graph = False
                self.pdf_file.close()
                del self.pdf_file
        elif process_style == '1':
            self.process_style = 'slice'
            div_basis = conf.get('PROCESS', 'divbasis')
            if div_basis in ('time', 'packet'):
                self.div_basis = div_basis
            else:
                print('wrong DIVISION BASIS!')
                exit(1)
            try:
                split_number = int(conf.get('PROCESS', 'split_number'))
                min_flow_length = int(conf.get('PROCESS', 'minflowlength'))
                if split_number <= 0 or min_flow_length < 0:
                    raise ValueError
                self.split_number = split_number
                self.min_flow_length = min_flow_length
            except ValueError:
                print('wrong SPLIT PARAMETER!')
                exit(1)
        elif process_style == '2':
            self.process_style = 'window'
            div_basis = conf.get('PROCESS', 'divbasis')
            if div_basis in ('time', 'packet'):
                self.div_basis = div_basis
            else:
                print('wrong DIVISION BASIS!')
                exit(1)
            try:
                wnd_size = int(conf.get('PROCESS', 'wnd_size'))
                wnd_speed = int(conf.get('PROCESS', 'wnd_speed'))
                if wnd_speed <= 0 or wnd_size <= 0:
                    raise ValueError
                self.wnd_size = wnd_size
                self.wnd_speed = wnd_speed
            except ValueError:
                print('wrong WINDOW PARAMETER!')
                exit(1)
        else:
            print('wrong Process Style!')
            exit(1)
