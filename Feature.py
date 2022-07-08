import csv
from collections import OrderedDict as ODict
import matplotlib.pyplot as plt
import feature_list
import utilities


def show_ip(byt_ip):
    if len(byt_ip) == 4:
        return '.'.join(list(map(str, list(byt_ip))))
    elif len(byt_ip) == 16:
        ip_str = ''
        for i in range(8):
            ip_str += byt_ip[2*i:2*i+2].hex()
            ip_str += ':'
        return ip_str.rstrip(':')


def get_ip_bytes(str_ip):
    if '.' in str_ip:  # IPv4
        return bytes(map(int, str_ip.split('.')))
    elif ':' in str_ip:  #IPv6
        return b''.join(map(bytes.fromhex, str_ip.split(':')))
    else:
        return None


def show_flow_id(flow_id, flow_g):
    if flow_g == (2, 2, 0, 0, 0):
        src_ip = show_ip(flow_id[0])
        dst_ip = show_ip(flow_id[1])
        str_flow_id = src_ip + ' <-> ' + dst_ip + '\n'
        return str_flow_id
    elif flow_g == (2, 2, 2, 2, 1):
        src_ip = show_ip(flow_id[0])
        dst_ip = show_ip(flow_id[1])
        str_flow_id = src_ip + ' <-> ' + dst_ip + '\n'
        src_port = flow_id[2]
        dst_port = flow_id[3]
        str_flow_id += str(src_port) + ' <-> ' + str(dst_port) + '\n'
        protocol = flow_id[4]
        if protocol == 17:
            str_flow_id += 'protocol : UDP'
        elif protocol == 1:
            str_flow_id += 'protocol : ICMP'
        elif protocol == 6:
            str_flow_id += 'protocol : TCP'
        else:
            str_flow_id += 'protocol : ' + str(protocol)
        str_flow_id += '\n'
        return str_flow_id
    else:
        index = 0
        if flow_g[0] == 1 and flow_g[1] == 1:
            src_ip = show_ip(flow_id[index])
            dst_ip = show_ip(flow_id[index + 1])
            printstr = src_ip + ' -> ' + dst_ip + '\n'
            index += 2
        elif flow_g[0] == 0 and flow_g[1] == 0:
            printstr = ''
        else:
            if flow_g[0] == 1:
                src_ip = show_ip(flow_id[index])
                printstr = 'src_ip' + ' : ' + src_ip + '\n'
            else:
                dst_ip = show_ip(flow_id[index])
                printstr = 'dst_ip' + ' : ' + dst_ip + '\n'
            index += 1
        if flow_g[2] == 1 and flow_g[3] == 1:
            src_port = flow_id[index]
            dst_port = flow_id[index + 1]
            printstr += str(src_port) + ' -> ' + str(dst_port) + '\n'
            index += 2
        elif flow_g[2] == 0 and flow_g[3] == 0:
            printstr += ''
        else:
            if flow_g[2] == 1:
                src_port = flow_id[index]
                printstr += 'src_port' + ' : ' + str(src_port) + '\n'
            else:
                dst_port = flow_id[index]
                printstr += 'dst_port' + ' : ' + str(dst_port) + '\n'
            index += 1
        if flow_g[4] == 1:
            protocol = flow_id[index]
            if protocol == 17:
                protocol = 'protocol : UDP'
            elif protocol == 1:
                protocol = 'protocol : ICMP'
            elif protocol == 6:
                protocol = 'protocol : TCP'
            else:
                protocol = 'protocol : ' + str(protocol)
            printstr += protocol + '\n'
        return printstr


def show_feature(fdictvalue):
    str_feature = ''
    for value in fdictvalue:
        length = len(str(value))
        if length <= 11:
            str_feature += ' ' * (12 - length) + str(value)
        else:
            if type(value) == str:
                str_feature += ' ' + value[0:4] + '...' + value[-4:]
            elif type(value) == int:
                value_str = str(value)
                bit_10, sign = (length, '+') if value > 0 else (length - 1, '-')
                bit_10_str = str(bit_10)
                if len(bit_10_str) == 1:
                    bit_10_str = '0' + bit_10_str
                else:
                    bit_10_str = bit_10_str[-2:]
                if sign == '+':
                    str_feature += ' ' + value_str[0] + '.' + value_str[1:7] + 'E' + bit_10_str
                else:
                    str_feature += ' -' + value_str[0] + '.' + value_str[1:6] + 'E' + bit_10_str
            elif type(value) == float:
                str_feature += ' {0:.5e}'.format(value) if value > 0 else ' {0:.4e}'.format(value)
            else:
                str_feature += ' ' + str(value)[0:4] + '...' + str(value)[-4:]
    return str_feature + '\n'


def str_to_feature(str_f):
    str_f = str_f[1:]
    try:
        feature = int(str_f)
        return feature
    except ValueError:
        pass
    try:
        feature = float(str_f)
        return feature
    except ValueError:
        pass
    return str_f


class Feature:
    def __init__(self, config=None, addons=None):
        if config is None:
            pass
        else:
            self.src = config.load_style
            self.feature_dict = {}
            if self.src == 'file':
                self.filename_list = addons['files']
            self.flow_g = config.flow_g
            self.feature_list = config.feature_list
            self.process_style = config.process_style
            if self.process_style == 'slice':
                self.div_basis = config.div_basis
                self.split_number = config.split_number
                self.min_flow_length = config.min_flow_length
            elif self.process_style == 'window':
                self.div_basis = config.div_basis
                self.wnd_size = config.wnd_size
                self.wnd_speed = config.wnd_speed

    def add_flow_id(self, flow_id, s_set):
        self.feature_dict[flow_id] = s_set

    def show_text(self):
        show_str = 40 * '=' + '\n'
        show_str += 'Load Style: ' + self.src + '\n'
        show_str += 'Included File(s):\n'
        for f in self.filename_list:
            show_str += '\t' + f + '\n'
        show_str += 'Flow Granularity:'
        for i in self.flow_g:
            show_str += ' ' + str(i)
        show_str += '\n'
        show_str += 'Process Style: ' + self.process_style + '\n'
        if self.process_style == 'slice':
            show_str += 'Division Basis: ' + self.div_basis + '\n'
            show_str += 'Split Number: ' + str(self.split_number) + '\n'
            show_str += 'Min Split Length: ' + str(self.min_flow_length) + '\n'
        elif self.process_style == 'window':
            show_str += 'Division Basis: ' + self.div_basis + '\n'
            show_str += 'Window Size: ' + str(self.wnd_size) + '\n'
            show_str += 'Window Speed: ' + str(self.wnd_speed) + '\n'
        show_str += 'Feature List:\n'
        index = 0
        for features in self.feature_list:
            for i in features[1]:
                index += 1
                show_str += '\t' + str(index) + '. ' + features[0].names[i] + '\n'
        number_feature = index
        show_str += '\n'
        for flow_id in self.feature_dict.keys():
            if not self.feature_dict[flow_id]:
                continue
            show_str += show_flow_id(flow_id, self.flow_g)
            if (self.process_style == 'slice' or self.process_style == 'window') and self.div_basis == 'time':
                show_str += '  time_beg  ' + '  time_end  '
            elif self.process_style != 'all':
                show_str += '  pack_beg  ' + '  pack_end  '
            for i in range(number_feature):
                i_str = str(i + 1)
                i_str_length = len(i_str)
                show_str += ((12-i_str_length) // 2) * ' ' + i_str + (12-i_str_length-(12-i_str_length)//2) * ' '
            show_str += '\n'
            for fdict in self.feature_dict[flow_id]:
                show_str += show_feature(fdict.values())
            show_str += '\n'
        return show_str

    @classmethod
    def load_from_text(cls, filename, index):
        """
        load Feature from filename‘s index-th record, index from 0 to N-1, N is the number of records.
        """
        try:
            with open(filename) as fp:
                file_lines = fp.readlines()
        except FileNotFoundError:
            return None
        n = 0
        begin_sign = False
        end_sign = False
        for i, ln in enumerate(file_lines):
            if ln == 40 * '=' + '\n':
                if n == index:
                    begin_sign = True
                    begin_i = i
                    n += 1
                elif n < index:
                    n += 1
                else:
                    end_sign = True
                    end_i = i
                    break
        if not begin_sign:
            return None
        if end_sign:
            record_lines = file_lines[begin_i + 1:end_i]
        else:
            record_lines = file_lines[begin_i + 1:]

        feature = cls()
        line_index = 0

        feature.src = record_lines[line_index][12:-1]
        line_index += 1

        line_index += 1
        feature.filename_list = []
        while record_lines[line_index].startswith('\t'):
            feature.filename_list.append(record_lines[line_index][1:-1])
            line_index += 1

        flow_g_str = record_lines[line_index][18:-1]
        feature.flow_g = tuple(map(int, flow_g_str.split(' ')))
        line_index += 1

        feature.process_style = record_lines[line_index][15:-1]
        line_index += 1

        if feature.process_style == 'slice':
            feature.div_basis = record_lines[line_index][16:-1]
            line_index += 1
            feature.split_number = int(record_lines[line_index][14:-1])
            line_index += 1
            feature.min_flow_length = int(record_lines[line_index][18:-1])
            line_index += 1
        elif feature.process_style == 'window':
            feature.div_basis = record_lines[line_index][16:-1]
            line_index += 1
            feature.wnd_size = int(record_lines[line_index][13:-1])
            line_index += 1
            feature.wnd_speed = int(record_lines[line_index][14:-1])
            line_index += 1

        line_index += 1
        f_name_list = []
        while record_lines[line_index].startswith('\t'):
            f_name_list.append(record_lines[line_index][1:-1].split('. ', 1)[1])
            line_index += 1
        myfeaturelist = []
        for f in feature_list.featurelist:
            f_of_features = []
            for j in range(len(f.names)):
                if f.names[j] in f_name_list:
                    f_of_features.append(j)
            if f_of_features:
                myfeaturelist.append((f, tuple(f_of_features)))
        feature.feature_list = tuple(myfeaturelist)
        line_index += 1

        feature.feature_dict = {}
        while line_index < len(record_lines):
            flow_id = []
            if feature.flow_g[0] or feature.flow_g[1]:  # this line: ip
                if feature.flow_g[0] and feature.flow_g[1]:
                    if feature.flow_g[0] == 2:
                        ip_list = record_lines[line_index][:-1].split(' <-> ')
                    else:
                        ip_list = record_lines[line_index][:-1].split(' -> ')
                    flow_id.append(get_ip_bytes(ip_list[0]))
                    flow_id.append(get_ip_bytes(ip_list[1]))
                else:
                    ip = record_lines[line_index][9:-1]
                    flow_id.append(get_ip_bytes(ip))
                line_index += 1
            if feature.flow_g[2] or feature.flow_g[3]:  # this line: port
                if feature.flow_g[2] and feature.flow_g[3]:
                    if feature.flow_g[2] == 2:
                        port_list = record_lines[line_index][:-1].split(' <-> ')
                    else:
                        port_list = record_lines[line_index][:-1].split(' -> ')
                    flow_id.append(int(port_list[0]))
                    flow_id.append(int(port_list[1]))
                else:
                    port = record_lines[line_index][11:-1]
                    flow_id.append(int(port))
                line_index += 1
            if feature.flow_g[4]:
                protocal_str = record_lines[line_index][11:-1]
                if protocal_str == 'TCP':
                    flow_id.append(6)
                elif protocal_str == 'UDP':
                    flow_id.append(17)
                elif protocal_str == 'ICMP':
                    flow_id.append(1)
                else:
                    flow_id.append(int(protocal_str))
                line_index += 1
            flow_id = tuple(flow_id)

            if record_lines[line_index][:12] == '  time_beg  ':
                beg_end_sign = 'time'
            elif record_lines[line_index][:12] == '  pack_beg  ':
                beg_end_sign = 'pack'
            else:
                beg_end_sign = None
            line_index += 1
            s_set = []
            while record_lines[line_index] != '\n':
                feature_line = record_lines[line_index]
                f_dict = ODict()
                f_i = 0
                if beg_end_sign == 'time':
                    f_dict['time_beg'] = str_to_feature(feature_line[f_i*12:f_i*12+12])
                    f_i += 1
                    f_dict['time_end'] = str_to_feature(feature_line[f_i * 12:f_i * 12 + 12])
                    f_i += 1
                elif beg_end_sign == 'pack':
                    f_dict['packet_beg'] = str_to_feature(feature_line[f_i * 12:f_i * 12 + 12])
                    f_i += 1
                    f_dict['packet_beg'] = str_to_feature(feature_line[f_i * 12:f_i * 12 + 12])
                    f_i += 1
                for f_name in f_name_list:
                    f_dict[f_name] = str_to_feature(feature_line[f_i * 12:f_i * 12 + 12])
                    f_i += 1
                s_set.append(f_dict)
                line_index += 1
            feature.add_flow_id(flow_id, s_set)
            line_index += 1

        return feature

    def print_csv(self, csvfile):
        feature_name_list = []
        five_part = ('src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol')
        for i in range(5):
            if self.flow_g[i]:
                feature_name_list.append(five_part[i])
        if (self.process_style == 'slice' or self.process_style == 'window') and self.div_basis == 'time':
            feature_name_list.extend(['time_beg', 'time_end'])
        elif self.process_style != 'all':
            feature_name_list.extend(['pack_beg', 'pack_end'])
        for features in self.feature_list:
            for i in features[1]:
                feature_name_list.append(features[0].names[i])

        writer = csv.DictWriter(csvfile, fieldnames=feature_name_list)
        csvfile.write('======,' * 20 + '\n')
        for flow_id in self.feature_dict.keys():
            i = 0
            flow_id_dict = ODict()
            if self.flow_g[0]:
                flow_id_dict['src_ip'] = show_ip(flow_id[i])
                i += 1
            if self.flow_g[1]:
                flow_id_dict['dst_ip'] = show_ip(flow_id[i])
                i += 1
            if self.flow_g[2]:
                flow_id_dict['src_port'] = flow_id[i]
                i += 1
            if self.flow_g[3]:
                flow_id_dict['dst_port'] = flow_id[i]
                i += 1
            if self.flow_g[4]:
                protocol = flow_id[i]
                if protocol == 17:
                    protocol = 'UDP'
                elif protocol == 1:
                    protocol = 'ICMP'
                elif protocol == 6:
                    protocol = 'TCP'
                else:
                    protocol = str(protocol)
                flow_id_dict['protocol'] = protocol
            f_dict = []
            for f_line in self.feature_dict[flow_id]:
                f_dict_line = flow_id_dict.copy()
                f_dict_line.update(f_line)
                f_dict.append(f_dict_line)

            writer.writeheader()
            writer.writerows(f_dict)
            csvfile.write('\n')

    def print_plt_pdf(self, pdf_file, min_plt=6):
        feature_name_list = []
        for features in self.feature_list:
            for i in features[1]:
                feature_name_list.append(features[0].names[i])
        wait_plt = ODict()
        for flow_id in self.feature_dict.keys():
            s_set = self.feature_dict[flow_id]
            if len(s_set) < min_plt:
                continue
            for f_n in feature_name_list:
                wait_plt[(f_n, flow_id)] = utilities.listofaindictinlist(s_set, f_n)

        plt.rcParams['font.sans-serif'] = ['SimHei']  # 显示中文标签
        plt.rcParams['axes.unicode_minus'] = False
        for f_n, flow_id in wait_plt.keys():
            plt.figure(figsize=(10, 10))
            title = show_flow_id(flow_id, self.flow_g)
            plt.title(title)
            plt.plot(range(len(wait_plt[(f_n, flow_id)])), wait_plt[(f_n, flow_id)], label=f_n)
            plt.legend()
            pdf_file.savefig()
            plt.close()
