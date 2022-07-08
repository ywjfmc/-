import dpkt
import utilities



class PktFeature:
    def __init__(self, name, function):
        """
        pkt_feature_value = function(packet_buf)
        """
        self.name = name
        self.function = function

    def __call__(self, *args, **kwargs):
        return self.function(*args, **kwargs)

# pkt_feature_list:

def pf_direct(buf):
    """
    return 1, if forward direction
    return 0, if backward direction
    """
    eth = dpkt.ethernet.Ethernet(buf)
    ip = eth.data
    src_ip = ip.src
    dst_ip = ip.dst
    if utilities.is_positive_direct(src_ip, dst_ip):
        return 1
    else:
        return 0
p_direct = PktFeature('direct', pf_direct)

def pf_total_size(buf):
    """
    return the byte number of total packet
    """
    eth = dpkt.ethernet.Ethernet(buf)
    return len(eth)
p_total_size = PktFeature('total_size', pf_total_size)

def pf_tcp_flags(buf):
    """
    return TCP flags(int) if TCP
    return None else
    """
    eth = dpkt.ethernet.Ethernet(buf)
    ip = eth.data
    if ip.p == 6:  # TCP
        tcp = ip.data
        return tcp.flags
    else:
        return None
p_tcp_flags = PktFeature('tcp_flags', pf_tcp_flags)

def pf_ip_head_len(buf):
    """
    return the length of IP head
    """
    eth = dpkt.ethernet.Ethernet(buf)
    ip = eth.data
    head_len = len(ip) - len(ip.data)
    return head_len
p_ip_head_len = PktFeature('ip_header_len', pf_ip_head_len)

def pf_tcp_udp_head_len(buf):
    """
    return the length of TCP head if TCP
    return the length of UDP head if UDP
    """
    eth = dpkt.ethernet.Ethernet(buf)
    ip = eth.data
    tcp_udp = ip.data
    head_len = len(tcp_udp) - len(tcp_udp.data)
    return head_len
p_tcp_udp_head_len = PktFeature('tcp_udp_header_len', pf_tcp_udp_head_len)



class FlowFeatures:
    def __init__(self, function, names, necessary_pkt_features=(), condition={}):
        """
        (feature_value1, feature_value2, ...) = function( flow_inf, slice, time_slice, update)
        slice = (p_beg, p_end)
        p_beg, p_end: int
        time_slice = (t_beg, t_end)
        t_beg, t_end: int
        update = (last_slice, last_values)
        condition = {'direct': 0 -> 仅单向 ; 1 -> 仅双向}
        """
        self.function = function
        self.names = names
        self.necessary_pkt_features = necessary_pkt_features
        self.condition = condition

    def check_condition(self, config):
        direct = self.condition.get('direct')
        if direct == 0 and 2 in config.flow_g:
            return False
        elif direct == 1 and 2 not in config.flow_g:
            return False

        return True

    def __call__(self, *args, **kwargs):
        return self.function(*args, **kwargs)

# flow_features_list:

def ff_fl_pkt_s(flow,sl,t_sl = None,update = None):
    if sl[0] > sl[1]:
        t_diff = 0 if t_sl is None else t_sl[1] - t_sl[0] + 1
        return t_diff, 0, 0
    number_packet = sl[1] - sl[0] + 1
    if t_sl is None:
        time_period = flow['feature_set'][sl[1]]['time'] - flow['feature_set'][sl[0]]['time'] + 1
    else:
        time_period = t_sl[1] - t_sl[0] + 1
    if time_period == 0:
        return (time_period, number_packet, float('inf'))
    else:
        return (time_period, number_packet, number_packet / (time_period / 1000000))
f_fl_pkt_s = FlowFeatures(ff_fl_pkt_s, ('持续时间', '包数', '流包率'))

def ff_tot_pk(flow,sl,t_sl = None,update = None):
    if sl[0] > sl[1]:
        return 0, 0, 0, 0, 0
    if update is not None:
        pre_sl = update[0]
        pre_val = update[1]
        inc, dec, res = utilities.update_slice(pre_sl, sl)
        fw_tot = pre_val[0]
        bw_tot = pre_val[1]
        for inc_sl in inc:
            inc_num = sum(utilities.listofaindictinlist(flow['feature_set'][inc_sl[0]:inc_sl[1] + 1], 'direct'))
            fw_tot += inc_num
            bw_tot += inc_sl[1] - inc_sl[0] + 1 - inc_num
        for dec_sl in dec:
            dec_num = sum(utilities.listofaindictinlist(flow['feature_set'][dec_sl[0]:dec_sl[1] + 1], 'direct'))
            fw_tot -= dec_num
            bw_tot -= dec_sl[1] - dec_sl[0] + 1 - dec_num
    else:
        fw_tot = sum(utilities.listofaindictinlist(flow['feature_set'][sl[0]:sl[1]+1], 'direct'))
        bw_tot = sl[1] - sl[0] + 1 - fw_tot
    if bw_tot == 0:
        fw_bw_ratio = float('inf')
    else:
        fw_bw_ratio = fw_tot / bw_tot
    if t_sl is None:
        time_period = flow['feature_set'][sl[1]]['time'] - flow['feature_set'][sl[0]]['time'] + 1
    else:
        time_period = t_sl[1] - t_sl[0] + 1
    if time_period == 0:
        fw_pkt_s = float('inf')
        bw_pkt_s = float('inf')
    else:
        fw_pkt_s = fw_tot / (time_period/1000000)
        bw_pkt_s = bw_tot / (time_period/1000000)
    return fw_tot, bw_tot, fw_bw_ratio, fw_pkt_s, bw_pkt_s
f_tot_pk = FlowFeatures(ff_tot_pk, ('正向包数', '反向包数', '正向反向包数比', '正向流包率', '反向流包率'), (p_direct,), {'direct': 1})

def ff_pkt_l(flow,sl,t_sl = None,update = None):
    if sl[0] > sl[1]:
        return 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    d_list = utilities.listofaindictinlist(flow['feature_set'][sl[0]:sl[1]+1], 'direct')
    s_list = utilities.listofaindictinlist(flow['feature_set'][sl[0]:sl[1]+1], 'total_size')
    fw_s_list = []
    fw_max = 0
    fw_min = float('inf')
    fw_sum = 0
    bw_s_list = []
    bw_max = 0
    bw_min = float('inf')
    bw_sum = 0
    for i in range(sl[1] - sl[0] + 1):
        if d_list[i] == 1:
            fw_s_list.append(s_list[i])
            fw_sum += s_list[i]
            if fw_max < s_list[i]:
                fw_max = s_list[i]
            if fw_min > s_list[i]:
                fw_min = s_list[i]
        else:
            bw_s_list.append(s_list[i])
            bw_sum += s_list[i]
            if bw_max < s_list[i]:
                bw_max = s_list[i]
            if bw_min > s_list[i]:
                bw_min = s_list[i]
    fw_std = utilities.get_std(fw_s_list)
    bw_std = utilities.get_std(bw_s_list)
    if len(fw_s_list):
        fw_avg = fw_sum / len(fw_s_list)
    else:
        fw_avg = 0
        fw_min = 0
    if len(bw_s_list):
        bw_avg = bw_sum / len(bw_s_list)
    else:
        bw_avg = 0
        bw_min = 0
    if bw_sum == 0:
        fw_bw_ratio = float('inf')
    else:
        fw_bw_ratio = fw_sum / bw_sum
    if t_sl is None:
        time_period = flow['feature_set'][sl[1]]['time'] - flow['feature_set'][sl[0]]['time'] + 1
    else:
        time_period = t_sl[1] - t_sl[0] + 1
    if time_period == 0:
        fw_byt_s = float('inf')
        bw_byt_s = float('inf')
    else:
        fw_byt_s = fw_sum / (time_period / 1000000)
        bw_byt_s = bw_sum / (time_period / 1000000)
    return (fw_sum, fw_max, fw_min, fw_avg, fw_std, bw_sum, bw_max, bw_min, bw_avg, bw_std, fw_bw_ratio, fw_byt_s, bw_byt_s)
std_tuple_buf =  ('正向总大小', '正向最大包大小', '正向最小包大小', '正向平均包大小', '正向包大小标准差',
                  '反向总大小', '反向最大包大小', '反向最小包大小', '反向平均包大小', '反向包大小标准差',
                  '正向反向总大小比', '正向流字节率', '反向流字节率')
f_pkt_l = FlowFeatures(ff_pkt_l, std_tuple_buf, (p_direct, p_total_size), {'direct': 1})

def ff_fl_byt_s(flow,sl,t_sl = None,update = None):
    if sl[0] > sl[1]:
        return 0, 0, 0
    if update is not None:
        pre_sl = update[0]
        pre_val = update[1]
        inc, dec, res = utilities.update_slice(pre_sl, sl)
        all_size = pre_val[1]
        for inc_sl in inc:
            all_size += sum(utilities.listofaindictinlist(flow['feature_set'][inc_sl[0]:inc_sl[1]+1], 'total_size'))
        for dec_sl in dec:
            all_size -= sum(utilities.listofaindictinlist(flow['feature_set'][dec_sl[0]:dec_sl[1]+1], 'total_size'))
    else:
        s_list = utilities.listofaindictinlist(flow['feature_set'][sl[0]:sl[1] + 1], 'total_size')
        all_size = sum(s_list)
    num = sl[1] - sl[0] + 1
    if t_sl is None:
        time_period = flow['feature_set'][sl[1]]['time'] - flow['feature_set'][sl[0]]['time'] + 1
    else:
        time_period = t_sl[1] - t_sl[0] + 1
    if time_period == 0:
        return (float('inf'), all_size, all_size / num)
    else:
        return (all_size / (time_period / 1000000), all_size, all_size / num)
f_fl_byt_s = FlowFeatures(ff_fl_byt_s, ('流字节率', '流大小', '包平均大小'), (p_total_size,))

def ff_iat(flow,sl,t_sl = None,update = None):
    if sl[0] > sl[1]:
        return 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    d_list = utilities.listofaindictinlist(flow['feature_set'][sl[0]:sl[1] + 1], 'direct')
    fw_time_dif = []
    bw_time_dif = []
    pre_fw_time = None
    pre_bw_time = None
    fw_max = 0
    fw_min = float('inf')
    fw_sum = 0
    bw_max = 0
    bw_min = float('inf')
    bw_sum = 0
    for i in range(sl[1] - sl[0] + 1):
        t = flow['feature_set'][sl[0] + i]['time']
        if d_list[i] == 1:
            if pre_fw_time is None:
                pre_fw_time = t
                continue
            else:
                fw_time_dif.append(t - pre_fw_time)
                fw_sum += t - pre_fw_time
                if fw_max < t - pre_fw_time:
                    fw_max = t - pre_fw_time
                if fw_min > t - pre_fw_time:
                    fw_min = t - pre_fw_time
                pre_fw_time = t
        else:
            if pre_bw_time is None:
                pre_bw_time = t
                continue
            else:
                bw_time_dif.append(t - pre_bw_time)
                bw_sum += t - pre_bw_time
                if bw_max < t - pre_bw_time:
                    bw_max = t - pre_bw_time
                if bw_min > t - pre_bw_time:
                    bw_min = t - pre_bw_time
                pre_bw_time = t
    fw_std = utilities.get_std(fw_time_dif)
    bw_std = utilities.get_std(bw_time_dif)
    if len(fw_time_dif):
        fw_avg = fw_sum / len(fw_time_dif)
    else:
        fw_avg = 0
        fw_min = 0
    if len(bw_time_dif):
        bw_avg = bw_sum / len(bw_time_dif)
    else:
        bw_avg = 0
        bw_min = 0
    return (fw_sum, fw_avg, fw_max, fw_min, fw_std, bw_sum, bw_avg, bw_max, bw_min, bw_std)
std_tuple_buf =  ('正向包总时间间隔', '正向包平均时间间隔', '正向包最大时间间隔', '正向包最小时间间隔', '正向包时间间隔标准差',
                  '反向包总时间间隔', '反向包平均时间间隔', '反向包最大时间间隔', '反向包最小时间间隔', '反向包时间间隔标准差')
f_iat = FlowFeatures(ff_iat, std_tuple_buf, (p_direct,), {'direct': 1})

def ff_fw_bw_flags(flow,sl,t_sl = None,update = None):
    if sl[0] > sl[1]:
        return 0, 0, 0, 0
    if update is not None:
        pre_sl = update[0]
        pre_val = update[1]
        inc, dec, res = utilities.update_slice(pre_sl, sl)
        fw_psh = pre_val[0]
        fw_urg = pre_val[1]
        bw_psh = pre_val[2]
        bw_urg = pre_val[3]
        for inc_sl in inc:
            for i in range(inc_sl[0], inc_sl[1] + 1):
                tcp_flags = flow['feature_set'][i]['tcp_flags']
                if tcp_flags is None:
                    continue
                if tcp_flags // 8 % 2 == 1:
                    psh = 1
                else:
                    psh = 0
                if tcp_flags // 32 % 2 == 1:
                    urg = 1
                else:
                    urg = 0
                if flow['feature_set'][i]['direct']:
                    fw_psh += psh
                    fw_urg += urg
                else:
                    bw_psh += psh
                    bw_urg += urg
        for dec_sl in dec:
            for i in range(dec_sl[0], dec_sl[1] + 1):
                tcp_flags = flow['feature_set'][i]['tcp_flags']
                if tcp_flags is None:
                    continue
                if tcp_flags // 8 % 2 == 1:
                    psh = 1
                else:
                    psh = 0
                if tcp_flags // 32 % 2 == 1:
                    urg = 1
                else:
                    urg = 0
                if flow['feature_set'][i]['direct']:
                    fw_psh -= psh
                    fw_urg -= urg
                else:
                    bw_psh -= psh
                    bw_urg -= urg
        return (fw_psh, fw_urg, bw_psh, bw_urg)
    d_list = utilities.listofaindictinlist(flow['feature_set'][sl[0]:sl[1] + 1], 'direct')
    fw_psh = 0
    fw_urg = 0
    bw_psh = 0
    bw_urg = 0
    for i in range(sl[1] - sl[0] + 1):
        tcp_flags = flow['feature_set'][sl[0] + i]['tcp_flags']
        if tcp_flags is None:
            continue
        if d_list[i] == 1:
            if tcp_flags // 8 % 2 == 1:
                fw_psh += 1
            if tcp_flags // 32 % 2 == 1:
                fw_urg += 1
        else:
            if tcp_flags // 8 % 2 == 1:
                bw_psh += 1
            if tcp_flags // 32 % 2 == 1:
                bw_urg += 1
    return (fw_psh, fw_urg, bw_psh, bw_urg)
std_tuple_buf = ('正向PSH包数', '正向URG包数', '反向PSH包数', '反向URG包数')
f_fw_bw_flags = FlowFeatures(ff_fw_bw_flags, std_tuple_buf, (p_direct, p_tcp_flags), {'direct': 1})

def ff_w_ip_hdr_len(flow,sl,t_sl = None,update = None):
    if sl[0] > sl[1]:
        return 0, 0
    if update is not None:
        pre_sl = update[0]
        pre_val = update[1]
        inc, dec, res = utilities.update_slice(pre_sl, sl)
        fw_ip_hdr_len = pre_val[0]
        bw_ip_hdr_len = pre_val[1]
        for inc_sl in inc:
            for i in range(inc_sl[0], inc_sl[1] + 1):
                hdr_len = flow['feature_set'][i]['ip_header_len']
                if flow['feature_set'][i]['direct']:
                    fw_ip_hdr_len += hdr_len
                else:
                    bw_ip_hdr_len += hdr_len
        for dec_sl in dec:
            for i in range(dec_sl[0], dec_sl[1] + 1):
                hdr_len = flow['feature_set'][i]['ip_header_len']
                if flow['feature_set'][i]['direct']:
                    fw_ip_hdr_len -= hdr_len
                else:
                    bw_ip_hdr_len -= hdr_len
        return (fw_ip_hdr_len, bw_ip_hdr_len)
    d_list = utilities.listofaindictinlist(flow['feature_set'][sl[0]:sl[1] + 1], 'direct')
    fw_ip_hdr_len = 0
    bw_ip_hdr_len = 0
    for i in range(sl[1] - sl[0] + 1):
        hdr_len = flow['feature_set'][sl[0] + i]['ip_header_len']
        if d_list[i] == 1:
            fw_ip_hdr_len += hdr_len
        else:
            bw_ip_hdr_len += hdr_len
    return (fw_ip_hdr_len, bw_ip_hdr_len)
f_w_ip_hdr_len = FlowFeatures(ff_w_ip_hdr_len, ('正向包IP头总长', '反向包IP头总长'), (p_direct, p_ip_head_len), {'direct': 1})

def ff_w_tcp_udp_hdr_len(flow,sl,t_sl = None,update = None):
    if sl[0] > sl[1]:
        return 0, 0
    if update is not None:
        pre_sl = update[0]
        pre_val = update[1]
        inc, dec, res = utilities.update_slice(pre_sl, sl)
        fw_tcp_udp_hdr_len = pre_val[0]
        bw_tcp_udp_hdr_len = pre_val[1]
        for inc_sl in inc:
            for i in range(inc_sl[0], inc_sl[1] + 1):
                hdr_len = flow['feature_set'][i]['tcp_udp_header_len']
                if flow['feature_set'][i]['direct']:
                    fw_tcp_udp_hdr_len += hdr_len
                else:
                    bw_tcp_udp_hdr_len += hdr_len
        for dec_sl in dec:
            for i in range(dec_sl[0], dec_sl[1] + 1):
                hdr_len = flow['feature_set'][i]['tcp_udp_header_len']
                if flow['feature_set'][i]['direct']:
                    fw_tcp_udp_hdr_len -= hdr_len
                else:
                    bw_tcp_udp_hdr_len -= hdr_len
        return (fw_tcp_udp_hdr_len, bw_tcp_udp_hdr_len)
    d_list = utilities.listofaindictinlist(flow['feature_set'][sl[0]:sl[1] + 1], 'direct')
    fw_tcp_udp_hdr_len = 0
    bw_tcp_udp_hdr_len = 0
    for i in range(sl[1] - sl[0] + 1):
        hdr_len = flow['feature_set'][sl[0] + i]['tcp_udp_header_len']
        if d_list[i] == 1:
            fw_tcp_udp_hdr_len += hdr_len
        else:
            bw_tcp_udp_hdr_len += hdr_len
    return (fw_tcp_udp_hdr_len, bw_tcp_udp_hdr_len)
std_tuple_buf = ('正向包传输头总长', '反向包传输头总长')
f_w_tcp_udp_hdr_len = FlowFeatures(ff_w_tcp_udp_hdr_len, std_tuple_buf, (p_direct, p_tcp_udp_head_len), {'direct': 1})

def ff_flags_cnt(flow,sl,t_sl = None,update = None):
    if sl[0] > sl[1]:
        return 0, 0, 0, 0, 0, 0, 0, 0
    if update is not None:
        pre_sl = update[0]
        pre_val = update[1]
        inc, dec, res = utilities.update_slice(pre_sl, sl)
        flags_cnt = list(pre_val)
        for inc_sl in inc:
            for i in range(inc_sl[0], inc_sl[1] + 1):
                tcp_flags = flow['feature_set'][i]['tcp_flags']
                if tcp_flags is None:
                    continue
                for j in range(8):
                    if tcp_flags // (2 ** j) % 2 == 1:
                        flags_cnt[j] += 1
        for dec_sl in dec:
            for i in range(dec_sl[0], dec_sl[1] + 1):
                tcp_flags = flow['feature_set'][i]['tcp_flags']
                if tcp_flags is None:
                    continue
                for j in range(8):
                    if tcp_flags // (2 ** j) % 2 == 1:
                        flags_cnt[j] -= 1
        return tuple(flags_cnt)
    flags_cnt = [0] * 8
    for i in range(sl[1] - sl[0] + 1):
        tcp_flags = flow['feature_set'][sl[0] + i]['tcp_flags']
        if tcp_flags is None:
            continue
        for j in range(8):
            if tcp_flags // (2**j) % 2 == 1:
                flags_cnt[j] += 1
    return tuple(flags_cnt)
std_tuple_buf = ('FIN包数', 'SYN包数', 'RST包数', 'PSH包数', 'ACK包数', 'URG包数', 'ECE包数', 'CWR包数')
f_flags_cnt = FlowFeatures(ff_flags_cnt, std_tuple_buf, (p_tcp_flags,))


featurelist = (f_fl_pkt_s, f_tot_pk, f_pkt_l, f_fl_byt_s, f_iat, f_fw_bw_flags, f_w_ip_hdr_len,
               f_w_tcp_udp_hdr_len, f_flags_cnt)
