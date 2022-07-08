import dpkt
import tqdm
import utilities
from collections import OrderedDict as ODict


def get_flow_id(pkt_buf, flow_g):
    """
    从原始dpkt包中获取flow_id。

    param:  pkt_buf: dpkt unpack buf
            flow_g: 流划分属性集，分为单向流和双向流，example：flow_g=(0，1，0，1，0)，单向流，代表五元组中取第二、四项作为flow_id。
            双向流只有两种：（2，2，0，0，0）与（2，2，2，2，1），分别代表把双方IP作为ID和把双方IP、端口、协议作为ID。
    return: return flow id in tuple, or return None on failure
    """
    eth = dpkt.ethernet.Ethernet(pkt_buf)
    ip = eth.data
    if not isinstance(ip, dpkt.ip.IP) and not isinstance(ip, dpkt.ip6.IP6):
        return None  # 网络层协议不是IPv4或IPv6，返回None
    tcp_udp = ip.data
    if not isinstance(tcp_udp, dpkt.tcp.TCP) and not isinstance(tcp_udp, dpkt.udp.UDP):
        return None  # 传输层协议不是TCP或UDP，返回None

    src_ip = ip.src
    dst_ip = ip.dst
    if int.from_bytes(src_ip, byteorder='big', signed=False) == int.from_bytes(dst_ip, byteorder='big', signed=False):
        return None  # 源IP、目的IP一样，返回None
    src_port = tcp_udp.sport
    dst_port = tcp_udp.dport
    protocol = ip.p
    unscreened = (src_ip, dst_ip, src_port, dst_port, protocol)

    flow_id = []
    if 2 not in flow_g:
        for i, b in enumerate(flow_g):
            if b == 1:
                flow_id.append(unscreened[i])
    elif flow_g == (2, 2, 0, 0, 0):
        if utilities.is_positive_direct(src_ip, dst_ip):
            flow_id = [src_ip, dst_ip]
        else:
            flow_id = [dst_ip, src_ip]
    elif flow_g == (2, 2, 2, 2, 1):
        if utilities.is_positive_direct(src_ip, dst_ip):
            flow_id = [src_ip, dst_ip, src_port, dst_port, protocol]
        else:
            flow_id = [dst_ip, src_ip, dst_port, src_port, protocol]

    return tuple(flow_id)


def unpack_feature(buf, featurelist):
    feature = {}
    for f in featurelist:
        feature[f.name] = f(buf)
    return feature


def get_flow_inf(pcap_file_list, config):
    opened_pcap_file_list = []
    for file in pcap_file_list:
        try:
            opened_pcap_file_list.append(dpkt.pcap.Reader(open(file, "rb")))
        except:
            print(file + ' can not be opened!')

    flow_inf = ODict()
    '''
    flow_inf has following structure:
    flow_inf = {flow_id_1: flow_1, flow_id_2: flow_2, ..., flow_id_n: flow_n}
    flow = {'packet_number': packet_number, 'start_time': start_time, 'feature_set': feature_set, 'test_id': test_id}
    feature_set = [packet_1, packet_2, ..., packet_n]
    packet = {'time': time, ...}
    '''
    slicefeaturelist = config.feature_list
    pktfeaturelist = set()
    for feature in slicefeaturelist:
        pktfeaturelist |= set(feature[0].necessary_pkt_features)
    i = 0
    for pcap_file in opened_pcap_file_list:
        for ts, buf in tqdm.tqdm(pcap_file, desc='Load Pcap File - ' + pcap_file.name) if config.is_tqdm else pcap_file:
            try:
                flow_id = get_flow_id(buf, config.flow_g)
            except:
                continue
            if flow_id is None:
                continue
            feature = unpack_feature(buf, pktfeaturelist)
            ts = float(ts)
            try:
                flow_inf[flow_id]['packet_number'] += 1
            except KeyError:
                flow_inf[flow_id] = {'packet_number': 1, 'start_time': ts, 'test_id': i, 'feature_set': []}
                i += 1
            packet_feature = {'time': int(1000000 * (ts - flow_inf[flow_id]['start_time']))}
            for f in feature.keys():
                packet_feature[f] = feature[f]
            flow_inf[flow_id]['feature_set'].append(packet_feature)
    # 包按时间顺序重排
    for flow in flow_inf.keys():
        flow_inf[flow]['feature_set'].sort(key=lambda x: x['time'])
        diff = flow_inf[flow]['feature_set'][0]['time']
        if diff < 0:
            flow_inf[flow]['start_time'] += diff
            for pkt in flow_inf[flow]['feature_set']:
                pkt['time'] -= diff
    return flow_inf
