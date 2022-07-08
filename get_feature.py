import utilities
from collections import OrderedDict as ODict
import tqdm


def time_window_split(timesplit, timeset):
    lp = None
    rp = None
    for i, t in enumerate(timeset):
        if timesplit[0] <= t:
            if timesplit[1] >= t:
                rp = i
                if lp is None:
                    lp = i
            else:
                break
    if lp is None:
        lp = 1
        rp = 0
    return lp, rp


def split_on_time(timesplit, timeset):
    i = 0
    splitpoint = []
    for j in range(len(timesplit) - 1):
        lp = i
        while timeset[i] < timesplit[j + 1]:
            i += 1
            if i == len(timeset) - 1:
                rp = i
                splitpoint.append((lp, rp))
                splitpoint += [(i, i - 1)] * (len(timesplit) - 1 - j)
                return splitpoint
        rp = i - 1
        splitpoint.append((lp, rp))
    splitpoint.append((i, len(timeset) - 1))
    return splitpoint


def get_split(flow, config):
    # splitpoint=[(split1_beg,split1_end),(split2_beg,split2_end),...]
    if config.process_style == 'all':
        return [(0, len(flow['feature_set']) - 1)], None
    elif config.process_style == 'slice':
        n = config.split_number
        min_flow_length = config.min_flow_length
        if flow['packet_number'] < min_flow_length * n:
            return [], None
        elif config.div_basis == 'time':
            timeunit = int(flow['feature_set'][-1]['time'] / n)
            timepoint = [i * timeunit for i in range(n)]
            splitpoint = split_on_time(timepoint, utilities.listofaindictinlist(flow['feature_set'], 'time'))
            time_split = [(i * timeunit, (i + 1) * timeunit - 1) for i in range(n - 1)] + \
                         [((n - 1) * timeunit, flow['feature_set'][-1]['time'])]
            return splitpoint, time_split
        elif config.div_basis == 'packet':
            splitpoint = []
            for i in range(n):
                splitpoint.append((flow['packet_number'] * i // n, flow['packet_number'] * (i + 1) // n - 1))
            return splitpoint, None
    elif config.process_style == 'window':
        wnd_size = config.wnd_size
        wnd_speed = config.wnd_speed
        if config.div_basis == 'packet':
            if wnd_size > flow['packet_number']:
                wnd_size = flow['packet_number']
            if wnd_speed > flow['packet_number']:
                wnd_speed = flow['packet_number']
            splitpoint = []
            lp = -wnd_size + wnd_speed
            rp = wnd_speed - 1
            while lp <= len(flow['feature_set']) - 1:
                splitpoint.append((max(0, lp), min(rp, len(flow['feature_set']) - 1)))
                lp += wnd_speed
                rp += wnd_speed
            return splitpoint, None
        elif config.div_basis == 'time':
            if wnd_size > flow['feature_set'][-1]['time'] + 1:
                wnd_size = flow['feature_set'][-1]['time'] + 1
            if wnd_speed > flow['feature_set'][-1]['time'] + 1:
                wnd_speed = flow['feature_set'][-1]['time'] + 1
            ltime = flow['feature_set'][0]['time'] - wnd_size + wnd_speed
            rtime = flow['feature_set'][0]['time'] + wnd_speed - 1
            splitpoint = []
            timepoint = []
            while ltime <= flow['feature_set'][-1]['time']:
                pkt_sl = time_window_split((ltime, rtime), utilities.listofaindictinlist(flow['feature_set'], 'time'))
                splitpoint.append(pkt_sl)
                timepoint.append((max(0, ltime), min(rtime, flow['feature_set'][-1]['time'])))
                ltime += wnd_speed
                rtime += wnd_speed
            return splitpoint, timepoint


def computefeatureline(flow, sp, featurelist, time_slice, update=None):
    feature = ODict()
    this_values = {}
    for f_tuple in featurelist:
        if update is None:
            r_tuple = f_tuple[0](flow, sp, time_slice)
        else:
            r_tuple = f_tuple[0](flow, sp, time_slice, update=(update[0], update[1][f_tuple[0].function]))
        this_values[f_tuple[0].function] = r_tuple
        for i in f_tuple[1]:
            feature[f_tuple[0].names[i]] = r_tuple[i]
    if sp[0] > sp[1]:
        this_values = None
    return feature, this_values


def get_feature(flow, config):
    s_set = []
    pkt_slice, time_slice = get_split(flow, config)
    if pkt_slice:
        last_sp = None
        last_values = None
        for i, sp in tqdm.tqdm(enumerate(pkt_slice), desc='Get Feature - flow_test_id:' + str(flow['test_id'])) if config.is_tqdm else enumerate(pkt_slice):
            p_style = config.process_style
            if time_slice is not None:
                time_sp = time_slice[i]
            else:
                time_sp = None
            if (p_style == 'slice' or p_style == 'window') and config.div_basis == 'time':
                feature_dict = ODict({'time_beg': time_sp[0], 'time_end': time_sp[1]})
            elif p_style != 'all':
                feature_dict = ODict({'packet_beg': sp[0], 'packet_end': sp[1]})
            else:
                feature_dict = ODict()
            if p_style == 'window' and last_values is not None:
                _feature_dict, last_values = computefeatureline(flow, sp, config.feature_list, time_sp,
                                                                (last_sp, last_values))
            else:
                _feature_dict, last_values = computefeatureline(flow, sp, config.feature_list, time_sp)
            feature_dict.update(_feature_dict)
            s_set.append(feature_dict)
            last_sp = sp
    return s_set
