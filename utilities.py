def listofaindictinlist(dictlist, a):
    res = [dic[a] for dic in dictlist]
    return res


def is_positive_direct(src_ip, dst_ip):
    src_ip = int.from_bytes(src_ip, byteorder='big', signed=False)
    dst_ip = int.from_bytes(dst_ip, byteorder='big', signed=False)
    if src_ip > dst_ip:
        return True
    else:
        return False


def get_std(num_list):
    if len(num_list) <= 1:
        return 0
    avg = sum(num_list) / len(num_list)
    return (sum(map(lambda x: (x - avg) ** 2, num_list)) / (len(num_list) - 1)) ** 0.5


def update_slice(pre_sl, sl):
    if pre_sl[0] > pre_sl[1]:
        inc = (sl,)
        dec = tuple()
        res = tuple()
        return inc, dec, res
    elif sl[0] > sl[1]:
        inc = tuple()
        dec = (pre_sl,)
        res = tuple()
        return inc, dec, res
    inc = []
    dec = []
    if pre_sl[1] < sl[1]:
        inc.append((max(pre_sl[1] + 1, sl[0]), sl[1]))
    if pre_sl[0] > sl[0]:
        inc.append((sl[0], min(pre_sl[0] - 1, sl[1])))
    if pre_sl[1] > sl[1]:
        dec.append((max(sl[1] + 1, pre_sl[0]), pre_sl[1]))
    if pre_sl[0] < sl[0]:
        dec.append((pre_sl[0], min(sl[0] - 1, pre_sl[1])))
    if pre_sl[1] < sl[0] or sl[1] < pre_sl[0]:
        res = tuple()
    else:
        res = (max(pre_sl[0], sl[0]), min(pre_sl[1], sl[1]))
    return tuple(inc), tuple(dec), res
