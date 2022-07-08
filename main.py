import sys
import load_config
import get_flow_inf
import get_feature
from Feature import Feature


def ext_feature(config_file_name):
    config = load_config.Config(config_file_name)
    if config.load_style == 'file':
        filenameset = config.filename_set
        filenames = filenameset.split('|')
        all_feature = []
        for strfnlist in filenames:
            filenamelist = strfnlist.split('&')
            while 1:
                try:
                    filenamelist.remove('')
                except ValueError:
                    break
            if not filenamelist:
                continue
            feature = Feature(config, {'files': filenamelist})
            flow_inf = get_flow_inf.get_flow_inf(filenamelist, config)
            for flow_id in flow_inf.keys():
                s_set = get_feature.get_feature(flow_inf[flow_id], config)
                feature.add_flow_id(flow_id, s_set)
            if config.is_text:
                print(feature.show_text(), file=config.out_file, end='')
            if config.is_csv:
                feature.print_csv(config.csv_file)
            if config.is_graph:
                feature.print_plt_pdf(config.pdf_file)
            all_feature.append(feature)
        if config.is_text and config.out_file != sys.stdout:
            config.out_file.close()
        if config.is_csv:
            config.csv_file.close()
        if config.is_graph:
            config.pdf_file.close()
        return all_feature


if __name__ == '__main__':
    ext_feature('flow.ini')
