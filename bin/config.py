# -*- coding:utf-8 -*-
import ConfigParser


class Config:
    """get config from the ini file"""

    def __init__(self, config_file):
        all_config = ConfigParser.ConfigParser()
        with open(config_file, 'r') as cfg_file:
            all_config.readfp(cfg_file)

        self.log_format = all_config.get('format', 'log-format')
        self.log_pattern = all_config.get('format', 'log-pattern')

        self.support_method = all_config.get('filter', 'support_method').split(',')
        self.is_with_parameters = int(all_config.get('filter', 'is_with_parameters'))
        self.always_parameter_keys = all_config.get('filter', 'always_parameter_keys').split(',')
        self.urls_most_number = int(all_config.get('filter', 'urls_most_number'))
        self.urls_pv_threshold = int(all_config.get('filter', 'urls_pv_threshold'))

        self.ignore_url_suffix = all_config.get('filter', 'ignore_url_suffix').split(',')

        self.fixed_parameter_keys = all_config.get('filter', 'fixed_parameter_keys').split(',')
        self.custom_parameters_list = all_config.get('filter', 'custom_parameters').split(',')
        self.custom_keys = []
        self.custom_parameters = {}
        for item in self.custom_parameters_list:
            key = item.split('=')[0]
            if len(item.split('=')) == 2:
                value = item.split('=')[1]
            else:
                value = ''
            self.custom_parameters.setdefault(key, value)
            self.custom_keys.append(key)
        self.ignore_urls = all_config.get('filter', 'ignore_urls').split(',')
        self.static_file = all_config.get('filter', 'static-file').split(',')

        self.second_line_flag = int(all_config.get('report', 'second_line_flag'))
        self.upload_flag = int(all_config.get('report', 'upload_flag'))
        self.upload_url = all_config.get('report', 'upload_url')

config = Config('../conf/config.ini')
