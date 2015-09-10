#!/bin/python
import logging
import os

LOG_DIR = '/var/log/calico/kubernetes'
ROOT_LOG_FORMAT = '%(asctime)s %(process)d %(levelname)s %(message)s'
LOG_FORMAT = '%(asctime)s %(process)d %(levelname)s %(filename)s: %(message)s'


def configure_logger(logger, logging_level, root_logger=False, log_dir=LOG_DIR):
    """
    Configures logging to the file 'calico.log' in the specified log directory

    If the logs are not coming from calico_kubernetes.py, format the log to
     include the filename of origin

    :param logger: logger object to configure
    :param logging_level: level at which logger starts logging. Input type is lowercase string
    :param root_logger: True indicated logger is calico_kubernetes. False indicates otherwise
    :param log_dir: Directory where calico.log lives. If None set to default
    :return:
    """
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)

    hdlr = logging.FileHandler(filename=log_dir+'/calico.log')

    if root_logger:
        formatter = logging.Formatter(ROOT_LOG_FORMAT)
        hdlr.setFormatter(formatter)
    else:
        formatter = logging.Formatter(LOG_FORMAT)
        hdlr.setFormatter(formatter)

    logger.addHandler(hdlr)
    logger.setLevel(logging_level)
