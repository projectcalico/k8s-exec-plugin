#!/bin/python
import logging
import os
import sys

LOG_DIR = '/var/log/calico/kubernetes/'
ROOT_LOG_FORMAT = '%(asctime)s %(process)d %(levelname)s %(message)s'
LOG_FORMAT = '%(asctime)s %(process)d %(levelname)s %(filename)s: %(message)s'


def configure_logger(logger, log_level, root_logger=False, log_dir=LOG_DIR):
    """
    Configures logging to the file 'calico.log' in the specified log directory

    If the logs are not coming from calico_kubernetes.py, format the log to
     include the filename of origin

    Additionally configures a stdout handler which logs INFO and
    above to stdout.

    :param logger: logger object to configure
    :param log_level: level at which logger starts logging.
    :param root_logger: True indicates logger is calico_kubernetes.
    :param log_dir: Directory where calico.log lives. If None set to default
    :return:
    """
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)

    file_hdlr = logging.handlers.RotatingFileHandler(filename=log_dir+'calico.log',
                                                     maxBytes=10000000,
                                                     backupCount=5)
    stdout_hdlr = logging.StreamHandler(sys.stdout)
    stdout_hdlr.setLevel(logging.INFO)

    # Determine which formatter to use.
    if root_logger:
        formatter = logging.Formatter(ROOT_LOG_FORMAT)
    else:
        formatter = logging.Formatter(LOG_FORMAT)

    # Set formatters on handlers
    file_hdlr.setFormatter(formatter)
    stdout_hdlr.setFormatter(formatter)

    logger.addHandler(file_hdlr)
    logger.addHandler(stdout_hdlr)
    logger.setLevel(log_level)
