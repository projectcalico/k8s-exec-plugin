#!/bin/python
import logging
from cloghandler import ConcurrentRotatingFileHandler
import os
import sys

LOG_DIR = '/var/log/calico/kubernetes/'
ROOT_LOG_FORMAT = '%(asctime)s %(process)d %(levelname)s %(message)s'
DOCKER_ID_ROOT_LOG_FORMAT = '%(asctime)s %(process)d [%(identity)s] %(levelname)s %(message)s'
LOG_FORMAT = '%(asctime)s %(process)d %(levelname)s %(filename)s: %(message)s'
DOCKER_ID_LOG_FORMAT = '%(asctime)s %(process)d [%(identity)s] %(levelname)s %(filename)s: %(message)s'


def configure_logger(logger, log_level, docker_id=None, log_format=LOG_FORMAT,
                     log_dir=LOG_DIR):
    """
    Configures logging to the file 'calico.log' in the specified log directory

    If the logs are not coming from calico_kubernetes.py, format the log to
     include the filename of origin

    Additionally configures a stderr handler which logs INFO and
    above to stderr.

    :param logger: logger object to configure
    :param log_level: level at which logger starts logging.
    :param log_format: Indicates which logging scheme to use.
    :param log_dir: Directory where calico.log lives. If None set to default
    :return:
    """
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)

    formatter = logging.Formatter(log_format)
    docker_filter = IdentityFilter(identity=docker_id)

    file_hdlr = ConcurrentRotatingFileHandler(filename=log_dir+'calico.log',
                                              maxBytes=1000000,
                                              backupCount=5)
    file_hdlr.setFormatter(formatter)
    if docker_id:
        file_hdlr.addFilter(docker_filter)

    # Add file handler and set log level.
    logger.addHandler(file_hdlr)
    logger.setLevel(log_level)

    # Create a stderr handler and apply it to the logger.
    # This only logs INFO and above to stderr.
    stderr_hdlr = logging.StreamHandler(sys.stderr)
    stderr_hdlr.setLevel(logging.INFO)
    stderr_hdlr.setFormatter(formatter)
    logger.addHandler(stderr_hdlr)


class IdentityFilter(logging.Filter):
    """
    Filter class to impart contextual identity information onto loggers.
    """
    def __init__(self, identity):
        self.identity = identity

    def filter(self, record):
        record.identity = self.identity
        return True
