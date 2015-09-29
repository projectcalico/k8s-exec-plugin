# Copyright 2015 Metaswitch Networks
#
# Licensed under the Apache License, Version 2.0 (the 'License');
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an 'AS IS' BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import socket
import logging
import json
import os
import sys

from netaddr import IPAddress, IPNetwork, AddrFormatError
from docker import Client
from docker.errors import APIError
import pycalico
from pycalico.netns import PidNamespace,remove_veth
from pycalico.ipam import IPAMClient
from pycalico.datastore_datatypes import Rules
from logutils import configure_logger
from subprocess import CalledProcessError, PIPE, Popen

ETCD_AUTHORITY_ENV = 'ETCD_AUTHORITY'
LOG_DIR = '/var/log/calico/kubernetes'

ORCHESTRATOR_ID = "docker"
HOSTNAME = socket.gethostname()

ENV = None
"""
Holds the environment dictionary.
"""

CONFIG = None
"""
Holds the CNI network config loaded from stdin.
"""

_log = logging.getLogger(__name__)
datastore_client = IPAMClient()
docker_client = Client()


def calico_kubernetes_cni(args):
    """
    Orchestrate top level function

    :param args: dict of values to pass to other functions (see: validate_args)
    """
    if args['command'] == 'ADD':
        create(args)
    elif args['command'] == 'DEL':
        delete(args)
    else:
        _log.warning('Unknown command: %s', args['command'])


def create(args):
    """"
    Handle a pod-create event.
    Print allocated IP as json to STDOUT

    :param args: dict of values to pass to other functions (see: validate_args)
    """
    container_id = args['container_id']
    netns = args['netns']
    interface = args['interface']
    net_name = args['name']

    _log.info('Configuring pod %s' % container_id)

    endpoint = _create_calico_endpoint(container_id=container_id,
                                       interface=interface)

    _set_profile_on_endpoint(endpoint=endpoint,
                             profile_name=net_name)

    dump = json.dumps(
        {
            "ip4": {
                "ip": "%s" % endpoint.ipv4_nets.copy().pop()
            }
        })
    _log.info('Dumping info to kubernetes: %s' % dump)
    print(dump)

    _log.info('Finished Creating pod %s' % container_id)


def delete(args):
    """
    Cleanup after a pod.

    :param args: dict of values to pass to other functions (see: validate_args)
    """
    container_id = args['container_id']
    net_name = args['name']

    _log.info('Deleting pod %s' % container_id)

    # Remove the profile for the workload.
    _container_remove(hostname=HOSTNAME,
                      orchestrator_id=ORCHESTRATOR_ID,
                      container_id=container_id)

    # Delete profile if only member
    if datastore_client.profile_exists(net_name) and \
       len(datastore_client.get_profile_members(net_name)) < 1:
        try:
            _log.info("Profile %s has no members, removing from datastore" % net_name)
            datastore_client.remove_profile(net_name)
        except:
            _log.error("Cannot remove profile %s: Profile cannot be found." % container_id)
            sys.exit(1)


def _create_calico_endpoint(container_id, interface):
    """
    Configure the Calico interface for a pod.
    Return Endpoint and IP

    :param container_id (str):
    :param interface (str): iface to use
    :rtype Endpoint: Endpoint created
    """
    _log.info('Configuring Calico networking.')

    try:
        _ = datastore_client.get_endpoint(hostname=HOSTNAME,
                                          orchestrator_id=ORCHESTRATOR_ID,
                                          workload_id=container_id)
    except KeyError:
        # Calico doesn't know about this container.  Continue.
        pass
    else:
        _log.error("This container has already been configured with Calico Networking.")
        sys.exit(1)

    endpoint = _container_add(hostname=HOSTNAME,
                              orchestrator_id=ORCHESTRATOR_ID,
                              container_id=container_id,
                              interface=interface)

    _log.info('Finished configuring network interface')
    return endpoint


def _container_add(hostname, orchestrator_id, container_id, interface):
    """
    Add a container to Calico networking
    Return Endpoint object and newly allocated IP

    :param hostname (str): Host for enndpoint allocation
    :param orchestrator_id (str): Specifies orchestrator
    :param container_id (str):
    :param interface (str): iface to use
    :rtype Endpoint: Endpoint created
    """
    # Allocate and Assign ip address through datastore_client
    try:
        ip = _assign_ip_address()
    except CalledProcessError, e:
        _log.exception("Error assigning IP address using IPAM plugin")
        sys.exit(e.returncode)

    # Create Endpoint object
    try:
        _log.info("Creating endpoint with IP address %s for container %s",
                  ip, container_id)
        ep = datastore_client.create_endpoint(HOSTNAME, ORCHESTRATOR_ID,
                                              container_id, [ip])
    except AddrFormatError:
        _log.error("This node is not configured for IPv%d, exiting.", ip.version)
        sys.exit(1)

    # Obtain the pid of the running container
    pid = _get_container_pid(container_id)

    # Create the veth, move into the container namespace, add the IP and
    # set up the default routes.
    _log.info("Creating the veth with pid %s on interface %s", pid, interface)
    ep.mac = ep.provision_veth(PidNamespace(pid), interface)
    datastore_client.set_endpoint(ep)

    return ep


def _container_remove(hostname, orchestrator_id, container_id):
    """
    Remove the indicated container on this host from Calico networking

    :param hostname (str): Host for enndpoint allocation
    :param orchestrator_id (str): Specifies orchestrator
    :param container_id (str):
    """
    # Un-assign the IP address by calling out to the IPAM plugin
    _unassign_ip_address()

    # Find the endpoint ID. We need this to find any ACL rules
    try:
        endpoint = datastore_client.get_endpoint(hostname=hostname,
                                                 orchestrator_id=orchestrator_id,
                                                 workload_id=container_id)
    except KeyError:
        _log.error("Container %s doesn't contain any endpoints" % container_id)
        sys.exit(1)

    # Remove the endpoint
    remove_veth(endpoint.name)

    # Remove the container from the datastore.
    datastore_client.remove_workload(hostname=hostname,
                                     orchestrator_id=orchestrator_id,
                                     workload_id=container_id)

    _log.info("Removed Calico interface from %s" % container_id)


def _set_profile_on_endpoint(endpoint, profile_name):
    """
    Configure the calico profile to the endpoint

    :param endpoint (Endpoint obj): Endpoint to set profile on
    :param profile_name (str): Profile name to add to endpoint
    """
    _log.info('Configuring Pod Profile: %s' % profile_name)

    if not datastore_client.profile_exists(profile_name):
        _log.info("Creating new profile %s." % (profile_name))
        datastore_client.create_profile(profile_name)
        # _assign_default_rules(profile_name)

    # Also set the profile for the workload.
    datastore_client.set_profiles_on_endpoint(profile_names=[profile_name],
                                              endpoint_id=endpoint.endpoint_id)


def _assign_default_rules(profile_name):
    """
    Generate a new profile rule list and update the datastore_client
    :param profile_name: The profile to update
    :type profile_name: string
    :return:
    """
    try:
        profile = datastore_client.get_profile(profile_name)
    except:
        _log.error("Could not apply rules. Profile not found: %s, exiting" % profile_name)
        sys.exit(1)

    rules_dict = {
        "id": profile_name,
        "inbound_rules": [
            {
                "action": "allow",
            },
        ],
        "outbound_rules": [
            {
                "action": "allow",
            },
        ],
    }

    rules_json = json.dumps(rules_dict, indent=2)
    profile_rules = Rules.from_json(rules_json)

    datastore_client.profile_update_rules(profile)
    _log.info("Finished applying default rules.")


def _assign_ip_address():
    """
    Assigns and returns an IPv4 address using the IPAM plugin specified in CONFIG.
    :return:
    """
    # May throw CalledProcessError - let it.  We may want to replace this with our own Exception.
    result = _call_ipam_plugin()
    _log.debug("IPAM plugin result: %s", result)

    try:
        # Load the response and get the assigned IP address.
        result = json.loads(result)
    except ValueError:
        _log.exception("Failed to parse IPAM response, exiting")
        sys.exit(1)

    # The request was successful.  Get the IP.
    _log.info("IPAM result: %s", result)
    return IPNetwork(result["ipv4"]["ip"])


def _unassign_ip_address():
    """
    Un-assigns the IP address for this container using the IPAM plugin specified in CONFIG.
    :return:
    """
    # Try to un-assign the address.  Catch exceptions - we don't want to stop execution if
    # we fail to un-assign the address.
    _log.info("Un-assigning IP address")
    try:
        result = _call_ipam_plugin()
        _log.debug("IPAM plugin result: %s", result)
    except CalledProcessError:
        _log.exception("IPAM plugin failed to un-assign IP address.")


def _call_ipam_plugin():
    """
    Calls through to the specified IPAM plugin.

    :param config: IPAM config as specified in the CNI network configuration file.  A
        dictionary with the following form:
        {
          type: <IPAM TYPE>
        }
    :return: Response from the IPAM plugin.
    """
    # Get the plugin type and location.
    plugin_type = CONFIG['ipam']['type']
    plugin_dir = ENV.get('CNI_PATH')
    _log.info("IPAM plugin type: %s.  Plugin directory: %s", plugin_type, plugin_dir)

    # Find the correct plugin based on the given type.
    plugin_path = os.path.abspath(os.path.join(plugin_dir, plugin_type))
    _log.info("Using IPAM plugin at: %s", plugin_path)

    # Execute the plugin and return the result.
    p = Popen(plugin_path, stdin=PIPE, stdout=PIPE, stderr=PIPE)
    stdout, stderr= p.communicate(json.dumps(CONFIG))
    _log.info("IPAM output: \nstdout: %s\nstderr: %s", stdout, stderr)
    return stdout


def _get_container_info(container_id):
    try:
        info = docker_client.inspect_container(container_id)
    except APIError as e:
        if e.response.status_code == 404:
            _log.error("Container %s was not found. Exiting.", container_id)
        else:
             _log.error(e.message)
        sys.exit(1)
    return info


def _get_container_pid(container_id):
    return _get_container_info(container_id)["State"]["Pid"]


def validate_args(env, conf):
    """
    Validate and organize environment and stdin args

    ENV =   {
                'CNI_IFNAME': 'eth0',                   req [default: 'eth0']
                'CNI_ARGS': '',
                'CNI_COMMAND': 'ADD',                   req
                'CNI_PATH': '.../.../...',
                'CNI_NETNS': 'netns',                   req [default: 'netns']
                'CNI_CONTAINERID': '1234abcd68',        req
            }
    CONF =  {
                "name": "test",                         req
                "type": "calico",
                "ipam": {
                    "type": "calico-ipam",
                    "subnet": "10.22.0.0/16",           req
                    "routes": [{"dst": "0.0.0.0/0"}],   optional (unsupported)
                    "range-start": ""                   optional (unsupported)
                    "range-end": ""                     optional (unsupported)
                    }
            }
    args = {
                'command': ENV['CNI_COMMAND']
                'interface': ENV['CNI_IFNAME']
                'netns': ENV['CNI_NETNS']
                'name': CONF['name']
                'subnet': CONF['ipam']['subnet']
    }

    :param env (dict): Environment variables from CNI.
    :param conf (dict): STDIN arguments converted to json dict
    :rtype dict:
    """
    _log.debug('Environment: %s' % env)
    _log.debug('Config: %s' % conf)

    args = dict()

    # ENV
    try:
        args['command'] = env['CNI_COMMAND']
    except KeyError:
        _log.error('No CNI_COMMAND in Environment')
        sys.exit(1)
    else:
        if args['command'] not in ["ADD", "DEL"]:
            _log.error('CNI_COMMAND \'%s\' not recognized' % args['command'])

    try:
        args['container_id'] = env['CNI_CONTAINERID']
    except KeyError:
        _log.error('No CNI_CONTAINERID in Environment')
        sys.exit(1)

    try:
        args['interface'] = env['CNI_IFNAME']
    except KeyError:
        _log.exception(
            'No CNI_IFNAME in Environment, using interface \'eth0\'')
        args['interface'] = 'eth0'

    try:
        args['netns'] = env['CNI_NETNS']
    except KeyError:
        _log.exception('No CNI_NETNS in Environment, using \'netns\'')
        args['netns'] = 'netns'

    # CONF
    try:
        args['name'] = conf['name']
    except KeyError:
        _log.error('No Name in Network Config')
        sys.exit(1)

    try:
        args['ipam'] = conf['ipam']
        _ = args['ipam']['type']
    except KeyError:
        _log.error('No IPAM specified in Network Config')
        sys.exit(1)

    _log.debug('Validated Args: %s' % args)
    return args


if __name__ == '__main__':
    # Setup logger
    if not os.path.exists(LOG_DIR):
        os.makedirs(LOG_DIR)
    hdlr = logging.FileHandler(filename=LOG_DIR+'/calico-kubernetes-cni.log')
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    hdlr.setFormatter(formatter)
    _log.addHandler(hdlr)
    _log.setLevel(logging.DEBUG)

    pycalico_logger = logging.getLogger(pycalico.__name__)
    configure_logger(pycalico_logger, logging.DEBUG, False)


    # Environment
    global ENV
    ENV = os.environ.copy()

    # Populate a global variable with the config read from stdin so that
    global CONFIG
    conf_raw = ''.join(sys.stdin.readlines()).replace('\n', '')
    CONFIG = json.loads(conf_raw).copy()

    # Scrub args
    args = validate_args(ENV, CONFIG)

    # Call plugin
    calico_kubernetes_cni(args)
