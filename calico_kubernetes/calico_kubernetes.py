# Copyright 2015 Metaswitch Networks
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Import print_function to use a testable "print()" function
# instead of keyword "print".
from __future__ import print_function

import os
import re
import requests
import logging
import sys
import json
import socket

from docker import Client
from docker.errors import APIError

from netaddr import IPAddress, IPNetwork, AddrFormatError
from policy import PolicyParser
from subprocess import check_output, CalledProcessError, check_call

import pycalico
from pycalico import netns
from pycalico.block import AlreadyAssignedError
from pycalico.datastore import IF_PREFIX
from pycalico.datastore_datatypes import Rule, Rules
from pycalico.ipam import IPAMClient
from pycalico.util import generate_cali_interface_name, get_host_ips

from logutils import *

pycalico_logger = logging.getLogger(pycalico.__name__)
logger = logging.getLogger(__name__)
LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO').upper()

DOCKER_VERSION = "1.16"
ORCHESTRATOR_ID = "docker"
HOSTNAME = socket.gethostname()

POLICY_ANNOTATION_KEY = "projectcalico.org/policy"

ETCD_AUTHORITY_ENV = "ETCD_AUTHORITY"
if ETCD_AUTHORITY_ENV not in os.environ:
    os.environ[ETCD_AUTHORITY_ENV] = 'kubernetes-master:6666'

# Get the desired calicoctl location.  By default, we search the PATH for
# the location of calicoctl, unless overridden by this variable.
CALICOCTL_PATH = os.environ.get('CALICOCTL_PATH', 'calicoctl')

KUBE_API_ROOT = os.environ.get('KUBE_API_ROOT',
                               'http://kubernetes-master:8080/api/v1/')

# Allow the user to enable/disable namespace isolation policy
DEFAULT_POLICY = os.environ.get('DEFAULT_POLICY', 'allow')

# Flag to indicate whether or not to use Calico IPAM.
# If False, use the default docker container ip address to create container.
# If True, use libcalico's auto_assign IPAM to create container.
CALICO_IPAM = os.environ.get('CALICO_IPAM', 'false')


class NetworkPlugin(object):

    def __init__(self):
        self.pod_name = None
        self.profile_name = None
        self.namespace = None
        self.docker_id = None
        self.auth_token = os.environ.get('KUBE_AUTH_TOKEN', None)
        self.policy_parser = None

        self._datastore_client = IPAMClient()
        self._docker_client = Client(
            version=DOCKER_VERSION,
            base_url=os.getenv("DOCKER_HOST", "unix://var/run/docker.sock"))

    def create(self, namespace, pod_name, docker_id):
        """"Create a pod."""
        self.pod_name = pod_name
        self.docker_id = docker_id
        self.namespace = namespace
        self.policy_parser = PolicyParser(self.namespace)
        self.profile_name = "%s_%s_%s" % (self.namespace,
                                          self.pod_name,
                                          str(self.docker_id)[:12])

        logger.info('Configuring docker container %s', self.docker_id)

        try:
            endpoint = self._configure_interface()
            self._configure_profile(endpoint)
        except CalledProcessError as e:
            logger.error('Error code %d creating pod networking: %s\n%s',
                         e.returncode, e.output, e)
            sys.exit(1)

    def delete(self, namespace, pod_name, docker_id):
        """Cleanup after a pod."""
        self.pod_name = pod_name
        self.docker_id = docker_id
        self.namespace = namespace
        self.profile_name = "%s_%s_%s" % (self.namespace,
                                          self.pod_name,
                                          str(self.docker_id)[:12])

        logger.info('Deleting container %s with profile %s',
                    self.docker_id, self.profile_name)

        # Remove the profile for the workload.
        self._container_remove()

        # Delete profile
        try:
            self._datastore_client.remove_profile(self.profile_name)
        except:
            logger.warning("Cannot remove profile %s; Profile cannot "
                           "be found.", self.profile_name)

    def status(self, namespace, pod_name, docker_id):
        self.namespace = namespace
        self.pod_name = pod_name
        self.docker_id = docker_id

        # Find the endpoint
        try:
            endpoint = self._datastore_client.get_endpoint(
                hostname=HOSTNAME,
                orchestrator_id=ORCHESTRATOR_ID,
                workload_id=self.docker_id
            )
        except KeyError:
            logger.error("Container %s doesn't contain any endpoints",
                         self.docker_id)
            sys.exit(1)

        # Retrieve IPAddress from the attached IPNetworks on the endpoint
        # Since Kubernetes only supports ipv4, we'll only check for ipv4 nets
        if not endpoint.ipv4_nets:
            logger.error("Exiting. No IPs attached to endpoint %s",
                         self.docker_id)
            sys.exit(1)
        else:
            ip_net = list(endpoint.ipv4_nets)
            if len(ip_net) is not 1:
                logger.warning("There is more than one IPNetwork attached "
                               "to endpoint %s", self.docker_id)
            ip = ip_net[0].ip

        logger.info("Retrieved pod IP Address: %s", ip)

        json_dict = {
            "apiVersion": "v1beta1",
            "kind": "PodNetworkStatus",
            "ip": str(ip)
        }

        logger.debug("Writing status to stdout: \n%s", json.dumps(json_dict))
        print(json.dumps(json_dict))

    def _configure_profile(self, endpoint):
        """
        Configure the calico profile on the given endpoint.
        """
        pod = self._get_pod_config()

        logger.info('Configuring Pod Profile: %s', self.profile_name)

        if self._datastore_client.profile_exists(self.profile_name):
            logger.error("Profile with name %s already exists, exiting.",
                         self.profile_name)
            sys.exit(1)
        else:
            rules = self._generate_rules(pod)
            self._datastore_client.create_profile(self.profile_name, rules)

        # Add tags to the profile.
        self._apply_tags(pod)

        # Set the profile for the workload.
        logger.info('Setting profile %s on endpoint %s',
                    self.profile_name, endpoint.endpoint_id)
        self._datastore_client.set_profiles_on_endpoint(
            [self.profile_name], endpoint_id=endpoint.endpoint_id
        )
        logger.info('Finished configuring profile.')

    def _configure_interface(self):
        """Configure the Calico interface for a pod.

        This involves the following steps:
        1) Determine the IP that docker assigned to the interface inside the
           container
        2) Delete the docker-assigned veth pair that's attached to the docker
           bridge
        3) Create a new calico veth pair, using the docker-assigned IP for the
           end in the container's namespace
        4) Assign the node's IP to the host end of the veth pair (required for
           compatibility with kube-proxy REDIRECT iptables rules).
        """
        # Set up parameters
        container_pid = self._get_container_pid(self.docker_id)
        interface = 'eth0'

        self._delete_docker_interface()
        logger.info('Configuring Calico network interface')
        ep = self._container_add(container_pid, interface)

        # Log our container's interfaces after adding the new interface.
        _log_interfaces(container_pid)

        interface_name = generate_cali_interface_name(IF_PREFIX,
                                                      ep.endpoint_id)
        node_ip = self._get_node_ip()
        logger.info('Adding IP %s to interface %s', node_ip, interface_name)

        # This is slightly tricky. Since the kube-proxy sometimes
        # programs REDIRECT iptables rules, we MUST have an IP on the host end
        # of the caliXXX veth pairs. This is because the REDIRECT rule
        # rewrites the destination ip/port of traffic from a pod to a service
        # VIP. The destination port is rewriten to an arbitrary high-numbered
        # port, and the destination IP is rewritten to one of the IPs allocated
        # to the interface. This fails if the interface doesn't have an IP,
        # so we allocate an IP which is already allocated to the node. We set
        # the subnet to /32 so that the routing table is not affected;
        # no traffic for the node_ip's subnet will use the /32 route.
        check_call(['ip', 'addr', 'add', node_ip + '/32',
                    'dev', interface_name])
        logger.info('Finished configuring network interface')
        return ep

    def _container_add(self, pid, interface):
        """
        Add a container (on this host) to Calico networking with the given IP.
        """
        # Check if the container already exists. If it does, exit.
        try:
            _ = self._datastore_client.get_endpoint(
                hostname=HOSTNAME,
                orchestrator_id=ORCHESTRATOR_ID,
                workload_id=self.docker_id
            )
        except KeyError:
            # Calico doesn't know about this container.  Continue.
            pass
        else:
            logger.error("This container has already been configured "
                         "with Calico Networking.")
            sys.exit(1)

        # Obtain information from Docker Client and validate container state
        self._validate_container_state(self.docker_id)

        ip_list = [self._assign_container_ip()]

        # Create Endpoint object
        try:
            logger.info("Creating endpoint with IPs %s", ip_list)
            ep = self._datastore_client.create_endpoint(HOSTNAME,
                                                        ORCHESTRATOR_ID,
                                                        self.docker_id,
                                                        ip_list)
        except (AddrFormatError, KeyError):
            logger.exception("Failed to create endpoint with IPs %s. "
                             "Unassigning IP address, then exiting.", ip_list)
            self._datastore_client.release_ips(set(ip_list))
            sys.exit(1)

        # Create the veth, move into the container namespace, add the IP and
        # set up the default routes.
        logger.info("Creating the veth with namespace pid %s on interface "
                    "name %s", pid, interface)
        ep.mac = ep.provision_veth(netns.PidNamespace(pid), interface)

        logger.info("Setting mac address %s to endpoint %s", ep.mac, ep.name)
        self._datastore_client.set_endpoint(ep)

        # Let the caller know what endpoint was created.
        return ep

    def _assign_container_ip(self):
        """
        Assign IPAddress either with the assigned docker IPAddress or utilize
        calico IPAM.

        The option to utilize IPAM is indicated by the environment variable
        "CALICO_IPAM".
        True indicates to utilize Calico's auto_assign IPAM policy.
        False indicate to utilize the docker assigned IPAddress

        :return IPAddress which has been assigned
        """
        def _assign(ip):
            """
            Local helper function for assigning an IP and checking for errors.
            Only used when operating with CALICO_IPAM=false
            """
            try:
                logger.info("Attempting to assign IP %s", ip)
                self._datastore_client.assign_ip(ip, str(self.docker_id), None)
            except (ValueError, RuntimeError):
                logger.exception("Failed to assign IPAddress %s", ip)
                sys.exit(1)

        if CALICO_IPAM == 'true':
            logger.info("Using Calico IPAM")
            try:
                ipv4s, ipv6s = self._datastore_client.auto_assign_ips(1, 0,
                                                        self.docker_id, None)
                ip = ipv4s[0]
                logger.debug("IPAM assigned ipv4=%s; ipv6= %s", ipv4s, ipv6s)
            except RuntimeError as err:
                logger.error("Cannot auto assign IPAddress: %s", err.message)
                sys.exit(1)
        else:
            logger.info("Using docker assigned IP address")
            ip = self._read_docker_ip()

            try:
                # Try to assign the address using the _assign helper function.
                _assign(ip)
            except AlreadyAssignedError:
                # If the Docker IP is already assigned, it is most likely that
                # an endpoint has been removed under our feet.  When using
                # Docker IPAM, treat Docker as the source of
                # truth for IP addresses.
                logger.warning("Docker IP is already assigned, finding "
                               "stale endpoint")
                self._datastore_client.release_ips(set([ip]))

                # Clean up whatever existing endpoint has this IP address.
                # We can improve this later by making use of IPAM attributes
                # in libcalico to store the endpoint ID.  For now,
                # just loop through endpoints on this host.
                endpoints = self._datastore_client.get_endpoints(
                    hostname=HOSTNAME,
                    orchestrator_id=ORCHESTRATOR_ID)
                for ep in endpoints:
                    if IPNetwork(ip) in ep.ipv4_nets:
                        logger.warning("Deleting stale endpoint %s",
                                       ep.endpoint_id)
                        for profile_id in ep.profile_ids:
                            self._datastore_client.remove_profile(profile_id)
                        self._datastore_client.remove_endpoint(ep)
                        break

                # Assign the IP address to the new endpoint.  It shouldn't
                # be assigned, since we just unassigned it.
                logger.warning("Retry Docker assigned IP")
                _assign(ip)
        return ip

    def _container_remove(self):
        """
        Remove the indicated container on this host from Calico networking
        """
        # Find the endpoint ID. We need this to find any ACL rules
        try:
            endpoint = self._datastore_client.get_endpoint(
                hostname=HOSTNAME,
                orchestrator_id=ORCHESTRATOR_ID,
                workload_id=self.docker_id
            )
        except KeyError:
            logger.exception("Container %s doesn't contain any endpoints",
                             self.docker_id)
            sys.exit(1)

        # Remove any IP address assignments that this endpoint has
        ip_set = set()
        for net in endpoint.ipv4_nets | endpoint.ipv6_nets:
            ip_set.add(net.ip)
        logger.info("Removing IP addresses %s from endpoint %s",
                    ip_set, endpoint.name)
        self._datastore_client.release_ips(ip_set)

        # Remove the veth interface from endpoint
        logger.info("Removing veth interface from endpoint %s", endpoint.name)
        try:
            netns.remove_veth(endpoint.name)
        except CalledProcessError:
            logger.exception("Could not remove veth interface from "
                             "endpoint %s", endpoint.name)

        # Remove the container/endpoint from the datastore.
        try:
            self._datastore_client.remove_workload(
                HOSTNAME, ORCHESTRATOR_ID, self.docker_id)
            logger.info("Successfully removed workload from datastore")
        except KeyError:
            logger.exception("Failed to remove workload.")

        logger.info("Removed Calico interface from %s", self.docker_id)

    def _validate_container_state(self, container_name):
        info = self._get_container_info(container_name)

        # Check the container is actually running.
        if not info["State"]["Running"]:
            logger.error("The container is not currently running.")
            sys.exit(1)

        # We can't set up Calico if the container shares the host namespace.
        if info["HostConfig"]["NetworkMode"] == "host":
            logger.error("Can't add the container to Calico because "
                         "it is running NetworkMode = host.")
            sys.exit(1)

    def _get_container_info(self, container_name):
        try:
            info = self._docker_client.inspect_container(container_name)
        except APIError as e:
            if e.response.status_code == 404:
                logger.error("Container %s was not found. Exiting.",
                             container_name)
            else:
                logger.error(e.message)
            sys.exit(1)
        return info

    def _get_container_pid(self, container_name):
        return self._get_container_info(container_name)["State"]["Pid"]

    def _read_docker_ip(self):
        """Get the IP for the pod's infra container."""
        container_info = self._get_container_info(self.docker_id)
        ip = container_info["NetworkSettings"]["IPAddress"]
        logger.info('Docker-assigned IP is %s', ip)
        return IPAddress(ip)

    def _get_node_ip(self):
        """
        Determine the IP for the host node.
        """
        # Compile list of addresses on network, return the first entry.
        # Try IPv4 and IPv6.
        addrs = get_host_ips(version=4) or get_host_ips(version=6)

        try:
            addr = addrs[0]
            logger.info('Using IP Address %s', addr)
            return addr
        except IndexError:
            # If both get_host_ips return empty lists, print message and exit.
            logger.exception('No Valid IP Address Found for Host - cannot '
                             'configure networking for pod %s. '
                             'Exiting', self.pod_name)
            sys.exit(1)

    def _delete_docker_interface(self):
        """Delete the existing veth connecting to the docker bridge."""
        logger.info('Deleting docker interface eth0')

        # Get the PID of the container.
        pid = str(self._get_container_pid(self.docker_id))
        logger.info('Container %s running with PID %s', self.docker_id, pid)

        # Set up a link to the container's netns.
        logger.info("Linking to container's netns")
        logger.debug(check_output(['mkdir', '-p', '/var/run/netns']))
        netns_file = '/var/run/netns/' + pid
        if not os.path.isfile(netns_file):
            logger.debug(check_output(['ln', '-s', '/proc/' + pid + '/ns/net',
                                      netns_file]))

        # Log our container's interfaces before making any changes.
        _log_interfaces(pid)

        # Reach into the netns and delete the docker-allocated interface.
        logger.debug(check_output(['ip', 'netns', 'exec', pid,
                                  'ip', 'link', 'del', 'eth0']))

        # Log our container's interfaces after making our changes.
        _log_interfaces(pid)

        # Clean up after ourselves (don't want to leak netns files)
        logger.debug(check_output(['rm', netns_file]))

    def _get_pod_ports(self, pod):
        """
        Get the list of ports on containers in the Pod.

        :return list ports: the Kubernetes ContainerPort objects for the pod.
        """
        ports = []
        for container in pod['spec']['containers']:
            try:
                more_ports = container['ports']
                logger.info('Adding ports %s', more_ports)
                ports.extend(more_ports)
            except KeyError:
                pass
        return ports

    def _get_pod_config(self):
        """Get the list of pods from the Kube API server."""
        pods = self._get_api_path('pods')
        logger.debug('Got pods %s', pods)

        for pod in pods:
            logger.debug('Processing pod %s', pod)
            ns = pod['metadata']['namespace'].replace('/', '_')
            name = pod['metadata']['name'].replace('/', '_')
            if ns == self.namespace and name == self.pod_name:
                this_pod = pod
                break
        else:
            raise KeyError('Pod not found: ' + self.pod_name)
        logger.debug('Got pod data %s', this_pod)
        return this_pod

    def _get_api_path(self, path):
        """Get a resource from the API specified API path.

        e.g.
        _get_api_path('pods')

        :param path: The relative path to an API endpoint.
        :return: A list of JSON API objects
        :rtype list
        """
        logger.info('Getting API Resource: %s from KUBE_API_ROOT: %s',
                    path, KUBE_API_ROOT)
        session = requests.Session()
        if self.auth_token:
            session.headers.update({'Authorization':
                                    'Bearer ' + self.auth_token})
        response = session.get(KUBE_API_ROOT + path, verify=False)
        response_body = response.text

        # The response body contains some metadata, and the pods themselves
        # under the 'items' key.
        return json.loads(response_body)['items']

    def _api_root_secure(self):
        """
        Checks whether the KUBE_API_ROOT is secure or insecure.
        If not an http or https address, exit.

        :return: Boolean: True if secure. False if insecure
        """
        if (KUBE_API_ROOT[:5] == 'https'):
            return True
        elif (KUBE_API_ROOT[:5] == 'http:'):
            return False
        else:
            logger.error('KUBE_API_ROOT is not set correctly (%s). '
                         'Please specify as http or https address. Exiting',
                         KUBE_API_ROOT)
            sys.exit(1)

    def _generate_rules(self, pod):
        """
        Generate Rules takes human readable policy strings in annotations
        and returns a libcalico Rules object.

        :return tuple of inbound_rules, outbound_rules
        """
        # Create allow and per-namespace rules for later use.
        allow = Rule(action="allow")
        allow_ns = Rule(action="allow", src_tag=self._get_namespace_tag(pod))
        annotations = self._get_metadata(pod, "annotations")
        logger.debug("Found annotations: %s", annotations)

        if self.namespace == "kube-system" :
            # Pods in the kube-system namespace must be accessible by all
            # other pods for services like DNS to work.
            logger.info("Pod is in kube-system namespace - allow all")
            inbound_rules = [allow]
            outbound_rules = [allow]
        elif annotations and POLICY_ANNOTATION_KEY in annotations:
            # If policy annotations are defined, use them to generate rules.
            logger.info("Generating advanced security policy from annotations")
            rules = annotations[POLICY_ANNOTATION_KEY]
            inbound_rules = []
            outbound_rules = [allow]
            for rule in rules.split(";"):
                parsed_rule = self.policy_parser.parse_line(rule)
                inbound_rules.append(parsed_rule)
        else:
            # If not annotations are defined, just use the configured
            # default policy.
            if DEFAULT_POLICY == 'ns_isolation':
                # Isolate on namespace boundaries by default.
                logger.debug("Default policy is namespace isolation")
                inbound_rules = [allow_ns]
                outbound_rules = [allow]
            else:
                # Allow all traffic by default.
                logger.debug("Default policy is allow all")
                inbound_rules = [allow]
                outbound_rules = [allow]

        return Rules(id=self.profile_name,
                     inbound_rules=inbound_rules,
                     outbound_rules=outbound_rules)

    def _apply_tags(self, pod):
        """
        In addition to Calico's default pod_name tag,
        Add tags generated from Kubernetes Labels and Namespace
            Ex. labels: {key:value} -> tags+= namespace_key_value
        Add tag for namespace
            Ex. namespace: default -> tags+= namespace_default

        :param self.profile_name: The name of the Calico profile.
        :type self.profile_name: string
        :param pod: The config dictionary for the pod being created.
        :type pod: dict
        :return:
        """
        logger.info('Applying tags')

        try:
            profile = self._datastore_client.get_profile(self.profile_name)
        except KeyError:
            logger.error('Could not apply tags. Profile %s could not be '
                         'found. Exiting', self.profile_name)
            sys.exit(1)

        # Grab namespace and create a tag if it exists.
        ns_tag = self._get_namespace_tag(pod)
        logger.info('Adding tag %s', ns_tag)
        profile.tags.add(ns_tag)

        # Create tags from labels
        labels = self._get_metadata(pod, 'labels')
        if labels:
            for k, v in labels.iteritems():
                tag = self._label_to_tag(k, v)
                logger.info('Adding tag %s', tag)
                profile.tags.add(tag)
        else:
            logger.warning('No labels found in pod %s', pod)

        self._datastore_client.profile_update_tags(profile)

        logger.info('Finished applying tags.')

    def _get_metadata(self, pod, key):
        """
        Return Metadata[key] Object given Pod
        Returns None if no key-value exists
        """
        try:
            val = pod['metadata'][key]
        except (KeyError, TypeError):
            logger.warning('No %s found in pod %s', key, pod)
            return None

        logger.debug("Pod %s: %s", key, val)
        return val

    def _escape_chars(self, unescaped_string):
        """
        Calico can only handle 3 special chars, '_.-'
        This function uses regex sub to replace SCs with '_'
        """
        # Character to replace symbols
        swap_char = '_'

        # If swap_char is in string, double it.
        unescaped_string = re.sub(swap_char, "%s%s" % (swap_char, swap_char),
                                  unescaped_string)

        # Substitute all invalid chars.
        return re.sub('[^a-zA-Z0-9\.\_\-]', swap_char, unescaped_string)

    def _get_namespace_tag(self, pod):
        """
        Pull metadata for namespace and return it and a generated NS tag
        """
        assert self.namespace
        ns_tag = self._escape_chars('%s=%s' % ('namespace', self.namespace))
        return ns_tag

    def _label_to_tag(self, label_key, label_value):
        """
        Labels are key-value pairs, tags are single strings. This function
        handles that translation.
        1) Concatenate key and value with '='
        2) Prepend a pod's namespace followed by '/' if available
        3) Escape the generated string so it is Calico compatible
        :param label_key: key to label
        :param label_value: value to given key for a label
        :param namespace: Namespace string, input None if not available
        :param types: (self, string, string, string)
        :return single string tag
        :rtype string
        """
        tag = '%s=%s' % (label_key, label_value)
        tag = '%s/%s' % (self.namespace, tag)
        tag = self._escape_chars(tag)
        return tag

def _log_interfaces(namespace):
    """
    Log interface state in namespace and default namespace.

    :param namespace
    :type namespace str
    """
    try:
        if logger.isEnabledFor(logging.DEBUG):
            interfaces = check_output(['ip', 'addr'])
            logger.debug("Interfaces in default namespace:\n%s", interfaces)

            namespaces = check_output(['ip', 'netns', 'list'])
            logger.debug("Namespaces:\n%s", namespaces)

            cmd = ['ip', 'netns', 'exec', str(namespace), 'ip', 'addr']
            namespace_interfaces = check_output(cmd)

            logger.debug("Interfaces in namespace %s:\n%s",
                         namespace, namespace_interfaces)
    except BaseException:
        # Don't exit if we hit an error logging out the interfaces.
        logger.exception("Ignoring error logging interfaces")

def run_protected():
    """
    Runs the plugin, intercepting all exceptions.
    """
    # Parse arguments and configure logging
    global logger, pycalico_logger
    mode = sys.argv[1]
    namespace = sys.argv[2].replace('/', '_') if len(sys.argv) >=3 else None
    pod_name = sys.argv[3].replace('/', '_') if len(sys.argv) >=4 else None
    docker_id = sys.argv[4] if len(sys.argv) >=5 else None

    # Append a stdout logging handler to log to the Kubelet.
    # We cannot do this in the status hook because the Kubelet looks to
    # stdout for status results.
    log_to_stdout = (mode != 'status')

    # Filter the logger to append the Docker ID to logs.
    # If docker_id is not supplied, do not include it in logger config.
    if docker_id:
        configure_logger(logger=logger,
                         log_level=LOG_LEVEL,
                         log_format=DOCKER_ID_ROOT_LOG_FORMAT,
                         log_to_stdout=log_to_stdout)
        configure_logger(logger=pycalico_logger,
                         log_level=LOG_LEVEL,
                         log_format=DOCKER_ID_LOG_FORMAT,
                         log_to_stdout=log_to_stdout)

        docker_filter = IdentityFilter(identity=str(docker_id)[:12])
        logger.addFilter(docker_filter)
        pycalico_logger.addFilter(docker_filter)
    else:
        configure_logger(logger=logger,
                         log_level=LOG_LEVEL,
                         log_format=ROOT_LOG_FORMAT,
                         log_to_stdout=log_to_stdout)
        configure_logger(logger=pycalico_logger,
                         log_level=LOG_LEVEL,
                         log_format=LOG_FORMAT,
                         log_to_stdout=log_to_stdout)

    # Try to run the plugin, logging out any BaseExceptions raised.
    logger.info("Begin Calico network plugin execution")
    logger.info('Plugin Args: %s', sys.argv)
    rc = 0
    try:
        run(mode=mode,
            namespace=namespace,
            pod_name=pod_name,
            docker_id=docker_id)
    except SystemExit:
        # If a SystemExit is thrown, we've already handled the error and have
        # called sys.exit().  No need to produce a duplicate exception
        # message, just set the return code to 1.
        rc = 1
    except BaseException:
        # Log the exception and set the return code to 1.
        logger.exception("Unhandled Exception killed plugin")
        rc = 1
    finally:
        # Log that we've finished, and exit with the correct return code.
        logger.info("Calico network plugin execution complete")
        sys.exit(rc)

def run(mode, namespace, pod_name, docker_id):
    if mode == 'init':
        logger.info('No initialization work to perform')
    elif mode == "status":
        # Status is called on a regular basis - handle separately
        # to avoid flooding the logs.
        logger.info('Executing Calico pod-status hook')
        NetworkPlugin().status(namespace, pod_name, docker_id)
    else:
        logger.info("Using LOG_LEVEL=%s", LOG_LEVEL)
        logger.info("Using ETCD_AUTHORITY=%s",
                    os.environ[ETCD_AUTHORITY_ENV])
        logger.info("Using KUBE_API_ROOT=%s", KUBE_API_ROOT)
        logger.info("Using CALICO_IPAM=%s", CALICO_IPAM)
        logger.info("Using DEFAULT_POLICY=%s", DEFAULT_POLICY)

        if mode == 'setup':
            logger.info('Executing Calico pod-creation hook')
            NetworkPlugin().create(namespace, pod_name, docker_id)
        elif mode == 'teardown':
            logger.info('Executing Calico pod-deletion hook')
            NetworkPlugin().delete(namespace, pod_name, docker_id)


if __name__ == '__main__':  # pragma: no cover
    run_protected()
