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
import ConfigParser

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

DOCKER_VERSION = "1.16"
ORCHESTRATOR_ID = "docker"
HOSTNAME = socket.gethostname()

# Config filename.
CONFIG_FILENAME = "calico_kubernetes.ini"

# Key to use when searching for annotations.
POLICY_ANNOTATION_KEY = "projectcalico.org/policy"

# Name of the profile to apply when using DEFAULT_POLICY == none.
DEFAULT_PROFILE_NAME = "default-profile"

# Values in configuration dictionary.
ETCD_AUTHORITY_VAR = "ETCD_AUTHORITY"
LOG_LEVEL_VAR = "LOG_LEVEL"
KUBE_AUTH_TOKEN_VAR = "KUBE_AUTH_TOKEN"
KUBE_API_ROOT_VAR = "KUBE_API_ROOT"
CALICO_IPAM_VAR = "CALICO_IPAM"
DEFAULT_POLICY_VAR = "DEFAULT_POLICY"

# All environment variables used by the plugin.
ENVIRONMENT_VARS = [ETCD_AUTHORITY_VAR,
                    LOG_LEVEL_VAR,
                    KUBE_AUTH_TOKEN_VAR,
                    KUBE_API_ROOT_VAR,
                    CALICO_IPAM_VAR,
                    DEFAULT_POLICY_VAR]

# Valid values for DEFAULT_POLICY
POLICY_NS_ISOLATION = "ns_isolation"
POLICY_ALLOW = "allow"
POLICY_NONE = "none"
ALL_POLICIES = [POLICY_NS_ISOLATION, POLICY_ALLOW, POLICY_NONE]


class NetworkPlugin(object):

    def __init__(self, config):
        self.pod_name = None
        self.namespace = None
        self.docker_id = None
        self.policy_parser = None

        # Get configuration from the given dictionary.
        logger.debug("Plugin running with config: %s", config)
        self.auth_token = config[KUBE_AUTH_TOKEN_VAR]
        self.api_root = config[KUBE_API_ROOT_VAR]
        self.calico_ipam = config[CALICO_IPAM_VAR].lower()
        self.default_policy = config[DEFAULT_POLICY_VAR].lower()

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
        logger.info('Configuring pod %s/%s (container_id %s)',
                    self.namespace, self.pod_name, self.docker_id)

        # Obtain information from Docker Client and validate container state.
        # If validation fails, the plugin will exit.
        self._validate_container_state(self.docker_id)

        try:
            endpoint = self._configure_interface()
            logger.info("Created Calico endpoint: %s", endpoint.endpoint_id)
            self._configure_profile(endpoint)
        except BaseException:
            # Check to see if an endpoint has been created.  If so,
            # we need to tear down any state we may have created.
            logger.error("Error networking pod - cleaning up")

            try:
                self.delete(namespace, pod_name, docker_id)
            except:
                # Catch all errors tearing down the pod - this
                # is best-effort.
                logger.exception("Error cleaning up pod")

            # We've torn down, now re-raise the Exception.
            raise
        else:
            logger.info("Successfully configured networking for pod %s/%s",
                        self.namespace, self.pod_name)

    def delete(self, namespace, pod_name, docker_id):
        """Cleanup after a pod."""
        self.pod_name = pod_name
        self.docker_id = docker_id
        self.namespace = namespace
        logger.info('Removing networking from pod %s/%s (container id %s)',
                    self.namespace, self.pod_name, self.docker_id)

        # Get the Calico endpoint.
        endpoint = self._get_endpoint()
        if not endpoint:
            # If there is no endpoint, we don't have any work to do - return.
            logger.debug("No Calico endpoint for pod, no work to do.")
            sys.exit(0)
        logger.debug("Pod has Calico endpoint %s", endpoint.endpoint_id)

        # Remove the endpoint and its configuration.
        self._remove_endpoint(endpoint)

        # Remove any profiles.
        self._remove_profiles(endpoint)

        logger.info("Successfully removed networking for pod %s/%s",
                    self.namespace, self.pod_name)

    def _remove_profiles(self, endpoint):
        """
        If the pod has any profiles, delete them unless they are the 
        default profile or have other members.  We can do this because 
        we create a profile per pod. Profile management for namespaces
        and service based policy will need to be done differently.
        """
        logger.debug("Endpoint has profiles: %s", endpoint.profile_ids)
        for profile_id in endpoint.profile_ids:
            if profile_id == DEFAULT_PROFILE_NAME:
                logger.debug("Do not delete default profile")
                continue

            if self._datastore_client.get_profile_members(profile_id):
                logger.info("Profile %s still has members, do not delete", 
                            profile_id)
                continue

            try:
                logger.info("Deleting Calico profile: %s", profile_id)
                self._datastore_client.remove_profile(profile_id)
            except KeyError:
                logger.warning("Cannot remove profile %s; Profile cannot "
                               "be found.", profile_id)


    def _get_endpoint(self):
        """
        Attempts to get and return the Calico endpoint for this pod.  If no
        endpoint exists, returns None.
        """
        logger.debug("Looking up endpoint for workload %s", self.docker_id)
        try:
            endpoint = self._datastore_client.get_endpoint(
                hostname=HOSTNAME,
                orchestrator_id=ORCHESTRATOR_ID,
                workload_id=self.docker_id
            )
        except KeyError:
            logger.debug("No Calico endpoint exists for pod %s/%s",
                         self.namespace, self.pod_name)
            endpoint = None
        return endpoint
 
    def status(self, namespace, pod_name, docker_id):
        self.namespace = namespace
        self.pod_name = pod_name
        self.docker_id = docker_id

        if self._uses_host_networking(self.docker_id):
            # We don't perform networking / assign IP addresses for pods running
            # in the host namespace, and so we can't return a status update
            # for them.
            logger.debug("Ignoring status for pod %s/%s in host namespace",
                         self.namespace, self.pod_name)
            sys.exit(0)

        # Get the endpoint.
        endpoint = self._get_endpoint()
        if not endpoint:
            # If the endpoint doesn't exist, we cannot provide a status.
            logger.debug("No endpoint for pod - cannot provide status")
            sys.exit(1)

        # Retrieve IPAddress from the attached IPNetworks on the endpoint
        # Since Kubernetes only supports ipv4, we'll only check for ipv4 nets
        if not endpoint.ipv4_nets:
            logger.error("Error in status: No IPs attached to pod %s/%s",
                         self.namespace, self.pod_name)
            sys.exit(1)
        else:
            ip_net = list(endpoint.ipv4_nets)
            if len(ip_net) is not 1:
                logger.warning("There is more than one IPNetwork attached "
                               "to pod %s/%s", self.namespace, self.pod_name)
            ip = ip_net[0].ip

        logger.debug("Retrieved pod IP Address: %s", ip)

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

        If DEFAULT_POLICY != none, we create a new profile for this pod and populate it 
        with the correct rules.

        Otherwise, the pod gets assigned to the default profile.
        """
        if self.default_policy != POLICY_NONE:
            # Determine the name for this profile.
            profile_name = "%s_%s_%s" % (self.namespace, 
                                         self.pod_name, 
                                         str(self.docker_id)[:12])

            # Create a new profile for this pod.
            logger.info("Creating profile '%s'", profile_name)

            #  Retrieve pod labels, etc.
            pod = self._get_pod_config()
    
            if self._datastore_client.profile_exists(profile_name):
                # In profile-per-pod, we don't ever expect duplicate profiles.
                logger.error("Profile '%s' already exists.", profile_name)
                sys.exit(1)
            else:
                # The profile doesn't exist - generate the rule set for this 
                # profile, and create it.
                rules = self._generate_rules(pod, profile_name)
                self._datastore_client.create_profile(profile_name, rules)
    
            # Add tags to the profile based on labels.
            self._apply_tags(pod, profile_name)
    
            # Set the profile for the workload.
            logger.info("Setting profile '%s' on endpoint %s",
                        profile_name, endpoint.endpoint_id)
            self._datastore_client.set_profiles_on_endpoint(
                [profile_name], endpoint_id=endpoint.endpoint_id
            )
            logger.debug('Finished configuring profile.')
        else:
            # Policy is disabled - add this pod to the default profile.
            if not self._datastore_client.profile_exists(DEFAULT_PROFILE_NAME):
                # If the default profile doesn't exist, create it.
                logger.info("Creating profile '%s'", DEFAULT_PROFILE_NAME)
                allow = Rule(action="allow")
                rules = Rules(id=DEFAULT_PROFILE_NAME, 
                              inbound_rules=[allow], 
                              outbound_rules=[allow])
                self._datastore_client.create_profile(DEFAULT_PROFILE_NAME, 
                                                      rules)

            # Set the default profile on this pod's Calico endpoint.
            logger.info("Setting profile '%s' on endpoint %s", 
                        DEFAULT_PROFILE_NAME, endpoint.endpoint_id)
            self._datastore_client.set_profiles_on_endpoint(
                [DEFAULT_PROFILE_NAME], 
                endpoint_id=endpoint.endpoint_id
            )

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
        # Get container's PID.
        container_pid = self._get_container_pid(self.docker_id)

        self._delete_docker_interface()
        logger.info('Configuring Calico network interface')
        ep = self._create_endpoint(container_pid)

        # Log our container's interfaces after adding the new interface.
        _log_interfaces(container_pid)

        interface_name = generate_cali_interface_name(IF_PREFIX,
                                                      ep.endpoint_id)
        node_ip = self._get_node_ip()
        logger.debug('Adding node IP %s to host-side veth %s', node_ip, interface_name)

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

    def _create_endpoint(self, pid):
        """
        Creates a Calico endpoint for this pod.
        - Assigns an IP address for this pod.
        - Creates the Calico endpoint object in the datastore.
        - Provisions the Calico veth pair for this pod.

        Returns the created libcalico Endpoint object.
        """
        # Interface name to be used.
        interface = "eth0"

        # Check if the container already exists. If it does, exit.
        if self._get_endpoint():
            logger.error("This container has already been configured "
                         "with Calico Networking.")
            sys.exit(1)

        ip_list = [self._assign_container_ip()]

        # Create Endpoint object
        try:
            logger.info("Creating Calico endpoint with IPs %s", ip_list)
            ep = self._datastore_client.create_endpoint(HOSTNAME,
                                                        ORCHESTRATOR_ID,
                                                        self.docker_id,
                                                        ip_list)
        except (AddrFormatError, KeyError):
            # We failed to create the endpoint - we must release the IPs
            # that we assigned for this endpoint or else they will leak.
            logger.exception("Failed to create endpoint with IPs %s. "
                             "Unassigning IP address, then exiting.", ip_list)
            self._datastore_client.release_ips(set(ip_list))
            sys.exit(1)

        # Create the veth, move into the container namespace, add the IP and
        # set up the default routes.
        logger.debug("Creating the veth with namespace pid %s on interface "
                     "name %s", pid, interface)
        ep.mac = ep.provision_veth(netns.PidNamespace(pid), interface)

        logger.debug("Setting mac address %s on endpoint %s", ep.mac, ep.name)
        self._datastore_client.set_endpoint(ep)

        # Let the caller know what endpoint was created.
        return ep

    def _assign_container_ip(self):
        """
        Assign IPAddress either with the assigned docker IPAddress or utilize
        calico IPAM.

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

        if self.calico_ipam == 'true':
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

    def _remove_endpoint(self, endpoint):
        """
        Remove the provided endpoint on this host from Calico networking
        - Removes any IP address assignments.
        - Removes the veth interface for this endpoint.
        - Removes the endpoint object from etcd.
        """
        # Remove any IP address assignments that this endpoint has
        ip_set = set()
        for net in endpoint.ipv4_nets | endpoint.ipv6_nets:
            ip_set.add(net.ip)
        logger.info("Removing IP addresses %s from endpoint %s",
                    ip_set, endpoint.name)
        self._datastore_client.release_ips(ip_set)

        # Remove the veth interface from endpoint
        logger.info("Removing veth interfaces")
        try:
            netns.remove_veth(endpoint.name)
        except CalledProcessError:
            logger.exception("Could not remove veth interface from "
                             "endpoint %s", endpoint.name)

        # Remove endpoint from the datastore.
        try:
            self._datastore_client.remove_workload(
                HOSTNAME, ORCHESTRATOR_ID, self.docker_id)
        except KeyError:
            logger.exception("Failed to remove workload.")
        logger.info("Removed Calico endpoint %s", endpoint.endpoint_id)

    def _validate_container_state(self, container_name):
        info = self._get_container_info(container_name)

        # Check the container is actually running.
        if not info["State"]["Running"]:
            logger.error("The container is not currently running.")
            sys.exit(1)

        # We can't set up Calico if the container shares the host namespace.
        if info["HostConfig"]["NetworkMode"] == "host":
            logger.info("Cannot network container %s/%s because "
                        "it is running NetworkMode = host.",
                        self.namespace, self.pod_name)
            sys.exit(0)

    def _uses_host_networking(self, container_name):
        """
        Returns true if the given container is running in the
        host network namespace.
        """
        info = self._get_container_info(container_name)
        return info["HostConfig"]["NetworkMode"] == "host"

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
            logger.debug("Node's IP address: %s", addr)
            return addr
        except IndexError:
            # If both get_host_ips return empty lists, print message and exit.
            logger.exception('No Valid IP Address Found for Host - cannot '
                             'configure networking for pod %s. '
                             'Exiting', self.pod_name)
            sys.exit(1)

    def _delete_docker_interface(self):
        """Delete the existing veth connecting to the docker bridge."""
        logger.debug('Deleting docker interface eth0')

        # Get the PID of the container.
        pid = str(self._get_container_pid(self.docker_id))
        logger.debug('Container %s running with PID %s', self.docker_id, pid)

        # Set up a link to the container's netns.
        logger.debug("Linking to container's netns")
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
        """Get the pod resource from the API.
        API Path depends on the api_root, namespace, and pod_name

        :return: JSON object containing the pod spec
        """
        with requests.Session() as session:
            if self._api_root_secure() and self.auth_token:
                logger.debug('Updating header with Token %s', self.auth_token)
                session.headers.update({'Authorization':
                                        'Bearer ' + self.auth_token})

            path = os.path.join(self.api_root,
                                'namespaces/%s/pods/%s' % (self.namespace,
                                                           self.pod_name))
            try:
                logger.debug('Querying API for Pod: %s', path)
                response = session.get(path, verify=False)
            except BaseException:
                logger.exception("Exception hitting Kubernetes API")
                sys.exit(1)
            else:
                if response.status_code != 200:
                    logger.error("Response from API returned %s Error:\n%s",
                                 response.status_code,
                                 response.text)
                    sys.exit(response.status_code)

        logger.debug("API Response: %s", response.text)
        pod = json.loads(response.text)
        return pod

    def _api_root_secure(self):
        """
        Checks whether the Kubernetes api root is secure or insecure.
        If not an http or https address, exit.

        :return: Boolean: True if secure. False if insecure
        """
        if (self.api_root[:5] == 'https'):
            logger.debug('Using Secure API access.')
            return True
        elif (self.api_root[:5] == 'http:'):
            logger.debug('Using Insecure API access.')
            return False
        else:
            logger.error('%s is not set correctly (%s). '
                         'Please specify as http or https address. Exiting',
                         KUBE_API_ROOT_VAR, self.api_root)
            sys.exit(1)

    def _generate_rules(self, pod, profile_name):
        """
        Generate Rules takes human readable policy strings in annotations
        and returns a libcalico Rules object.

        :return Pycalico Rules object. 
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
            if self.default_policy == POLICY_NS_ISOLATION:
                # Isolate on namespace boundaries by default.
                logger.debug("Default policy is namespace isolation")
                inbound_rules = [allow_ns]
                outbound_rules = [allow]
            elif self.default_policy == POLICY_ALLOW:
                # Allow all traffic by default.
                logger.debug("Default policy is allow all")
                inbound_rules = [allow]
                outbound_rules = [allow]

        return Rules(id=profile_name,
                     inbound_rules=inbound_rules,
                     outbound_rules=outbound_rules)

    def _apply_tags(self, pod, profile_name):
        """
        In addition to Calico's default pod_name tag,
        Add tags generated from Kubernetes Labels and Namespace
            Ex. labels: {key:value} -> tags+= namespace_key_value
        Add tag for namespace
            Ex. namespace: default -> tags+= namespace_default

        :param profile_name: The name of the Calico profile.
        :type profile_name: string
        :param pod: The config dictionary for the pod being created.
        :type pod: dict
        :return:
        """
        logger.debug("Applying tags to profile '%s'", profile_name)

        try:
            profile = self._datastore_client.get_profile(profile_name)
        except KeyError:
            logger.error('Could not apply tags. Profile %s could not be '
                         'found. Exiting', profile_name)
            sys.exit(1)

        # Grab namespace and create a tag if it exists.
        ns_tag = self._get_namespace_tag(pod)
        logger.debug('Generated tag: %s', ns_tag)
        profile.tags.add(ns_tag)

        # Create tags from labels
        labels = self._get_metadata(pod, 'labels')
        if labels:
            for k, v in labels.iteritems():
                tag = self._label_to_tag(k, v)
                logger.debug('Generated tag: %s', tag)
                profile.tags.add(tag)

        # Apply tags to profile.
        self._datastore_client.profile_update_tags(profile)
        logger.debug('Finished applying tags.')

    def _get_metadata(self, pod, key):
        """
        Return Metadata[key] Object given Pod
        Returns None if no key-value exists
        """
        try:
            val = pod['metadata'][key]
        except (KeyError, TypeError):
            logger.debug('No %s found in pod %s', key, pod)
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


def validate_config(config):
    """
    Validates the given configuration dictionary and exits 
    if an error is found.
    """
    if not config[DEFAULT_POLICY_VAR] in ALL_POLICIES:
        err = "Invalid value %s=%s, must be one of %s"
        sys.exit(err % (DEFAULT_POLICY_VAR, 
                        config[DEFAULT_POLICY_VAR], 
                        ALL_POLICIES))


def load_config():
    """
    Loads configuration for the plugin - returns a dictionary.

    Looks first in environment, then in local config file.
    """
    # First, read the config file and get defaults.
    config = read_config_file()

    # Get config from environment, if defined.
    for var in ENVIRONMENT_VARS:
        config[var] = os.environ.get(var, config[var])

    # ETCD_AUTHORITY is handled slightly differently - we need to set it in the
    # environment so that libcalico works correctly.
    if not ETCD_AUTHORITY_VAR in os.environ:
        logger.debug("Use env variable: %s=%s",
                     ETCD_AUTHORITY_VAR,
                     config[ETCD_AUTHORITY_VAR])
        os.environ[ETCD_AUTHORITY_VAR] = config[ETCD_AUTHORITY_VAR]

    # Ensure case is correct.
    config[LOG_LEVEL_VAR] = config[LOG_LEVEL_VAR].upper()

    # Validate the config before returning it.  This will exit
    # and emit an error if any of the configuration is wrong.
    validate_config(config)

    return config


def read_config_file():
    """
    Reads the config file on disk and returns configuration dictionary.
    """
    # Get the current directory and find path to config file.
    executable = sys.argv[0]
    cur_dir = os.path.dirname(executable)
    config_file = os.path.join(cur_dir, CONFIG_FILENAME)

    # Create dictionary of default values.
    defaults = {
        ETCD_AUTHORITY_VAR: "127.0.0.1:2379",
        CALICO_IPAM_VAR: "true",
        KUBE_API_ROOT_VAR: "http://kubernetes-master:8080/api/v1",
        DEFAULT_POLICY_VAR: "allow",
        KUBE_AUTH_TOKEN_VAR: None,
        LOG_LEVEL_VAR: "INFO",
    }
    config = {}

    # Check that the file exists.  If not, return default values.
    if not os.path.isfile(config_file):
        return defaults

    # Read the config file.
    parser = ConfigParser.ConfigParser(defaults)
    parser.read(config_file)

    # Make sure the config section exists
    if not "config" in parser.sections():
        sys.exit("No [config] section in file %s" % config_file)

    # Get any values from the configuration file and populate dictionary.
    for var in ENVIRONMENT_VARS:
        config[var] = parser.get("config", var)

    return config


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

    # Get config from file / environment.
    config = load_config()

    # Filter the logger to append the Docker ID to logs.
    # If docker_id is not supplied, do not include it in logger config.
    if docker_id:
        configure_logger(logger=logger,
                         log_level=config[LOG_LEVEL_VAR],
                         docker_id=str(docker_id)[:12],
                         log_format=DOCKER_ID_ROOT_LOG_FORMAT)
        configure_logger(logger=pycalico_logger,
                         log_level=config[LOG_LEVEL_VAR],
                         docker_id=str(docker_id)[:12],
                         log_format=DOCKER_ID_LOG_FORMAT)

    else:
        configure_logger(logger=logger,
                         log_level=config[LOG_LEVEL_VAR],
                         log_format=ROOT_LOG_FORMAT)
        configure_logger(logger=pycalico_logger,
                         log_level=config[LOG_LEVEL_VAR],
                         log_format=LOG_FORMAT)

    # Try to run the plugin, logging out any BaseExceptions raised.
    logger.debug("Begin Calico network plugin execution")
    logger.debug('Plugin Args: %s', sys.argv)
    rc = 0
    try:
        run(mode=mode,
            namespace=namespace,
            pod_name=pod_name,
            docker_id=docker_id,
            config=config)
    except SystemExit, e:
        # If a SystemExit is thrown, we've already handled the error and have
        # called sys.exit().  No need to produce a duplicate exception
        # message, just return the exit code.
        rc = e.code
    except BaseException:
        # Log the exception and set the return code to 1.
        logger.exception("Unhandled Exception killed plugin")
        rc = 1
    finally:
        # Log that we've finished, and exit with the correct return code.
        logger.debug("Calico network plugin execution complete, rc=%s", rc)
        sys.exit(rc)


def run(mode, namespace, pod_name, docker_id, config):
    if mode == 'init':
        logger.info('No initialization work to perform')
    else:
        if mode == 'setup':
            logger.info('Executing Calico pod-creation hook')
            NetworkPlugin(config).create(namespace, pod_name, docker_id)
        elif mode == 'teardown':
            logger.info('Executing Calico pod-deletion hook')
            NetworkPlugin(config).delete(namespace, pod_name, docker_id)
        elif mode == "status":
            logger.debug('Executing Calico pod-status hook')
            NetworkPlugin(config).status(namespace, pod_name, docker_id)


if __name__ == '__main__':  # pragma: no cover
    run_protected()
