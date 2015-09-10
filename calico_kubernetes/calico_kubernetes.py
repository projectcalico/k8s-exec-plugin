#!/bin/python
import json
import os
import sys
import re
import socket
from docker import Client
from docker.errors import APIError
from subprocess import check_output, CalledProcessError, check_call
import requests
import sh
import logging
from netaddr import IPAddress, AddrFormatError
from logutils import configure_logger
import pycalico
from pycalico import netns
from pycalico.datastore import IF_PREFIX, DatastoreClient
from pycalico.util import generate_cali_interface_name, get_host_ips
from pycalico.ipam import IPAMClient
from pycalico.block import AlreadyAssignedError

logger = logging.getLogger(__name__)
pycalico_logger = logging.getLogger(pycalico.__name__)
LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO').upper()

DOCKER_VERSION = "1.16"
ORCHESTRATOR_ID = "docker"
HOSTNAME = socket.gethostname()

POLICY_ANNOTATION_KEY = "projectcalico.org/policy"

ETCD_AUTHORITY_ENV = "ETCD_AUTHORITY"
if ETCD_AUTHORITY_ENV not in os.environ:
    os.environ[ETCD_AUTHORITY_ENV] = 'kubernetes-master:6666'

# Append to existing env, to avoid losing PATH etc.
# Need to edit the path here since calicoctl loads client on import.
CALICOCTL_PATH = os.environ.get('CALICOCTL_PATH', '/usr/bin/calicoctl')

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

        self._datastore_client = IPAMClient()
        self.calicoctl = sh.Command(CALICOCTL_PATH).bake(_env=os.environ)
        self._docker_client = Client(
            version=DOCKER_VERSION,
            base_url=os.getenv("DOCKER_HOST", "unix://var/run/docker.sock"))

    def create(self, namespace, pod_name, docker_id):
        """"Create a pod."""
        # Calicoctl does not support the '-' character in iptables rule names.
        # TODO: fix Felix to support '-' characters.
        self.pod_name = pod_name
        self.docker_id = docker_id
        self.namespace = namespace
        self.profile_name = "%s_%s_%s" % (self.namespace, self.pod_name, str(self.docker_id)[:12])

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
        self.profile_name = "%s_%s_%s" % (self.namespace, self.pod_name, str(self.docker_id)[:12])

        logger.info('Deleting container %s with profile %s',
                    self.docker_id, self.profile_name)

        # Remove the profile for the workload.
        self._container_remove()

        # Delete profile
        try:
            self._datastore_client.remove_profile(self.profile_name)
        except:
            logger.warning("Cannot remove profile %s; Profile cannot be found.",
                           self.profile_name)

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
            logger.error("Container %s doesn't contain any endpoints" % self.docker_id)
            sys.exit(1)

        # Retrieve IPAddress from the attached IPNetworks on the endpoint
        # Since Kubernetes only supports ipv4, we'll only check for ipv4 nets
        if not endpoint.ipv4_nets :
            logger.error("Exiting. No IPs attached to endpoint %s", self.docker_id)
            sys.exit(1)
        else:
            ip_net = list(endpoint.ipv4_nets)
            if len(ip_net) is not 1:
                logger.warning("There is more than one IPNetwork attached to endpoint %s", self.docker_id)
            ip = ip_net[0].ip

        logger.info("Retrieved IP Address: %s", ip)

        json_dict = {
            "apiVersion": "v1beta1",
            "kind": "PodNetworkStatus",
            "ip": str(ip)
        }

        logger.debug("Writing json dict to stdout: \n%s", json.dumps(json_dict))
        print json.dumps(json_dict)

    def _configure_profile(self, endpoint):
        """
        Configure the calico profile for a pod.

        Currently assumes one pod with each name.
        """
        pod = self._get_pod_config()

        logger.info('Configuring Pod Profile: %s', self.profile_name)

        if self._datastore_client.profile_exists(self.profile_name):
            logger.error("Profile with name %s already exists, exiting.",
                         self.profile_name)
            sys.exit(1)
        else:
            self._datastore_client.create_profile(self.profile_name)

        self._apply_rules(pod)

        self._apply_tags(pod)

        # Also set the profile for the workload.
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
        interface_name = generate_cali_interface_name(IF_PREFIX, ep.endpoint_id)
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
            logger.error("This container has already been configured with Calico Networking.")
            sys.exit(1)

        # Obtain information from Docker Client and validate container state
        self._validate_container_state(self.docker_id)

        ip_list = [self._assign_container_ip()]

        # Create Endpoint object
        try:
            logger.info("Creating endpoint with IPs %s", ip_list)
            ep = self._datastore_client.create_endpoint(HOSTNAME, ORCHESTRATOR_ID,
                                                        self.docker_id, ip_list)
        except (AddrFormatError, KeyError):
            logger.exception("Failed to create endpoint with IPs %s. Unassigning "
                             "IP address, then exiting.", ip_list)
            self._datastore_client.release_ips(set(ip_list))
            sys.exit(1)

        # Create the veth, move into the container namespace, add the IP and
        # set up the default routes.
        logger.info("Creating the veth with namespace pid %s on interface name %s", pid, interface)
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
        if CALICO_IPAM == 'true':
            # Assign ip address through IPAM Client
            logger.info("Using Calico IPAM")
            try:
                ip_list, ipv6_addrs = self._datastore_client.auto_assign_ips(
                    1, 0, self.docker_id, None)
                ip = ip_list[0]
                logger.debug("ip_list is %s; ipv6_addrs is %s", ip_list, ipv6_addrs)
                assert not ipv6_addrs
            except RuntimeError as err:
                logger.error("Cannot auto assign IPAddress: %s", err.message)
                sys.exit(1)

        else:
            logger.info("Using docker assigned IP address")
            ip = self._read_docker_ip()
            try:
                self._datastore_client.assign_ip(ip, str(self.docker_id), None)
            except (ValueError, RuntimeError, AlreadyAssignedError):
                logger.exception("Cannot assign IPAddress %s", ip)
                sys.exit(1)

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
            logger.exception("Container %s doesn't contain any endpoints", self.docker_id)
            sys.exit(1)

        # Remove any IP address assignments that this endpoint has
        ip_set = set()
        for net in endpoint.ipv4_nets | endpoint.ipv6_nets:
            ip_set.add(net.ip)
        logger.info("Removing IP addresses %s from endpoint %s", ip_set, endpoint.name)
        self._datastore_client.release_ips(ip_set)

        # Remove the veth interface from endpoint
        logger.info("Removing veth interface from endpoint %s", endpoint.name)
        try:
            netns.remove_veth(endpoint.name)
        except CalledProcessError:
            logger.exception("Could not remove veth interface from endpoint %s",
                           endpoint.name)

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
            logger.error("Can't add the container to Calico because it is running NetworkMode = host.")
            sys.exit(1)

    def _get_container_info(self, container_name):
        try:
            info = self._docker_client.inspect_container(container_name)
        except APIError as e:
            if e.response.status_code == 404:
                logger.error("Container %s was not found. Exiting.", container_name)
            else:
                logger.error(e.message)
            sys.exit(1)
        return info

    def _get_container_pid(self, container_name):
        return self._get_container_info(container_name)["State"]["Pid"]

    def _read_docker_ip(self):
        """Get the IP for the pod's infra container."""
        ip = self._get_container_info(self.docker_id)["NetworkSettings"]["IPAddress"]
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
                             'configure networking for pod %s. Exiting' % (self.pod_name))
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

        # Reach into the netns and delete the docker-allocated interface.
        logger.debug(check_output(['ip', 'netns', 'exec', pid,
                                  'ip', 'link', 'del', 'eth0']))

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
        logger.debug('Got pods %s' % pods)

        for pod in pods:
            logger.debug('Processing pod %s', pod)
            if pod['metadata']['namespace'].replace('/', '_') == self.namespace and \
                pod['metadata']['name'].replace('/', '_') == self.pod_name:
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
        logger.info('Getting API Resource: %s from KUBE_API_ROOT: %s', path, KUBE_API_ROOT)
        bearer_token = self._get_api_token()
        session = requests.Session()
        session.headers.update({'Authorization': 'Bearer ' + bearer_token})
        response = session.get(KUBE_API_ROOT + path, verify=False)
        response_body = response.text

        # The response body contains some metadata, and the pods themselves
        # under the 'items' key.
        return json.loads(response_body)['items']

    def _get_api_token(self):
        """
        Get the kubelet Bearer token for this node, used for HTTPS auth.
        If no token exists, this method will return an empty string.
        :return: The token.
        :rtype: str
        """
        logger.info('Getting Kubernetes Authorization')
        try:
            with open('/var/lib/kubelet/kubernetes_auth') as f:
                json_string = f.read()
        except IOError as e:
            logger.info("Failed to open auth_file (%s), assuming insecure mode" % e)
            return ""

        logger.info('Got kubernetes_auth: ' + json_string)
        auth_data = json.loads(json_string)
        return auth_data['BearerToken']

    def _generate_rules(self, pod):
        """
        Generate Rules takes human readable policy strings in annotations
        and creates argument arrays for calicoctl

        :return two lists of rules(arg lists): inbound list of rules (arg lists)
        outbound list of rules (arg lists)
        """

        ns_tag = self._get_namespace_tag(pod)

        # kube-system services need to be accessed by all namespaces
        if self.namespace == "kube-system" :
            logger.info("Pod %s belongs to the kube-system namespace - "
                        "allow all inbound and outbound traffic", pod)
            return [["allow"]], [["allow"]]

        if self.namespace and DEFAULT_POLICY == 'ns_isolation':
            inbound_rules = [["allow", "from", "tag", ns_tag]]
            outbound_rules = [["allow"]]
        else:
            inbound_rules = [["allow"]]
            outbound_rules = [["allow"]]

        logger.info("Getting Policy Rules from Annotation of pod %s", pod)

        annotations = self._get_metadata(pod, "annotations")

        # Find policy block of annotations
        if annotations and POLICY_ANNOTATION_KEY in annotations:
            # Remove Default Rule (Allow Namespace)
            inbound_rules = []
            rules = annotations[POLICY_ANNOTATION_KEY]

            # Rules separated by semicolons
            for rule in rules.split(";"):
                args = rule.split(" ")

                # Labels are declared in the annotations with the format 'label X=Y'
                # These must be converted into format 'tag NAMSPACE_X_Y' to be parsed by calicoctl.
                if 'label' in args:
                    # Replace arg 'label' with arg 'tag'
                    label_ind = args.index('label')
                    args[label_ind] = 'tag'

                    # Split given label 'key=value' into components 'key', 'value'
                    label = args[label_ind + 1]
                    key, value = label.split('=')

                    # Compose Calico tag out of key, value components
                    tag = self._label_to_tag(key, value)
                    args[label_ind + 1] = tag

                # Remove empty strings and add to rule list
                args = filter(None, args)
                inbound_rules.append(args)

        return inbound_rules, outbound_rules

    def _apply_rules(self, pod):
        """
        Generate a rules for a given profile based on annotations.
        1) Remove Calicoctl default rules
        2) Create new profiles based on annotations, and establish new defaults

        Exceptions:
            If namespace = kube-system (internal kube services), allow all traffic
            If no policy in annotations, allow from pod's Namespace
            Outbound policy should allow all traffic

        :param pod: pod info to parse
        :type pod: dict()
        :return:
        """
        try:
            profile = self._datastore_client.get_profile(self.profile_name)
        except:
            logger.exception("ERROR: Could not apply rules. Profile not found: %s, exiting", self.profile_name)
            sys.exit(1)

        inbound_rules, outbound_rules = self._generate_rules(pod)

        logger.info("Removing Default Rules")

        # TODO: This method is append-only, not profile replacement, we need to replace calicoctl calls
        #       but necessary functions are not available in pycalico ATM

        # Remove default rules. Assumes 2 in, 1 out.
        try:
            self.calicoctl('profile', self.profile_name, 'rule', 'remove', 'inbound', '--at=2')
            self.calicoctl('profile', self.profile_name, 'rule', 'remove', 'inbound', '--at=1')
            self.calicoctl('profile', self.profile_name, 'rule', 'remove', 'outbound', '--at=1')
        except sh.ErrorReturnCode as e:
            logger.error('Could not delete default rules for profile %s '
                         '(assumed 2 inbound, 1 outbound)\n%s', self.profile_name, e)

        # Call calicoctl to populate inbound rules
        for rule in inbound_rules:
            logger.info('applying inbound rule \n%s', rule)
            try:
                self.calicoctl('profile', self.profile_name, 'rule', 'add', 'inbound', rule)
            except sh.ErrorReturnCode as e:
                logger.error('Could not apply inbound rule %s.\n%s', rule, e)

        # Call calicoctl to populate outbound rules
        for rule in outbound_rules:
            logger.info('applying outbound rule \n%s' % rule)
            try:
                self.calicoctl('profile', self.profile_name, 'rule', 'add', 'outbound', rule)
            except sh.ErrorReturnCode as e:
                logger.error('Could not apply outbound rule %s.\n%s', rule, e)

        logger.info('Finished applying rules.')

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
            logger.error('Could not apply tags. Profile %s could not be found. Exiting', self.profile_name)
            sys.exit(1)

        # Grab namespace and create a tag if it exists.
        ns_tag = self._get_namespace_tag(pod)

        if ns_tag:
            logger.info('Adding tag %s' % ns_tag)
            profile.tags.add(ns_tag)
        else:
            logger.warning('Namespace tag cannot be generated')

        # Create tags from labels
        labels = self._get_metadata(pod, 'labels')
        if labels:
            for k, v in labels.iteritems():
                tag = self._label_to_tag(k, v)
                logger.info('Adding tag ' + tag)
                profile.tags.add(tag)
        else:
            logger.warning('No labels found in pod %s' % pod)

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

        logger.debug("%s of pod %s:\n%s", key, pod, val)
        return val

    def _escape_chars(self, unescaped_string):
        """
        Calico can only handle 3 special chars, '_.-'
        This function uses regex sub to replace SCs with '_'
        """
        # Character to replace symbols
        swap_char = '_'

        # If swap_char is in string, double it.
        unescaped_string = re.sub(swap_char, "%s%s" % (swap_char, swap_char), unescaped_string)

        # Substitute all invalid chars.
        return re.sub('[^a-zA-Z0-9\.\_\-]', swap_char, unescaped_string)

    def _get_namespace_tag(self, pod):
        """
        Pull metadata for namespace and return it and a generated NS tag
        """
        ns_tag = self._escape_chars('%s=%s' % ('namespace', self.namespace))
        return ns_tag

    def _label_to_tag(self, label_key, label_value):
        """
        Labels are key-value pairs, tags are single strings. This function handles that translation
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


if __name__ == '__main__':
    configure_logger(logger, LOG_LEVEL, True)
    configure_logger(pycalico_logger, LOG_LEVEL, False)

    mode = sys.argv[1]

    if mode == 'init':
        logger.info('No initialization work to perform')
    else:
        # These args only present for setup/teardown.
        namespace = sys.argv[2].replace('/', '_')
        pod_name = sys.argv[3].replace('/', '_')
        docker_id = sys.argv[4]

        logger.info('Args: %s' % sys.argv)
        logger.info("Using LOG_LEVEL=%s", LOG_LEVEL)
        logger.info("Using ETCD_AUTHORITY=%s", os.environ[ETCD_AUTHORITY_ENV])
        logger.info("Using CALICOCTL_PATH=%s", CALICOCTL_PATH)
        logger.info("Using KUBE_API_ROOT=%s", KUBE_API_ROOT)
        logger.info("Using CALICO_IPAM=%s", CALICO_IPAM)
        logger.info("Using DEFAULT_POLICY=%s", DEFAULT_POLICY)

        if mode == 'setup':
            logger.info('Executing Calico pod-creation hook')
            NetworkPlugin().create(namespace, pod_name, docker_id)
        elif mode == 'teardown':
            logger.info('Executing Calico pod-deletion hook')
            NetworkPlugin().delete(namespace, pod_name, docker_id)
        elif mode == 'status':
            logger.info('Executing Calico pod-status hook')
            NetworkPlugin().status(namespace, pod_name, docker_id)
