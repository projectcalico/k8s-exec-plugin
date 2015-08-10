#!/bin/python
import json
import os
import sys
from docker import Client
from docker.errors import APIError
from subprocess import check_output, CalledProcessError, check_call
import requests
from urllib import quote
import sh
import re
from pycalico.datastore import IF_PREFIX, DatastoreClient
from pycalico.util import generate_cali_interface_name, get_host_ips
from pycalico.datastore_datatypes import Rules

DOCKER_VERSION = "1.16"

ETCD_AUTHORITY_ENV = "ETCD_AUTHORITY"
if ETCD_AUTHORITY_ENV not in os.environ:
    os.environ[ETCD_AUTHORITY_ENV] = 'kubernetes-master:6666'
print("Using ETCD_AUTHORITY=%s" % os.environ[ETCD_AUTHORITY_ENV])

# Append to existing env, to avoid losing PATH etc.
# Need to edit the path here since calicoctl loads client on import.
CALICOCTL_PATH = os.environ.get('CALICOCTL_PATH', '/usr/bin/calicoctl')
print("Using CALICOCTL_PATH=%s" % CALICOCTL_PATH)

KUBE_API_ROOT = os.environ.get('KUBE_API_ROOT',
                               'http://kubernetes-master:8080/api/v1/')
print("Using KUBE_API_ROOT=%s" % KUBE_API_ROOT)


class NetworkPlugin(object):

    def __init__(self):
        self.pod_name = None
        self.docker_id = None
        self._datastore_client = DatastoreClient()
        self.calicoctl = sh.Command(CALICOCTL_PATH).bake(_env=os.environ)
        self._docker_client = Client(
            version=DOCKER_VERSION,
            base_url=os.getenv("DOCKER_HOST", "unix://var/run/docker.sock"))

    def create(self, pod_name, docker_id):
        """"Create a pod."""
        # Calicoctl does not support the '-' character in iptables rule names.
        # TODO: fix Felix to support '-' characters.
        self.pod_name = pod_name
        self.docker_id = docker_id

        print('Configuring docker container %s' % self.docker_id)

        try:
            endpoint = self._configure_interface()
            self._configure_profile(endpoint)
        except CalledProcessError as e:
            print('Error code %d creating pod networking: %s\n%s' % (
                e.returncode, e.output, e))
            sys.exit(1)

    def delete(self, pod_name, docker_id):
        """Cleanup after a pod."""
        self.pod_name = pod_name
        self.docker_id = docker_id

        print('Deleting container %s with profile %s' %
            (self.docker_id, self.pod_name))

        # Remove the profile for the workload.
        self.calicoctl('container', 'remove', self.docker_id)

        # Delete profile
        try:
            self._datastore_client.remove_profile(self.pod_name)
        except:
            print "Cannot remove profile %s; Profile cannot be found." % self.pod_name

    def _configure_profile(self, endpoint):
        """
        Configure the calico profile for a pod.

        Currently assumes one pod with each name.
        """
        profile_name = self.pod_name
        print('Configuring Pod Profile: %s' % profile_name)

        if self._datastore_client.profile_exists(profile_name):
            print "Error: Profile with name %s already exists, exiting." % profile_name
            sys.exit(1)
        else:
            self._datastore_client.create_profile(profile_name)

        pod = self._get_pod_config()

        self._apply_rules(profile_name, pod)

        self._apply_tags(profile_name, pod)

        # Also set the profile for the workload.
        print('Setting profile %s on endpoint %s' %
              (profile_name, endpoint.endpoint_id))
        self._datastore_client.set_profiles_on_endpoint(
            profile_name, endpoint_id=endpoint.endpoint_id
        )
        print('Finished configuring profile.')

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
        container_ip = self._read_docker_ip()
        container_id = self._get_container_id(self.docker_id)
        self._delete_docker_interface()
        print('Configuring Calico network interface')
        self.calicoctl('container', 'add', self.docker_id, container_ip, '--interface=eth0')
        ep = self._datastore_client.get_endpoint(workload_id=container_id)
        interface_name = generate_cali_interface_name(IF_PREFIX, ep.endpoint_id)
        node_ip = self._get_node_ip()
        print('Adding IP %s to interface %s' % (node_ip, interface_name))

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
        print('Finished configuring network interface')
        return ep

    def _get_node_ip(self):
        """
        Determine the IP for the host node.
        """
        # Compile list of addresses on network, return the first entry.
        # Try IPv4 and IPv6.
        addrs = get_host_ips(version=4) or get_host_ips(version=6)

        try:
            addr = addrs[0]
            print('Using IP Address %s' % (addr))
            return addr
        except IndexError:
            # If both get_host_ips return empty lists, print message and exit.
            print('Error: No Valid IP Address Found for Host - cannot configure networking for pod %s. Exiting' % (self.pod_name))
            sys.exit(1)

    def _read_docker_ip(self):
        """Get the IP for the pod's infra container."""
        ip = check_output([
            'docker', 'inspect', '-format', '{{ .NetworkSettings.IPAddress }}',
            self.docker_id
        ])
        # Clean trailing whitespace (expect a '\n' at least).
        ip = ip.strip()

        print('Docker-assigned IP was %s' % ip)
        return ip

    def _delete_docker_interface(self):
        """Delete the existing veth connecting to the docker bridge."""
        print('Deleting docker interface eth0')

        # Get the PID of the container.
        pid = check_output([
            'docker', 'inspect', '-format', '{{ .State.Pid }}',
            self.docker_id
        ])
        # Clean trailing whitespace (expect a '\n' at least).
        pid = pid.strip()
        print('Container %s running with PID %s' % (self.docker_id, pid))

        # Set up a link to the container's netns.
        print("Linking to container's netns")
        print(check_output(['mkdir', '-p', '/var/run/netns']))
        netns_file = '/var/run/netns/' + pid
        if not os.path.isfile(netns_file):
            print(check_output(['ln', '-s', '/proc/' + pid + '/ns/net',
                                netns_file]))

        # Reach into the netns and delete the docker-allocated interface.
        print(check_output(['ip', 'netns', 'exec', pid,
                            'ip', 'link', 'del', 'eth0']))

        # Clean up after ourselves (don't want to leak netns files)
        print(check_output(['rm', netns_file]))

    def _get_pod_ports(self, pod):
        """
        Get the list of ports on containers in the Pod.

        :return list ports: the Kubernetes ContainerPort objects for the pod.
        """
        ports = []
        for container in pod['spec']['containers']:
            try:
                more_ports = container['ports']
                print('Adding ports %s' % more_ports)
                ports.extend(more_ports)
            except KeyError:
                pass
        return ports

    def _get_pod_config(self):
        """Get the list of pods from the Kube API server."""
        pods = self._get_api_path('pods')
        print('Got pods %s' % pods)

        for pod in pods:
            print('Processing pod %s' % pod)
            if pod['metadata']['name'].replace('/', '_') == self.pod_name:
                this_pod = pod
                break
        else:
            raise KeyError('Pod not found: ' + self.pod_name)
        print('Got pod data %s' % this_pod)
        return this_pod

    def _get_api_path(self, path):
        """Get a resource from the API specified API path.

        e.g.
        _get_api_path('pods')

        :param path: The relative path to an API endpoint.
        :return: A list of JSON API objects
        :rtype list
        """
        print('Getting API Resource: %s from KUBE_API_ROOT: %s' % (path, KUBE_API_ROOT))
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
        print('Getting Kubernetes Authorization')
        try:
            with open('/var/lib/kubelet/kubernetes_auth') as f:
                json_string = f.read()
        except IOError as e:
            print("Failed to open auth_file (%s), assuming insecure mode" % e)
            return ""

        print('Got kubernetes_auth: ' + json_string)
        auth_data = json.loads(json_string)
        return auth_data['BearerToken']

    def _generate_rules(self, pod):
        """
        Generate Rules takes human readable policy strings in annotations
        and creates argument arrays for calicoctl

        :return two lists of rules(arg lists): inbound list of rules (arg lists)
        outbound list of rules (arg lists)
        """

        namespace, ns_tag = self._get_namespace_and_tag(pod)

        # kube-system services need to be accessed by all namespaces
        if namespace == "kube-system" :
            print "using kube-system, allow all"
            return [["allow"]], [["allow"]]

        inbound_rules = [
            ["allow", "from", "tag", ns_tag]
        ]

        outbound_rules = [
            ["allow"]
        ]

        print("Getting Policy Rules from Annotation of pod %s" % pod)

        annotations = self._get_metadata(pod, "annotations")

        # Find policy block of annotations
        if annotations and "policy" in annotations.keys():
            # Remove Default Rule (Allow Namespace)
            inbound_rules = []
            rules = annotations["policy"]

            # Rules separated by semicolons
            for rule in rules.split(";"):
                args = rule.split(" ")

                # Replace labels with tags
                # key=value -> namespace_key_value
                # TODO: account for improper formatting
                if 'label' in args:
                    label_ind = args.index('label')
                    args[label_ind] = 'tag'
                    label = args[label_ind + 1]
                    key, value = label.split('=')
                    tag = self._label_to_tag(key, value, namespace)
                    args[label_ind + 1] = tag

                # Remove null args and add to rule list
                args = filter(None, args)
                inbound_rules.append(args)

        return inbound_rules, outbound_rules

    def _generate_profile_json(self, profile_name, rules):
        """
        DEPRECIATED: Not used in current semantic annotation format
        Given a list of of Calico rules, generate a Calico Profile JSON blob
        implementing those rules.

        :param profile_name: The name of the Calico profile
        :type profile_name: string
        :param rules: A tuple of (inbound, outbound) Calico rules
        :type rules: tuple
        :return: A JSON blob ready to be loaded by calicoctl
        :rtype: str
        """
        inbound, outbound = rules
        profile = {
            'id': profile_name,
            'inbound_rules': inbound,
            'outbound_rules': outbound,
        }
        profile_json = json.dumps(profile, indent=2)
        print('Final profile "%s":\n%s' % (profile_name, profile_json))
        return profile_json

    def _apply_rules(self, profile_name, pod):
        """
        Generate a new profile with the default 'allow all' rules.

        :param profile_name: The profile to update
        :type profile_name: string
        :return:
        """
        try:
            profile = self._datastore_client.get_profile(profile_name)
        except:
            print("Error: Could not apply rules. Profile not found: %s, exiting" % profile_name)
            sys.exit(1)

        inbound_rules, outbound_rules = self._generate_rules(pod)

        print "Removing Default Rules"

        # TODO: This method is append-only, not profile replacement, we need to remove default rules
        # TODO: remove calicoctl calls (x5)
        try:
            self.calicoctl('profile', profile_name, 'rule', 'remove', 'inbound', '--at=2')
            self.calicoctl('profile', profile_name, 'rule', 'remove', 'inbound', '--at=1')
            self.calicoctl('profile', profile_name, 'rule', 'remove', 'outbound', '--at=1')
        except sh.ErrorReturnCode as e:
            print('Could not delete default rules for profile %s (assumed 2 inbound, 1 outbound)\n%s' % (profile_name, e))

        for rule in inbound_rules:
            print 'applying inbound rule \n%s' % rule
            try:
                self.calicoctl('profile', profile_name, 'rule', 'add', 'inbound', rule)
            except sh.ErrorReturnCode as e:
                print('Could not create rule %s.\n%s' % (rule, e))

        for rule in outbound_rules:
            print 'applying outbound rule \n%s' % rule
            try:
                self.calicoctl('profile', profile_name, 'rule', 'add', 'outbound', rule)
            except sh.ErrorReturnCode as e:
                print('Could not create rule %s.\n%s' % (rule, e))

        print('Finished applying rules.')

    def _apply_tags(self, profile_name, pod):
        """
        Extract the label KV pairs from the pod config, and apply each as a
        tag in the pod's profile.

        :param profile_name: The name of the Calico profile.
        :type profile_name: string
        :param pod: The config dictionary for the pod being created.
        :type pod: dict
        :return:
        """
        print('Applying tags')

        try:
            profile = self._datastore_client.get_profile(profile_name)
        except KeyError:
            print('Error: Could not apply tags. Profile %s could not be found. Exiting' % profile_name)
            sys.exit(1)

        # Grab namespace and create a tag if it exists.
        namespace, ns_tag = self._get_namespace_and_tag(pod)

        if ns_tag:
            print('Adding tag %s' % ns_tag)
            profile.tags.add(ns_tag)

        # Create tags from labels
        labels = self._get_metadata(pod, 'labels')
        if labels:
            for k, v in labels.iteritems():
                tag = self._label_to_tag(k, v, namespace)
                print('Adding tag ' + tag)
                profile.tags.add(tag)
        else:
            print('No labels found in pod %s' % pod)

        self._datastore_client.profile_update_tags(profile)

        print('Finished applying tags.')

    def _get_metadata(self, pod, key):
        """
        Return Metadata[key] Object given Pod
        Returns None if no key-value exists
        """
        try:
            val = pod['metadata'][key]
        except KeyError:
            print('No %s found in pod %s' % (key, pod))
            return None

        print("%s of pod %s:\n%s" % (key, pod, val))
        return val

    def _escape_chars(self, unescaped_string):
        """
        Calico can only handle 3 special chars, '_.-'
        This function uses regex sub to replace SCs with '_'
        """
        escape_seq = '_'
        return re.sub('[^a-zA-Z0-9\.-]', escape_seq, unescaped_string)

    def _get_namespace_and_tag(self, pod):
        namespace = self._get_metadata(pod, 'namespace')
        ns_tag = self._escape_chars('%s=%s' % ('namespace', namespace)) if namespace else None
        return namespace, ns_tag

    def _label_to_tag(self, label_key, label_value, namespace):
        """
        Labels are key-value pairs, tags are single strings. This function handles that translation
        1) concatenate key and value with '='
        2) prepend a pod's namespace followed by '/' if available
        3) replace special characters with urllib-style escape sequence
        :param label_key: key to label
        :param label_value: value to given key for a label
        :param namespace: Namespace string, input None if not available
        :param types: (self, string, string, string)
        :return single string tag
        :rtype string
        """
        tag = '%s=%s' % (label_key, label_value)
        tag = '%s/%s' % (namespace, tag) if namespace else tag
        tag = self._escape_chars(tag)
        return tag

    def _get_container_id(self, container_name):
        try:
            info = self._docker_client.inspect_container(container_name)
        except APIError as e:
            if e.response.status_code == 404:
                print("Error: Could not get container ID for %s. Exiting." % container_name)
            else:
                print(e.message)
            sys.exit(1)
        return info["Id"]

if __name__ == '__main__':
    print('Args: %s' % sys.argv)
    mode = sys.argv[1]

    if mode == 'init':
        print('No initialization work to perform')
    else:
        # These args only present for setup/teardown.
        pod_name = sys.argv[3].replace('/', '_')
        docker_id = sys.argv[4]
        if mode == 'setup':
            print('Executing Calico pod-creation hook')
            NetworkPlugin().create(pod_name, docker_id)
        elif mode == 'teardown':
            print('Executing Calico pod-deletion hook')
            NetworkPlugin().delete(pod_name, docker_id)
