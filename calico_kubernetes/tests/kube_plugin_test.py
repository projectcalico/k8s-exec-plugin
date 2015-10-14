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
import os
import sys
import json
import logging
import unittest

from mock import patch, Mock, MagicMock, call
from nose_parameterized import param
from nose.tools import assert_equal, assert_true, assert_false
from docker.errors import APIError
from netaddr import IPAddress, IPNetwork
from subprocess import CalledProcessError
from docker.errors import APIError
from nose.tools import assert_equal
from nose_parameterized import parameterized

from calico_kubernetes import calico_kubernetes, logutils
from pycalico.datastore import IF_PREFIX
from pycalico.block import AlreadyAssignedError
from pycalico.datastore_datatypes import Profile, Endpoint

# noinspection PyProtectedMember
from calico_kubernetes.calico_kubernetes import _log_interfaces, POLICY_ANNOTATION_KEY
from calico_kubernetes.logutils import ROOT_LOG_FORMAT, LOG_FORMAT

# noinspection PyUnresolvedReferences
patch_object = patch.object

TEST_HOST = calico_kubernetes.HOSTNAME
TEST_ORCH_ID = calico_kubernetes.ORCHESTRATOR_ID

_log = logging.getLogger(__name__)


class NetworkPluginTest(unittest.TestCase):

    def setUp(self):
        # Mock out sh so it doesn't fail when trying to find the
        # calicoctl binary (which may not exist)
        with patch('calico_kubernetes.calico_kubernetes.sh.Command',
                   autospec=True) as m_sh:
            self.plugin = calico_kubernetes.NetworkPlugin()

            # Datastore and Docker Clients should be mocked
            self.m_datastore_client = MagicMock(autospec=True)
            self.plugin._datastore_client = self.m_datastore_client
            self.m_docker_client = MagicMock(autospec=True)
            self.plugin._docker_client = self.m_docker_client

    def test_create(self):
        """Test Pod Creation Hook"""
        with patch_object(self.plugin, '_configure_interface',
                          autospec=True) as m_configure_interface, \
                patch_object(self.plugin, '_configure_profile',
                             autospec=True) as m_configure_profile:
            # Set up mock objects
            m_configure_interface.return_value = 'endpt_id'

            # Set up args
            namespace = 'ns'
            pod_name = 'pod1'
            docker_id = 123456789101112
            profile_name = 'ns_pod1_123456789101'

            # Call method under test
            self.plugin.create(namespace, pod_name, docker_id)

            # Assert
            assert_equal(namespace, self.plugin.namespace)
            assert_equal(pod_name, self.plugin.pod_name)
            assert_equal(docker_id, self.plugin.docker_id)
            assert_equal(profile_name, self.plugin.profile_name)
            m_configure_interface.assert_called_once_with()
            m_configure_profile.assert_called_once_with('endpt_id')

    def test_create_error(self):
        """Test Pod Creation Hook Failure"""
        with patch_object(self.plugin, '_configure_interface',
                          autospec=True) as m_configure_interface:
            # Set up mock objects
            m_configure_interface.side_effect = CalledProcessError(1,'','')

            # Set up args
            namespace = 'ns'
            pod_name = 'pod1'
            docker_id = 13

            # Call method under test
            self.assertRaises(
                SystemExit, self.plugin.create, namespace, pod_name, docker_id)

    def test_delete(self):
        """Test Pod Deletion Hook"""
        with patch_object(self.plugin, '_container_remove', autospec=True) as m_container_remove:
            # Set up mock objs
            self.m_datastore_client.profile_exists.return_value = True

            # Set up args
            namespace = 'ns'
            pod_name = 'pod1'
            docker_id = 123456789101112
            profile_name = 'ns_pod1_123456789101'

            # Call method under test
            self.plugin.delete(namespace, pod_name, docker_id)

            # Assert
            m_container_remove.assert_called_once_with()
            assert_equal(namespace, self.plugin.namespace)
            assert_equal(pod_name, self.plugin.pod_name)
            assert_equal(docker_id, self.plugin.docker_id)
            assert_equal(profile_name, self.plugin.profile_name)
            self.m_datastore_client.remove_profile(profile_name)

    def test_delete_error(self):
        """Test Pod Deletion Hook Failure"""
        """
        If the datastore remove_profile function returns KeyError, the profile is not in the datastore.
        Issue warning log, but do not fail.
        """
        with patch_object(self.plugin, '_container_remove', autospec=True) as m_container_remove:
            # Set up mock objs
            self.m_datastore_client.profile_exists.return_value = True
            self.m_datastore_client.remove_profile.side_effect = KeyError

            # Set up args
            namespace = 'ns'
            pod_name = 'pod1'
            docker_id = 123456789101112
            profile_name = 'ns_pod1_123456789101'

            # Call method under test
            self.plugin.delete(namespace, pod_name, docker_id)

    @patch('__builtin__.print', autospec=True)
    def test_status(self, m_print):
        """Test Pod Status Hook"""
        # Set up args
        namespace = 'ns'
        pod_name = 'pod1'
        docker_id = 123456789101112

        # Call method under test
        endpoint = Endpoint(TEST_HOST, TEST_ORCH_ID, '1234', '5678',
                            'active', 'mac')
        ipv4 = IPAddress('1.1.1.1')
        ipv4_2 = IPAddress('1.1.1.2')
        ipv6 = IPAddress('201:db8::')
        endpoint.ipv4_nets.add(IPNetwork(ipv4))
        endpoint.ipv4_nets.add(IPNetwork(ipv4_2))
        endpoint.ipv6_nets.add(IPNetwork(ipv6))
        self.m_datastore_client.get_endpoint.return_value = endpoint

        json_dict = {
            "apiVersion": "v1beta1",
            "kind": "PodNetworkStatus",
            "ip": "1.1.1.2"
        }

        self.plugin.status(namespace, pod_name, docker_id)
        self.m_datastore_client.get_endpoint.assert_called_once_with(hostname=TEST_HOST,
                                                                     orchestrator_id=TEST_ORCH_ID,
                                                                     workload_id=docker_id)
        m_print.assert_called_once_with(json.dumps(json_dict))

    @patch('__builtin__.print', autospec=True)
    def test_status_no_ip(self, m_print):
        """Test Pod Status Hook: No IP on Endpoint"""
        """
        Test for sys exit when endpoint ipv4_nets is empty.
        """
        # Set up args
        namespace = 'ns'
        pod_name = 'pod1'
        docker_id = 123456789101112

        # Call method under test
        endpoint = Endpoint(TEST_HOST, TEST_ORCH_ID, '1234', '5678',
                            'active', 'mac')
        endpoint.ipv4_nets = None
        endpoint.ipv6_nets = None
        self.m_datastore_client.get_endpoint.return_value = endpoint

        self.assertRaises(
            SystemExit, self.plugin.status, namespace, pod_name, docker_id)

        assert_false(m_print.called)

    @patch('__builtin__.print', autospec=True)
    def test_status_ep_error(self, m_print):
        """Test Pod Status Hook: Endpoint Retrieval Error"""
        """
        Test for sys exit when get_endpoint returns an error.
        """
        # Set up args
        namespace = 'ns'
        pod_name = 'pod1'
        docker_id = 123456789101112

        self.m_datastore_client.get_endpoint.side_effect = KeyError

        self.assertRaises(
            SystemExit, self.plugin.status, namespace, pod_name, docker_id)

        assert_false(m_print.called)

    def test_configure_interface(self):
        with patch_object(self.plugin, '_read_docker_ip',
                          autospec=True) as m_read_docker_ip, \
                patch_object(self.plugin, '_get_container_pid', autospec=True) as m_get_container_pid, \
                patch_object(self.plugin, '_delete_docker_interface',
                             autospec=True) as m_delete_docker_interface, \
                patch_object(self.plugin, '_container_add',
                             autospec=True) as m_container_add, \
                patch_object(calico_kubernetes, 'generate_cali_interface_name',
                             autospec=True) as m_generate_cali_interface_name, \
                patch_object(self.plugin, '_get_node_ip',
                             autospec=True) as m_get_node_ip, \
                patch_object(calico_kubernetes, 'check_call',
                             autospec=True) as m_check_call, \
                patch('calico_kubernetes.tests.kube_plugin_test.'
                      'calico_kubernetes._log_interfaces',
                      autospec=True) as _:
            # Set up mock objects
            m_get_container_pid.return_value = 'container_pid'
            m_read_docker_ip.return_value = IPAddress('1.1.1.1')
            endpoint = Endpoint(TEST_HOST, TEST_ORCH_ID, '1234', '5678',
                                'active', 'mac')
            m_container_add.return_value = endpoint
            m_generate_cali_interface_name.return_value = 'interface_name'
            m_get_node_ip.return_value = '1.2.3.4'

            # Set up args
            self.plugin.pod_name = 'pod1'
            container_name = 'container1'
            self.plugin.docker_id = container_name

            # Call method under test
            return_val = self.plugin._configure_interface()

            # Assert
            m_get_container_pid.assert_called_once_with(container_name)
            m_delete_docker_interface.assert_called_once_with()
            m_container_add.assert_called_once_with('container_pid', 'eth0')
            m_generate_cali_interface_name.assert_called_once_with(
                IF_PREFIX, endpoint.endpoint_id)
            m_get_node_ip.assert_called_once_with()
            m_check_call.assert_called_once_with(
                ['ip', 'addr', 'add', '1.2.3.4' + '/32',
                 'dev', 'interface_name'])
            assert_equal(return_val, endpoint)

    def test_container_add(self):
        with patch_object(self.plugin, '_validate_container_state',
                          autospec=True) as m_validate_container_state, \
                patch('calico_kubernetes.calico_kubernetes.netns.PidNamespace', autospec=True) as m_pid_ns, \
                patch_object(self.plugin, '_assign_container_ip', autospec=True) as m_assign_ip:
            # Set up mock objs
            self.m_datastore_client.get_endpoint.side_effect = KeyError
            endpoint = Endpoint(TEST_HOST, TEST_ORCH_ID, '1234', '5678',
                                'active', 'mac')
            endpoint.provision_veth = Mock()
            endpoint.provision_veth.return_value = 'new_mac'
            self.m_datastore_client.create_endpoint.return_value = endpoint

            # Set up arguments
            container_name = 'container_name'
            self.plugin.docker_id = container_name
            pid = 'pid'
            ip = IPAddress('1.1.1.1')
            interface = 'eth0'

            m_assign_ip.return_value = ip

            # Call method under test
            return_value = self.plugin._container_add(pid, interface)

            # Assert call parameters
            self.m_datastore_client.get_endpoint.assert_called_once_with(
                hostname=TEST_HOST,
                orchestrator_id=TEST_ORCH_ID,
                workload_id=self.plugin.docker_id
            )
            m_validate_container_state.assert_called_once_with(container_name)
            self.m_datastore_client.create_endpoint.assert_called_once_with(TEST_HOST,
                                                                            TEST_ORCH_ID,
                                                                            self.plugin.docker_id,
                                                                            [ip])
            self.m_datastore_client.set_endpoint.assert_called_once_with(
                endpoint)
            endpoint.provision_veth.assert_called_once_with(
                m_pid_ns(pid), interface)

            # Verify method output
            assert_equal(endpoint.mac, 'new_mac')
            assert_equal(return_value, endpoint)

    def test_container_add_create_error(self):
        """Test Endpoint Creation Error in _container_add"""
        """
        _container_add should release ips and exit when endpoint creation fails.
        """
        with patch_object(self.plugin, '_validate_container_state', autospec=True) as m_validate, \
                patch_object(self.plugin, '_assign_container_ip', autospec=True) as m_assign_ip:

            # Set up mock objs
            self.m_datastore_client.get_endpoint.side_effect = KeyError
            self.m_datastore_client.create_endpoint.side_effect = KeyError

            # Set up arguments
            pid = 'pid'
            ip = IPAddress('1.1.1.1')
            interface = 'eth0'
            m_assign_ip.return_value = ip

            self.assertRaises(
                SystemExit, self.plugin._container_add, pid, interface)

            # Assert
            self.m_datastore_client.release_ips.assert_called_once_with(
                set([ip]))
            assert_false(self.m_datastore_client.set_endpoint.called)


    def test_container_add_container_exists(self):
        """
        Test _container_add method when container already exists.

        Expect system exit.
        """
        # Set up arguments
        pid = 'pid'
        interface = 'eth0'

        # Call method under test
        self.assertRaises(
            SystemExit, self.plugin._container_add, pid, interface)

    @patch('calico_kubernetes.calico_kubernetes.netns.remove_veth', autospec=True)
    def test_container_remove(self, m_remove_veth):
        # Set up mock objs
        endpoint = Endpoint(TEST_HOST, TEST_ORCH_ID, '1234', '5678',
                            'active', 'mac')
        ipv4 = IPAddress('1.1.1.1')
        ipv6 = IPAddress('201:db8::')
        endpoint.ipv4_nets.add(IPNetwork(ipv4))
        endpoint.ipv6_nets.add(IPNetwork(ipv6))
        self.m_datastore_client.get_endpoint.return_value = endpoint

        # Set up arguments
        self.plugin.docker_id = "abcd"
        hostname = TEST_HOST
        orchestrator_id = TEST_ORCH_ID

        # Call method under test
        self.plugin._container_remove()

        # Assert
        self.m_datastore_client.get_endpoint.assert_called_once_with(
            hostname=hostname,
            orchestrator_id=orchestrator_id,
            workload_id='abcd'
        )

        m_remove_veth.assert_called_once_with(endpoint.name)

    @patch('calico_kubernetes.calico_kubernetes.netns.remove_veth', autospec=True)
    def test_container_remove_with_exceptions(self, m_remove_veth):
        """Test Container Remove Exception Handling"""
        """
        Failures in remove_veth and remove_workload should gently raise exceptions without exit.
        """
        # Raise errors under test.
        m_remove_veth.side_effect = CalledProcessError(1, '', '')
        self.m_datastore_client.remove_workload.side_effect = KeyError

        self.plugin._container_remove()

    def test_container_remove_no_endpoints(self):
        """
        Test _container_remove when the container does not container any endpoints

        Expect a system exit
        """
        self.m_datastore_client.get_endpoint.side_effect = KeyError

        # Call method under test
        self.assertRaises(SystemExit, self.plugin._container_remove)

    def test_validate_container_state(self):
        with patch_object(self.plugin, '_get_container_info', autospec=True) as m_get_container_info:
            # Set up mock objs
            info_dict = {'State': {'Running': 1}, 'HostConfig': {'NetworkMode': ''}}
            m_get_container_info.return_value = info_dict

            # Call method under test
            self.plugin._validate_container_state('container_name')

            # Assert
            m_get_container_info.assert_called_once_with('container_name')
            assert_true(info_dict['State']['Running'])
            self.assertNotEqual(info_dict['HostConfig']['NetworkMode'], 'host')

    def test_validate_container_state_not_running(self):
        """
        Test _validate_container_state when the container is not running

        Expect system exit
        """
        with patch_object(self.plugin, '_get_container_info', autospec=True) as m_get_container_info:
            # Set up mock objs
            info_dict = {'State': {'Running': 0}, 'HostConfig': {'NetworkMode': ''}}
            m_get_container_info.return_value = info_dict

            # Call method under test
            self.assertRaises(SystemExit, self.plugin._validate_container_state,
                              'container_name')

    def test_valdiate_container_state_network_mode_host(self):
        """
        Test _validate_container_state when the network mode is host

        Expect system exit
        """
        with patch_object(self.plugin, '_get_container_info', autospec=True) as m_get_container_info:
            # Set up mock objs
            info_dict = {'State': {'Running': 1}, 'HostConfig': {'NetworkMode': 'host'}}
            m_get_container_info.return_value = info_dict

            # Call method under test
            self.assertRaises(SystemExit, self.plugin._validate_container_state,
                              'container_name')

    def test_get_container_info(self):
        # Set up args
        container_name = 'container_name'

        # Call method under test
        self.plugin._get_container_info(container_name)

        # Assert
        self.m_docker_client.inspect_container.assert_called_once_with(
            container_name)

    def test_get_container_info_docker_api_error(self):
        # Create mock side effect APIError
        self.m_docker_client.inspect_container.side_effect = APIError(
            'Error', Mock())

        # Set up args
        container_name = 'container_name'

        # Call method under test
        self.assertRaises(
            SystemExit, self.plugin._get_container_info, container_name)

    def test_get_container_info_404(self):
        """Test 404 error on API Access in _get_container_info"""
        """
        Method should raise SystemExit when API returns 404
        """
        # Create mock side effect APIError
        response = Mock()
        response.status_code = 404
        self.m_docker_client.inspect_container.side_effect = APIError(
            'Error', response)

        # Set up args
        container_name = 'container_name'

        # Call method under test
        self.assertRaises(
            SystemExit, self.plugin._get_container_info, container_name)

    def test_get_container_pid(self):
        with patch_object(self.plugin, '_get_container_info', autospec=True) as m_get_container_info:
            # Set up args
            container_name = 'container_name'

            # Call method under test
            self.plugin._get_container_pid(container_name)

            # Assert
            m_get_container_info.assert_called_once_with(container_name)

    def test_assign_container_ip_docker_already_assigned(self):
        """Test Duplicate IP assignment"""
        """
        When IP is already assigned, assert that all endpoints, ips and profiles are removed.
        """
        with patch.object(self.plugin, "_read_docker_ip") as m_read_ip:

            # Don't use CALICO_IPAM for this test.
            calico_kubernetes.CALICO_IPAM = "false"

            # Mock the Docker IP
            docker_ip = "172.12.23.4"
            m_read_ip.return_value = docker_ip

            # Mock out assignment - already assigned for first call,
            # not assigned on the second.
            self.m_datastore_client.assign_ip.side_effect = iter(
                [AlreadyAssignedError, None])

            endpoint = Mock()
            endpoint.ipv4_nets = [
                IPNetwork("1.1.1.1"), IPNetwork("172.12.23.4")]
            endpoint.profile_ids = ["p1", "p2"]
            self.m_datastore_client.get_endpoints.return_value = [endpoint]

            # Run method under test
            ip = self.plugin._assign_container_ip()

            self.m_datastore_client.get_endpoints.assert_called_once()
            self.m_datastore_client.remove_profile.has_calls([("p1"), ("p2")])
            self.m_datastore_client.release_ips.assert_called_once_with(
                set([docker_ip]))
            self.m_datastore_client.remove_endpoint.assert_called_once_with(
                endpoint)

            # Assert we return the IP we just deleted then readded.
            assert_equal(ip, docker_ip)

    def test_assign_container_ip_assign_error(self):
        """Test assign_container_ip sys exit on Runtime Error"""
        """
        Assert SystemExit when datastore client fails to allocate IP
        """
        with patch.object(self.plugin, "_read_docker_ip") as m_read_ip:

            # Don't use CALICO_IPAM for this test.
            calico_kubernetes.CALICO_IPAM = "false"

            # Mock the Docker IP
            docker_ip = "172.12.23.4"
            m_read_ip.return_value = docker_ip

            # Mock out assignment - already assigned for first call,
            # not assigned on the second.
            self.m_datastore_client.assign_ip.side_effect = RuntimeError

            # Run method under test
            self.assertRaises(SystemExit, self.plugin._assign_container_ip)

    def test_assign_container_ipam_succeed(self):
        """Test assign_container_ip with IPAM enabled"""
        """
        When IPAM is enabled, client should return a list of ips.
        Method should scrape off and return the first ipv4.
        """
        calico_kubernetes.CALICO_IPAM = "true"

        # Mock the Docker IP
        self.plugin.docker_id = "docker_id"
        self.m_datastore_client.auto_assign_ips.return_value = [1, 2], [3, 4]

        ip = self.plugin._assign_container_ip()

        self.m_datastore_client.auto_assign_ips.assert_called_once_with(
            1, 0, "docker_id", None)
        assert_equal(ip, 1)

    def test_assign_container_ipam_error(self):
        # Don't use CALICO_IPAM for this test.
        """Test assign_container_ip IPAM auto assign failure"""
        """
        Assert SystemExit when datastore client fails to allocate IP
        """
        calico_kubernetes.CALICO_IPAM = "true"

        # Mock the Docker IP
        self.plugin.docker_id = "docker_id"
        self.m_datastore_client.auto_assign_ips.side_effect = RuntimeError

        # Run method under test
        self.assertRaises(SystemExit, self.plugin._assign_container_ip)


    def test_get_node_ip_no_host_ips(self):
        """
        Test _get_nope_ip when get_host_ip does not return any ips

        Expect system exit
        """
        with patch('calico_kubernetes.calico_kubernetes.get_host_ips',
                   autospec=True) as m_get_host_ips:
            # Set up mock objects
            m_get_host_ips.return_value = ['1.2.3.4','4.2.3.4']

            # Call method under test
            return_val = self.plugin._get_node_ip()

            # Assert
            m_get_host_ips.assert_called_once_with(version=4)
            assert_equal(return_val, '1.2.3.4')

    def test_get_node_ip(self):
        with patch('calico_kubernetes.calico_kubernetes.get_host_ips',
                   autospec=True) as m_get_host_ips:
            # Set up mock objects
            m_get_host_ips.return_value = []

            # Call method under test
            self.assertRaises(SystemExit, self.plugin._get_node_ip)

    def test_read_docker_ip(self):
        with patch_object(self.plugin, '_get_container_info',
                          autospec=True) as m_get_container_info:
            # Set up mock objects
            m_get_container_info.return_value = {'NetworkSettings': {'IPAddress': '1.2.3.4'}}

            # Call method under test
            return_val = self.plugin._read_docker_ip()

            # Assert
            m_get_container_info.assert_called_once_with(self.plugin.docker_id)
            assert_equal(return_val, IPAddress('1.2.3.4'))

    def test_delete_docker_interface(self):
        with patch_object(calico_kubernetes, 'check_output',
                          autospec=True) as m_check_output, \
                patch_object(self.plugin, '_get_container_pid', autospec=True) as m_get_container_pid:
            # Set up mock objects
            m_get_container_pid.return_value = 'pid'

            # Call method under test
            self.plugin._delete_docker_interface()

            # Assert call list

            m_check_output.assert_has_calls([
                call(['mkdir', '-p', '/var/run/netns']),
                call(['ln', '-s', '/proc/' + 'pid' + '/ns/net', '/var/run/netns/pid']),
                call(['ip', 'netns', 'exec', 'pid', 'ip', 'link', 'del', 'eth0']),
                call(['rm', '/var/run/netns/pid'])
            ], any_order=True)

    def test_configure_profile(self):
        with patch_object(self.plugin, '_get_namespace_tag',
                          autospec=True) as m_get_namespace_tag, \
                patch_object(self.plugin, '_get_pod_config',
                             autospec=True) as m_get_pod_config, \
                patch_object(self.plugin, '_apply_rules',
                             autospec=True) as m_apply_rules, \
                patch_object(self.plugin, '_apply_tags',
                             autospec=True) as m_apply_tags:
            # Set up mock objects
            self.m_datastore_client.profile_exists.return_value = False
            m_get_pod_config.return_value = 'pod'
            m_get_namespace_tag.return_value = 'tag'

            # Set up class members
            pod_name = 'pod_name'
            profile_name = 'profile_name'
            self.plugin.pod_name = pod_name
            self.plugin.profile_name = profile_name

            # Set up args
            endpoint = Endpoint(TEST_HOST, TEST_ORCH_ID, '1234', '5678',
                                'active', 'mac')

            # Call method under test
            self.plugin._configure_profile(endpoint)

            # Assert
            self.m_datastore_client.profile_exists.assert_called_once_with(
                self.plugin.profile_name)
            self.m_datastore_client.create_profile.assert_called_once_with(
                self.plugin.profile_name)
            m_get_pod_config.assert_called_once_with()
            m_apply_rules.assert_called_once_with('pod')
            m_apply_tags.assert_called_once_with('pod')
            self.m_datastore_client.set_profiles_on_endpoint.assert_called_once_with(
                [profile_name], endpoint_id=endpoint.endpoint_id)

    def test_configure_profile_profile_exists(self):
        """
        Test _configure_profile when profile already exists.

        Expect system exit.
        """
        with patch_object(self.plugin, '_get_pod_config',
                          autospec=True) as m_get_pod_config:
            # Set up mock objects
            self.m_datastore_client.profile_exists.return_value = True
            m_get_pod_config.return_value = 'pod'

            # Set up class members
            profile_name = 'profile_name'
            self.plugin.profile_name = profile_name

            # Set up args
            endpoint = Endpoint(TEST_HOST, TEST_ORCH_ID, '1234', '5678',
                                'active', 'mac')

            # Call method under test
            self.assertRaises(SystemExit, self.plugin._configure_profile, endpoint)

            # Assert
            m_get_pod_config.assert_called_once_with()
            self.m_datastore_client.profile_exists.assert_called_once_with(
                profile_name)
            assert_false(self.m_datastore_client.create_profile.called)

    def test_get_pod_ports(self):
        # Initialize pod dictionary and expected outcome
        pod = {'spec': {'containers': [{'ports': [1, 2, 3]},{'ports': [4, 5]}]}}
        ports = [1, 2, 3, 4, 5]

        # Call method under test
        return_val = self.plugin._get_pod_ports(pod)

        # Assert
        assert_equal(return_val, ports)

    def test_get_pod_ports_no_ports(self):
        """
        Tests for getting ports for a pod, which has no ports.
        Mocks the pod spec reponse from the apiserver such that it
        does not inclue the 'ports' key for each of its containers.
        Asserts not ports are returned and no error is thrown.
        """
        # Initialize pod dictionary and expected outcome
        pod = {'spec': {'containers': [{'':[1, 2, 3]}, {'': [4, 5]}]}}
        ports = []

        # Call method under test
        return_val = self.plugin._get_pod_ports(pod)

        # Assert
        self.assertListEqual(return_val, ports)

    def test_get_pod_config(self):
        """Test _get_pod_config"""
        """
        Given a list of pods and a queried pod name, ensure that the proper data is returned.
        """
        with patch_object(self.plugin, '_get_api_path',
                          autospec=True) as m_get_api_path:
            # Set up mock object
            pod1 = {'metadata': {'namespace': 'a', 'name': 'pod-1'}}
            pod2 = {'metadata': {'namespace': 'a', 'name': 'pod-2'}}
            pod3 = {'metadata': {'namespace': 'a', 'name': 'pod-3'}}
            pods = [pod1, pod2, pod3]
            m_get_api_path.return_value = pods

            # Set up class member
            self.plugin.pod_name = 'pod-2'
            self.plugin.namespace = 'a'

            # Call method under test
            return_val = self.plugin._get_pod_config()

            # Assert
            assert_equal(return_val, pod2)

    def test_get_pod_config_error(self):
        """Test _get_pod_config Failure"""
        """
        Given a list of pods and an invalid pod name, ensure that a KeyError is raised.
        """
        with patch_object(self.plugin, '_get_api_path',
                          autospec=True) as m_get_api_path:
            # Set up mock object and class members
            pod1 = {'metadata': {'name': 'pod-1', 'namespace': 'ns'}}
            pods = [pod1]
            m_get_api_path.return_value = pods

            # Set up class member
            self.plugin.pod_name = 'corrupt'
            self.plugin.namespace = 'ns'

            # Call method under test expecting exception
            self.assertRaises(KeyError, self.plugin._get_pod_config)

    @patch('calico_kubernetes.calico_kubernetes.requests.Session',
           autospec=True)
    @patch('json.loads', autospec=True)
    def test_get_api_path(self, m_json_load, m_session):
        """Test _get_api_path"""
        """
        Test for correct calls in _get_api_path.
        """
        # Set up mock objects
        self.plugin.auth_token = 'TOKEN'
        m_session_return = Mock()
        m_session_return.headers = Mock()
        m_get_return = Mock()
        m_get_return.text = 'response_body'
        m_session_return.get.return_value = m_get_return
        m_session.return_value = m_session_return

        # Initialize args
        path = 'path/to/api/object'

        # Call method under test
        self.plugin._get_api_path(path)

        # Assert correct data in calls.
        m_session_return.headers.update.assert_called_once_with(
            {'Authorization': 'Bearer ' + 'TOKEN'})
        m_session_return.get.assert_called_once_with(
            calico_kubernetes.KUBE_API_ROOT + 'path/to/api/object',
            verify=False)
        m_json_load.assert_called_once_with('response_body')

    def test_generate_rules(self):
        """Test _generate_rules"""
        """
        Test that label conversion and command parsing works for multiple rules.
        """
        pod = {
                'metadata': {
                    'name': 'name',
                    'namespace': 'ns',
                    'annotations': {
                        POLICY_ANNOTATION_KEY: "allow from label key=value; allow tcp from ports 555,666"
                    }
                  }
              }
        self.plugin.namespace = 'ns'

        # Call method under test empty annotations/namespace
        return_val = self.plugin._generate_rules(pod)
        assert_equal(return_val, ([["allow", "from", "tag", "ns_key_value"],
                                   ["allow", "tcp", "from", "ports", "555,666"]],
                                  [["allow"]]))

    def test_generate_rules_kube_system(self):
        """Test _generate_rules with namespace kube_system"""
        """
        Test that kube-system overrides rules to allow all
        """
        pod = {
                'metadata': {
                                'name': 'name',
                                'namespace': 'kube-system',
                                'annotations': {
                                    POLICY_ANNOTATION_KEY : "allow from label key=value"
                                }
                }
              }
        self.plugin.namespace = 'kube-system'
        # Call method under test empty annotations/namespace
        return_val = self.plugin._generate_rules(pod)
        assert_equal(return_val, ([["allow"]],
                                  [["allow"]]))

    def test_generate_rules_ns_iso(self):
        """Test _generate_rules with ns_isolation"""
        """
        Test that ns_isolation is default policy when set.
        """
        pod = {
                'metadata': {
                                'name': 'name',
                                'namespace': 'ns'
                }
              }
        self.plugin.namespace = 'ns'
        calico_kubernetes.DEFAULT_POLICY = 'ns_isolation'

        # Call method under test empty annotations/namespace
        return_val = self.plugin._generate_rules(pod)

        # Assert return value is correct.
        assert_equal(return_val, ([["allow", "from", "tag", "namespace_ns"]],
                                  [['allow']]))

    def test_generate_rules_ns_iso_override(self):
        """Test _generate_rules with ns_isolation and programmed policy"""
        """
        Test that ns_isolation is overridden by annotation policy
        """
        pod = {
            'metadata': {
                'name': 'name',
                'namespace': 'ns',
                'annotations': {
                    POLICY_ANNOTATION_KEY: "allow from label key=value"
                }
            }
        }
        self.plugin.namespace = 'ns'
        calico_kubernetes.DEFAULT_POLICY = 'ns_isolation'

        # Call method under test empty annotations/namespace
        return_val = self.plugin._generate_rules(pod)

        # Assert return value is correct.
        assert_equal(return_val, ([["allow", "from", "tag", "ns_key_value"]],
                                  [['allow']]))

    def test_apply_rules(self):
        with patch_object(self.plugin, '_generate_rules',
                          autospec=True) as m_generate_rules, \
                patch_object(self.plugin, 'calicoctl',
                             autospec=True) as m_calicoctl:

            # Set up mock objects
            m_profile = Mock()
            self.m_datastore_client.get_profile.return_value = m_profile
            m_generate_rules.return_value = ([["allow"]], [["allow"]])
            m_calicoctl.return_value = None
            profile_name = 'a_b_c'
            self.plugin.profile_name = profile_name
            pod = {'metadata': {'namespace': 'a', 'profile': 'name'}}
            self.plugin.namespace = pod['metadata']['namespace']

            # Call method under test
            self.plugin._apply_rules(pod)

            # Assert
            self.m_datastore_client.get_profile.assert_called_once_with(
                profile_name)
            m_calicoctl.assert_has_calls([
                call('profile', profile_name, 'rule', 'remove', 'inbound', '--at=2'),
                call('profile', profile_name, 'rule', 'remove', 'inbound', '--at=1'),
                call('profile', profile_name, 'rule', 'remove', 'outbound', '--at=1')
            ])
            m_generate_rules.assert_called_once_with(pod)
            self.m_datastore_client.profile_update_rules(m_profile)

    def test_apply_rules_profile_not_found(self):
        self.m_datastore_client.get_profile.side_effect = KeyError
        self.assertRaises(SystemExit, self.plugin._apply_rules, 'profile')

    def test_apply_tags(self):
        # Intialize args
        pod = {
            'metadata': {'namespace': 'a', 'labels': {1: 2, "2/3": "4_5"}}}
        self.plugin.namespace = pod['metadata']['namespace']
        self.plugin.profile_name = 'profile_name'

        # Set up mock objs
        m_profile = Mock(spec=Profile, name=self.plugin.profile_name)
        m_profile.tags = set()
        self.m_datastore_client.get_profile.return_value = m_profile

        check_tags = set()
        check_tags.add('namespace_a')
        check_tags.add('a_1_2')
        check_tags.add('a_2_3_4__5')

        # Call method under test
        self.plugin._apply_tags(pod)

        # Assert
        self.m_datastore_client.get_profile.assert_called_once_with(
            self.plugin.profile_name)
        self.m_datastore_client.profile_update_tags.assert_called_once_with(
            m_profile)
        assert_equal(m_profile.tags, check_tags)

    def test_apply_tags_no_labels(self):
        # Intialize args
        pod = {}
        self.plugin.profile_name = 'profile_name'
        self.m_datastore_client.get_profile.return_value = Mock()

        # Call method under test
        self.plugin._apply_tags(pod)

        # Assert
        assert_false(self.m_datastore_client.called)

    def test_apply_tags_profile_not_found(self):
        # Intialize args
        pod = {'metadata': {'labels': {1: 1, 2: 2}}}
        profile_name = 'profile_name'

        # Set up mock objs
        self.m_datastore_client.get_profile.side_effect = KeyError

        # Call method under test expecting sys exit
        self.assertRaises(SystemExit, self.plugin._apply_tags, pod)

    @parameterized.expand([(1234,), ('testNAMESPACE',)])
    def test_log_interfaces(self, ns):
        with patch('calico_kubernetes.tests.kube_plugin_test.'
                   'calico_kubernetes.check_output',
                   autospec=True, return_value='MOCK_OUTPUT') as m_check_output:
            _log.info('Testing namespace %s (type=%s)', ns, type(ns))
            _log_interfaces(ns)

            assert_equal(m_check_output.mock_calls,
                         [
                             call(['ip', 'addr']),
                             call(['ip', 'netns', 'list']),
                             # Check we always pass a string to check_output
                             call(['ip', 'netns', 'exec', str(ns),
                                   'ip', 'addr'])
                         ])

    @patch('sys.exit', autospec=True)
    @patch('calico_kubernetes.calico_kubernetes.run')
    @patch('calico_kubernetes.tests.kube_plugin_test.'
           'calico_kubernetes.configure_logger', autospec=True)
    def test_run_protected(self, m_conf_logger, m_run, m_sys_exit):
        """Test global method run_protected"""
        """
        Ensure code path not broken
        """
        calico_kubernetes.run_protected()

        # Check that the logger was set up; don't care about the details.
        assert_true(len(m_conf_logger.mock_calls) > 0)
        # Check we actually called the work function.
        m_run.assert_called_with()
        # We should exit without error.
        m_sys_exit.assert_called_with(0)

    @patch('calico_kubernetes.calico_kubernetes.run')
    @patch('calico_kubernetes.tests.kube_plugin_test.'
           'calico_kubernetes.configure_logger', autospec=True)
    def test_run_protected_sys_exit(self, _, m_run):
        """Test failure in global method run_protected"""
        for exception_cls in (SystemExit, RuntimeError):
            _log.info('Testing that we handle %s exceptions',
                      str(exception_cls.__name__))
            m_run.side_effect = exception_cls

            self.assertRaises(SystemExit, calico_kubernetes.run_protected)

            # Check we actually called the work function.
            m_run.assert_called_with()

    def test_run_init(self):
        """Test run method with argument 'init'"""
        """
        Check for desired calls for mode init
        """
        with patch_object(sys, 'argv', [None, 'init', 'ns/ns', 'pod/pod', 'id']) as m_argv:
            calico_kubernetes.run()

    @patch('calico_kubernetes.calico_kubernetes.NetworkPlugin')
    def test_run_status(self, m_plugin):
        """Test run method with argument 'status'"""
        """
        Check for desired calls for mode status
        """
        with patch_object(sys, 'argv', [None, 'status', 'ns/ns', 'pod/pod', 'id']) as m_argv:
            calico_kubernetes.run()
            m_plugin().status.assert_called_once_with('ns_ns', 'pod_pod', 'id')

    @patch('calico_kubernetes.calico_kubernetes.NetworkPlugin')
    def test_run_delete(self, m_plugin):
        """Test run method with argument 'teardown'"""
        """
        Check for desired calls for mode teardown
        """
        with patch_object(sys, 'argv', [None, 'teardown', 'ns/ns', 'pod/pod', 'id']) as m_argv:
            calico_kubernetes.run()
            m_plugin().delete.assert_called_once_with('ns_ns', 'pod_pod', 'id')

    @patch('calico_kubernetes.calico_kubernetes.NetworkPlugin')
    def test_run_create(self, m_plugin):
        """Test run method with argument 'setup'"""
        """
        Check for desired calls for mode setup
        """
        with patch_object(sys, 'argv', [None, 'setup', 'ns/ns', 'pod/pod', 'id']) as m_argv:
            calico_kubernetes.run()
            m_plugin().create.assert_called_once_with('ns_ns', 'pod_pod', 'id')

    @patch('os.path', autospec=True)
    @patch('os.makedirs', autospec=True)
    @patch('logging.handlers.RotatingFileHandler', autospec=True)
    @patch('logging.StreamHandler', autospec=True)
    @patch('logging.Formatter', autospec=True)
    def test_configure_root_logger(self, m_logging_f, m_logging_sh, m_logging_fh, m_os_makedirs, m_os_path):
        """Test configure_logger with root_logger=True"""
        """
        Check calls for valid arguments.
        """
        m_os_path.exists.return_value = False
        m_log = Mock()
        f_handler = Mock()
        s_handler = Mock()
        m_logging_fh.return_value = f_handler
        m_logging_sh.return_value = s_handler

        logutils.configure_logger(m_log, logging.DEBUG, True, '/mock/')

        m_os_makedirs.assert_called_once_with('/mock/')
        m_logging_fh.assert_called_once_with(filename='/mock/calico.log',
                                             maxBytes=10000000,
                                             backupCount=5)
        m_logging_sh.assert_called_once_with(sys.stdout)
        s_handler.setLevel.assert_called_once_with(logging.INFO)
        m_logging_f.assert_called_once_with(ROOT_LOG_FORMAT)
        m_log.addHandler.has_calls([(f_handler), (s_handler)])
        m_log.setLevel.assert_called_once_with(logging.DEBUG)

    @patch('os.path', autospec=True)
    @patch('os.makedirs', autospec=True)
    @patch('logging.handlers.RotatingFileHandler', autospec=True)
    @patch('logging.StreamHandler', autospec=True)
    @patch('logging.Formatter', autospec=True)
    def test_configure_child_logger(self, m_logging_f, m_logging_sh, m_logging_fh, m_os_makedirs, m_os_path):
        """Test configure_logger with root_logger=False"""
        """
        Ensure correct format applied.
        """
        m_os_path.exists.return_value = False
        m_log = Mock()

        logutils.configure_logger(m_log, logging.DEBUG, False, '/mock/')

        m_logging_f.assert_called_once_with(LOG_FORMAT)

    def test_api_root_secure_true(self):
        """Test api_root_secure output for https"""
        """
        Should return True
        """
        calico_kubernetes.KUBE_API_ROOT = "https://test.com"
        return_val = self.plugin._api_root_secure()
        assert_true(return_val)

    def test_api_root_secure_false(self):
        """Test api_root_secure output for http"""
        """
        Should return False
        """
        calico_kubernetes.KUBE_API_ROOT = "http://test.com"
        return_val = self.plugin._api_root_secure()
        assert_false(return_val)

    def test_api_root_secure_error(self):
        """Test api_root_secure output for invalid http(s) scheme"""
        """
        Should raise SystemExit
        """
        calico_kubernetes.KUBE_API_ROOT = "invalid"
        self.assertRaises(SystemExit, self.plugin._api_root_secure)
