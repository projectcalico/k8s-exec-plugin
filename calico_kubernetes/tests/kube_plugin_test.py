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
import requests
import unittest
import copy

from logging import LogRecord
from docker.errors import APIError
from mock import patch, Mock, MagicMock, call
from netaddr import IPAddress, IPNetwork
from nose.tools import assert_equal, assert_true, assert_false, assert_raises
from nose_parameterized import parameterized
from subprocess import CalledProcessError

from calico_kubernetes import calico_kubernetes, logutils, policy
from pycalico.block import AlreadyAssignedError
from pycalico.datastore import IF_PREFIX, Rule, Rules
from pycalico.datastore_datatypes import Profile, Endpoint

# noinspection PyProtectedMember
from calico_kubernetes.calico_kubernetes import _log_interfaces, POLICY_ANNOTATION_KEY
from calico_kubernetes.calico_kubernetes import (KUBE_API_ROOT_VAR,
                                                 CALICO_IPAM_VAR,
                                                 KUBE_AUTH_TOKEN_VAR,
                                                 ETCD_AUTHORITY_VAR,
                                                 LOG_LEVEL_VAR,
                                                 DEFAULT_POLICY_VAR)
from calico_kubernetes.logutils import ROOT_LOG_FORMAT, LOG_FORMAT, DOCKER_ID_ROOT_LOG_FORMAT, DOCKER_ID_LOG_FORMAT

# noinspection PyUnresolvedReferences
patch_object = patch.object

TEST_HOST = calico_kubernetes.HOSTNAME
TEST_ORCH_ID = calico_kubernetes.ORCHESTRATOR_ID

_log = logging.getLogger(__name__)

CONFIG = {
    KUBE_API_ROOT_VAR: "",
    KUBE_AUTH_TOKEN_VAR: "",
    CALICO_IPAM_VAR: "true",
    ETCD_AUTHORITY_VAR: "",
    LOG_LEVEL_VAR: "",
    DEFAULT_POLICY_VAR: "",
}


class NetworkPluginTest(unittest.TestCase):

    def setUp(self):
        self.plugin = calico_kubernetes.NetworkPlugin(CONFIG)
        self.plugin.namespace = "namespace"
        self.plugin.pod_name = "podname"
        self.plugin.docker_id = "dockeridabcd"

        # We expect this profile name to be generated.
        self.expected_profile_name = "namespace_podname_dockeridabcd"

        # Datastore and Docker Clients should be mocked
        self.m_datastore_client = MagicMock(spec=self.plugin._datastore_client)
        self.plugin._datastore_client = self.m_datastore_client
        self.m_docker_client = MagicMock(spec=self.plugin._docker_client)
        self.plugin._docker_client = self.m_docker_client
        self.plugin.policy_parser = MagicMock(spec=policy.PolicyParser)

    def test_create(self):
        """Test Pod Creation Hook"""
        with patch_object(self.plugin, '_configure_interface',
                          autospec=True) as m_configure_interface, \
                patch_object(self.plugin, '_configure_profile',
                             autospec=True) as m_configure_profile:
            # Set up mock objects
            endpoint = Mock()
            endpoint.endpoint_id = "12345abcd_endpoint_id"
            m_configure_interface.return_value = endpoint
            m_validate_container_state = MagicMock(spec=self.plugin._validate_container_state)
            self.plugin._validate_container_state = m_validate_container_state

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
            m_validate_container_state.assert_called_once_with(self.plugin.docker_id)
            m_configure_interface.assert_called_once_with()
            m_configure_profile.assert_called_once_with(endpoint)

    def test_create_error(self):
        """Test Pod Creation Hook Failure"""
        with patch_object(self.plugin, '_configure_interface',
                          autospec=True) as m_configure_interface:
            # Set up mock objects
            m_configure_interface.side_effect = CalledProcessError(1,'','')
            self.plugin.delete = MagicMock(spec=self.plugin.delete)

            # Set up args
            namespace = 'ns'
            pod_name = 'pod1'
            docker_id = 13

            # Call method under test
            assert_raises(SystemExit, self.plugin.create, namespace, pod_name, docker_id)
            self.plugin.delete.assert_called_once_with(namespace, pod_name, docker_id)

    def test_delete(self):
        """Test Pod Deletion Hook"""
        # Mock
        m_remove_endpoint = MagicMock(spec=self.plugin._remove_endpoint)
        self.plugin._remove_endpoint = m_remove_endpoint
        m_get_endpoint = MagicMock(spec=self.plugin._get_endpoint)
        endpoint = MagicMock()
        endpoint.profile_ids = [1, 2, 3]
        self.plugin._get_endpoint = m_get_endpoint
        self.plugin._get_endpoint.return_value = endpoint
        self.plugin.default_policy = "ns_isolation"

        # Mock so that first profile has members, second and third are empty.
        # We'll only call remove_profile on the second and third profiles.
        get_side_effect = iter([Mock(), None, None])
        self.plugin._datastore_client.get_profile_members.side_effect = get_side_effect

        # Mock so that second profile is deleted, last does not exist.
        rm_side_effect = iter([None, KeyError])
        self.plugin._datastore_client.remove_profile.side_effect = rm_side_effect

        # Set up args
        namespace = 'ns'
        pod_name = 'pod1'
        docker_id = 123456789101112

        # Call method under test
        self.plugin.delete(namespace, pod_name, docker_id)

        # Assert expected output
        expected_calls = [call(2), call(3)]
        m_remove_endpoint.assert_called_once_with(m_get_endpoint())
        assert_equal(self.plugin._datastore_client.remove_profile.mock_calls, expected_calls)
        assert_equal(namespace, self.plugin.namespace)
        assert_equal(pod_name, self.plugin.pod_name)
        assert_equal(docker_id, self.plugin.docker_id)

    def test_delete_default_profile(self):
        """Test Pod Deletion Hook with default profile"""
        # Mock
        m_remove_endpoint = MagicMock(spec=self.plugin._remove_endpoint)
        self.plugin._remove_endpoint = m_remove_endpoint
        m_get_endpoint = MagicMock(spec=self.plugin._get_endpoint)
        endpoint = MagicMock()
        endpoint.profile_ids = [calico_kubernetes.DEFAULT_PROFILE_NAME]
        self.plugin._get_endpoint = m_get_endpoint
        self.plugin._get_endpoint.return_value = endpoint
        self.plugin.default_policy = "none"

        # Set up args
        namespace = 'ns'
        pod_name = 'pod1'
        docker_id = 123456789101112

        # Call method under test
        self.plugin.delete(namespace, pod_name, docker_id)

        # Assert expected output
        assert_false(self.plugin._datastore_client.remove_profile.called)
        m_remove_endpoint.assert_called_once_with(m_get_endpoint())

    def test_delete_no_endpoint(self):
        """Test Pod Deletion Hook when no endpoint exists"""
        # Mock
        m_remove_endpoint = MagicMock(spec=self.plugin._remove_endpoint)
        self.plugin._remove_endpoint = m_remove_endpoint
        m_get_endpoint = MagicMock(spec=self.plugin._get_endpoint)
        self.plugin._get_endpoint = m_get_endpoint
        self.plugin._get_endpoint.return_value = None

        # Set up args
        namespace = 'ns'
        pod_name = 'pod1'
        docker_id = 123456789101112

        # Call method under test
        assert_raises(SystemExit, self.plugin.delete, namespace, pod_name, docker_id)

    def test_delete_error(self):
        """Test Pod Deletion Hook Failure

        If the datastore remove_profile function returns KeyError,
        the profile is not in the datastore. In this instance, Calico
        should Issue warning log, but delete() will not fail.
        """
        with patch_object(self.plugin, '_remove_endpoint', autospec=True) as m_remove_endpoint:
            # Set up mock obj
            self.m_datastore_client.remove_profile.side_effect = KeyError

            # Set up args
            namespace = 'ns'
            pod_name = 'pod1'
            docker_id = 123456789101112
            profile_name = 'ns_pod1_123456789101'

            # Call method under test
            self.plugin.delete(namespace, pod_name, docker_id)

            # If WAD, we don't need to assert anything.
            # If not, primary delete() test will catch errors.

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
    def test_status_host_network(self, m_print):
        """Test Pod Status Hook for Host Networked Pod"""
        # Set up args
        namespace = 'ns'
        pod_name = 'pod1'
        docker_id = 123456789101112
        self.plugin._uses_host_networking = Mock()
        self.plugin._uses_host_networking.return_value = True

        # Call method under test
        assert_raises(SystemExit, self.plugin.status, namespace, pod_name, docker_id)
        assert_false(self.m_datastore_client.get_endpoint.called)

    @patch('__builtin__.print', autospec=True)
    def test_status_no_ip(self, m_print):
        """Test Pod Status Hook: No IP on Endpoint

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

        assert_raises(
            SystemExit, self.plugin.status, namespace, pod_name, docker_id)

        # Prints are read externally. We don't want to print in a fail state.
        assert_false(m_print.called)

    @patch('__builtin__.print', autospec=True)
    def test_status_ep_error(self, m_print):
        """Test Pod Status Hook: Endpoint Retrieval Error

        Test for sys exit when get_endpoint returns an error.
        """
        # Set up args
        namespace = 'ns'
        pod_name = 'pod1'
        docker_id = 123456789101112

        self.m_datastore_client.get_endpoint.side_effect = KeyError

        assert_raises(
            SystemExit, self.plugin.status, namespace, pod_name, docker_id)

        # Prints are read externally. We don't want to print in a fail state.
        assert_false(m_print.called)

    def test_configure_interface(self):
        with patch_object(self.plugin, '_read_docker_ip',
                          autospec=True) as m_read_docker_ip, \
                patch_object(self.plugin, '_get_container_pid', autospec=True) as m_get_container_pid, \
                patch_object(self.plugin, '_delete_docker_interface',
                             autospec=True) as m_delete_docker_interface, \
                patch_object(self.plugin, '_create_endpoint',
                             autospec=True) as m_create_endpoint, \
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
            m_create_endpoint.return_value = endpoint
            m_generate_cali_interface_name.return_value = 'interface_name'
            m_get_node_ip.return_value = '1.2.3.4'

            # Set up args
            self.plugin.pod_name = 'pod1'
            container_name = 'container1'
            self.plugin.docker_id = container_name

            # Call method under test
            return_val = self.plugin._configure_interface()

            # Assert expected calls
            m_get_container_pid.assert_called_once_with(container_name)
            m_delete_docker_interface.assert_called_once_with()
            m_create_endpoint.assert_called_once_with('container_pid')
            m_generate_cali_interface_name.assert_called_once_with(
                IF_PREFIX, endpoint.endpoint_id)
            m_get_node_ip.assert_called_once_with()
            m_check_call.assert_called_once_with(
                ['ip', 'addr', 'add', '1.2.3.4' + '/32',
                 'dev', 'interface_name'])
            assert_equal(return_val, endpoint)

    def test_create_endpoint(self):
        with patch('calico_kubernetes.calico_kubernetes.netns.PidNamespace', autospec=True) as m_pid_ns, \
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

            m_assign_ip.return_value = ip

            # Call method under test
            return_value = self.plugin._create_endpoint(pid)

            # Assert call parameters
            self.m_datastore_client.get_endpoint.assert_called_once_with(
                hostname=TEST_HOST,
                orchestrator_id=TEST_ORCH_ID,
                workload_id=self.plugin.docker_id
            )
            self.m_datastore_client.create_endpoint.assert_called_once_with(TEST_HOST,
                                                                            TEST_ORCH_ID,
                                                                            self.plugin.docker_id,
                                                                            [ip])
            self.m_datastore_client.set_endpoint.assert_called_once_with(
                endpoint)
            endpoint.provision_veth.assert_called_once_with(
                m_pid_ns(pid), "eth0")

            # Verify method output
            assert_equal(endpoint.mac, 'new_mac')
            assert_equal(return_value, endpoint)

    def test_create_endpoint_create_error(self):
        """Test Endpoint Creation Error in _create_endpoint

        _create_endpoint should release ips and exit when endpoint creation fails.
        """
        with patch_object(self.plugin, '_validate_container_state', autospec=True) as m_validate, \
                patch_object(self.plugin, '_assign_container_ip', autospec=True) as m_assign_ip:

            # Set up mock objs
            self.m_datastore_client.get_endpoint.side_effect = KeyError
            self.m_datastore_client.create_endpoint.side_effect = KeyError

            # Set up arguments
            pid = 'pid'
            ip = IPAddress('1.1.1.1')
            m_assign_ip.return_value = ip

            assert_raises(SystemExit, self.plugin._create_endpoint, pid)

            # Assert
            self.m_datastore_client.release_ips.assert_called_once_with(set([ip]))
            assert_false(self.m_datastore_client.set_endpoint.called)

    def test_create_endpoint_container_exists(self):
        """
        Test _create_endpoint method when container already exists.

        Expect system exit.
        """
        # Set up arguments
        pid = 'pid'

        # Call method under test
        assert_raises(SystemExit, self.plugin._create_endpoint, pid)

    @patch('calico_kubernetes.calico_kubernetes.netns.remove_veth', autospec=True)
    def test_remove_endpoint(self, m_remove_veth):
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
        self.plugin._remove_endpoint(endpoint)

        m_remove_veth.assert_called_once_with(endpoint.name)

    @patch('calico_kubernetes.calico_kubernetes.netns.remove_veth', autospec=True)
    def test_remove_endpoint_with_exceptions(self, m_remove_veth):
        """Test Container Remove Exception Handling

        Failures in remove_veth and remove_workload should gently raise exceptions without exit.
        """
        # Raise errors under test.
        m_remove_veth.side_effect = CalledProcessError(1, '', '')
        self.m_datastore_client.remove_workload.side_effect = KeyError

        self.plugin._remove_endpoint(MagicMock())

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
            assert_raises(SystemExit, self.plugin._validate_container_state,
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
            assert_raises(
                SystemExit, self.plugin._validate_container_state, 'container_name')

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
        assert_raises(
            SystemExit, self.plugin._get_container_info, container_name)

    def test_get_container_info_404(self):
        """Test 404 error on API Access in _get_container_info

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
        assert_raises(
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
        """Test Duplicate IP assignment

        When IP is already assigned, assert that all endpoints, ips and profiles are removed.
        """
        with patch.object(self.plugin, "_read_docker_ip") as m_read_ip:

            # Don't use CALICO_IPAM for this test.
            self.plugin.calico_ipam = "false"

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
        """Test assign_container_ip sys exit on Runtime Error

        Assert SystemExit when datastore client fails to allocate IP
        """
        with patch.object(self.plugin, "_read_docker_ip") as m_read_ip:

            # Don't use CALICO_IPAM for this test.
            self.plugin.calico_ipam = "false"

            # Mock the Docker IP
            docker_ip = "172.12.23.4"
            m_read_ip.return_value = docker_ip

            # Mock out assignment - already assigned for first call,
            # not assigned on the second.
            self.m_datastore_client.assign_ip.side_effect = RuntimeError

            # Run method under test
            assert_raises(SystemExit, self.plugin._assign_container_ip)

    def test_assign_container_ipam_succeed(self):
        """Test assign_container_ip with IPAM enabled

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
        """Test assign_container_ip IPAM auto assign failure

        Assert SystemExit when datastore client fails to allocate IP
        """
        calico_kubernetes.CALICO_IPAM = "true"

        # Mock the Docker IP
        self.plugin.docker_id = "docker_id"
        self.m_datastore_client.auto_assign_ips.side_effect = RuntimeError

        # Run method under test
        assert_raises(SystemExit, self.plugin._assign_container_ip)

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
            assert_raises(SystemExit, self.plugin._get_node_ip)

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
        # Set up mock objects
        m_get_namespace_tag = MagicMock(spec=self.plugin._get_namespace_tag)
        m_get_pod_config = MagicMock(spec=self.plugin._get_pod_config)
        m_generate_rules = MagicMock(spec=self.plugin._generate_rules)
        m_apply_tags = MagicMock(spec=self.plugin._apply_tags)
        self.plugin._get_namespace_tag = m_get_namespace_tag
        self.plugin._get_pod_config = m_get_pod_config
        self.plugin._generate_rules = m_generate_rules
        self.plugin._apply_tags = m_apply_tags
        self.m_datastore_client.profile_exists.return_value = False
        m_get_pod_config.return_value = 'pod'
        m_get_namespace_tag.return_value = 'tag'

        # Mock generation of rules
        expected_rules = Rules(id="id", inbound_rules=[], outbound_rules=[])
        m_generate_rules.return_value = expected_rules

        # Set up args
        endpoint = Endpoint(TEST_HOST, TEST_ORCH_ID, '1234', '5678',
                            'active', 'mac')

        # Call method under test
        self.plugin._configure_profile(endpoint)

        # Assert
        self.m_datastore_client.profile_exists.assert_called_once_with(self.expected_profile_name)
        self.m_datastore_client.create_profile.assert_called_once_with(self.expected_profile_name, expected_rules)
        m_get_pod_config.assert_called_once_with()
        m_apply_tags.assert_called_once_with('pod', self.expected_profile_name)
        self.m_datastore_client.set_profiles_on_endpoint.assert_called_once_with(
        [self.expected_profile_name], endpoint_id=endpoint.endpoint_id)

    def test_configure_profile_no_policy(self):
        """
        Test configuring profile when DEFAULT_POLICY == "none"
        """
        # Mock
        self.plugin.default_policy = "none"
        self.plugin._datastore_client.profile_exists.return_value = False
        endpoint = MagicMock(spec=Endpoint)
        endpoint.endpoint_id = "12345678"

        # Call
        self.plugin._configure_profile(endpoint)

        # Assert

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

            # Set up args
            endpoint = Endpoint(TEST_HOST, TEST_ORCH_ID, '1234', '5678',
                                'active', 'mac')

            # Call method under test
            assert_raises(
                SystemExit, self.plugin._configure_profile, endpoint)

            # Assert
            m_get_pod_config.assert_called_once_with()
            self.m_datastore_client.profile_exists.assert_called_once_with(
                self.expected_profile_name)
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

    @patch('calico_kubernetes.calico_kubernetes.requests.Session',
           autospec=True)
    @patch('calico_kubernetes.calico_kubernetes.NetworkPlugin._api_root_secure',
           autospec=True)
    @patch('json.loads', autospec=True)
    def test_get_pod_config(self, m_json_load, m_secure, m_session):
        """Test _get_pod_config Success

        Test for correct calls in _get_api_path.
        """
        # Set up class member
        self.plugin.pod_name = 'pod-1'
        self.plugin.namespace = 'a'
        pod1 = '{"metadata": {"namespace": "a", "name": "pod-1"}}'

        # Set up mock objects
        m_secure.return_value = True
        self.plugin.auth_token = 'TOKEN'

        get_obj = Mock()
        get_obj.status_code = 200
        get_obj.text = pod1

        m_session_obj = Mock()
        m_session_obj.headers = Mock()
        m_session_obj.get.return_value = get_obj

        m_session.return_value = m_session_obj
        m_session_obj.__enter__ = Mock(return_value=m_session_obj)
        m_session_obj.__exit__ = Mock(return_value=False)

        # Call method under test
        api_root = "http://kubernetesapi:8080/api/v1/"
        self.plugin.api_root = api_root
        self.plugin._get_pod_config()

        # Assert correct data in calls.
        m_session_obj.headers.update.assert_called_once_with(
            {'Authorization': 'Bearer ' + 'TOKEN'})
        m_session_obj.get.assert_called_once_with(
            api_root + 'namespaces/a/pods/pod-1',
            verify=False)
        m_json_load.assert_called_once_with(pod1)

    @patch('calico_kubernetes.calico_kubernetes.requests.Session',
           autospec=True)
    @patch('calico_kubernetes.calico_kubernetes.NetworkPlugin._api_root_secure',
           autospec=True)
    @patch('json.loads', autospec=True)
    def test_get_pod_config_error(self, m_json_load, m_secure, m_session):
        """Test _get_api_path with API Access Error
        """
        # Set up mock objects
        m_secure.return_value = True
        self.plugin.auth_token = 'TOKEN'

        m_session_obj = Mock()
        m_session_obj.headers = Mock()
        m_session_obj.get.side_effect = BaseException

        m_session.return_value = m_session_obj
        m_session_obj.__enter__ = Mock(return_value=m_session_obj)
        m_session_obj.__exit__ = Mock(return_value=False)

        # Call method under test
        assert_raises(SystemExit, self.plugin._get_pod_config)

    @patch('calico_kubernetes.calico_kubernetes.requests.Session',
           autospec=True)
    @patch('calico_kubernetes.calico_kubernetes.NetworkPlugin._api_root_secure',
           autospec=True)
    @patch('json.loads', autospec=True)
    def test_get_pod_config_response_code(self, m_json_load, m_secure, m_session):
        """Test _get_api_path with incorrect status_code
        """
        # Set up class member
        self.plugin.pod_name = 'pod-1'
        self.plugin.namespace = 'a'
        pod1 = '{"metadata": {"namespace": "a", "name": "pod-1"}}'

        # Set up mock objects
        m_secure.return_value = True
        self.plugin.auth_token = 'TOKEN'

        get_obj = Mock()
        get_obj.status_code = 404

        m_session_obj = Mock()
        m_session_obj.headers = Mock()
        m_session_obj.get.return_value = get_obj

        m_session.return_value = m_session_obj
        m_session_obj.__enter__ = Mock(return_value=m_session_obj)
        m_session_obj.__exit__ = Mock(return_value=False)

        # Call method under test
        assert_raises(SystemExit, self.plugin._get_pod_config)

    def test_generate_rules(self):
        """Test _generate_rules

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

        # Call method under test.
        return_val = self.plugin._generate_rules(pod, self.expected_profile_name)

        # Expected calls
        expected = [call("allow from label key=value"),
                    call(" allow tcp from ports 555,666")]

        # Assert
        assert_equal(self.plugin.policy_parser.parse_line.mock_calls, expected)

    def test_generate_rules_kube_system(self):
        """Test _generate_rules with namespace kube_system

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
        self.plugin.policy_parser.namespace = 'kube-system'

        # Expected result
        allow = [Rule(action="allow")]
        expected = Rules(id=self.expected_profile_name,
                         inbound_rules=allow,
                         outbound_rules=allow)

        # Call method under test empty annotations/namespace
        return_val = self.plugin._generate_rules(pod, self.expected_profile_name)
        assert_equal(return_val, expected)

    def test_generate_rules_allow_all(self):
        """Test _generate_rules with policy "allow"

        Tests that all traffic is allowed when default policy is "allow"
        """
        pod = {
                'metadata': {
                                'name': 'name',
                                'namespace': 'ns'
                }
              }
        self.plugin.default_policy = "allow"

        # Call method under test empty annotations/namespace
        return_val = self.plugin._generate_rules(pod, self.expected_profile_name)

        allow = [Rule(action="allow")]
        expected = Rules(id=self.expected_profile_name,
                         inbound_rules=allow,
                         outbound_rules=allow)

        # Assert return value is correct.
        assert_equal(return_val, expected)

    def test_generate_rules_ns_iso_override(self):
        """Test _generate_rules with ns_isolation and programmed policy

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
        self.plugin.default_policy = "ns_isolation"

        # Call method under test empty annotations/namespace
        return_val = self.plugin._generate_rules(pod, self.expected_profile_name)

        # Assert return value is correct.
        expected = [call("allow from label key=value")]
        assert_equal(self.plugin.policy_parser.parse_line.mock_calls, expected)

        inbound = [self.plugin.policy_parser.parse_line()]
        expected = Rules(id=self.expected_profile_name,
                         inbound_rules=inbound,
                         outbound_rules=[{'action': 'allow'}])
        assert_equal(return_val, expected)

    def test_generate_rules_ns_isolation(self):
        pod = {'metadata': {'profile': 'name'}}
        self.plugin.default_policy = "ns_isolation"

        # Expected result
        ns_tag = "namespace_%s" % self.plugin.namespace
        inbound = [Rule(action="allow", src_tag=ns_tag)]
        outbound = [Rule(action="allow")]
        expected = Rules(id=self.expected_profile_name,
                         inbound_rules=inbound,
                         outbound_rules=outbound)

        # Call method under test empty annotations/namespace
        return_val = self.plugin._generate_rules(pod, self.expected_profile_name)

        # Assert
        self.assertEqual(return_val, expected)

    def test_generate_rules_annotations(self):
        # Create the pod metadata
        policy = {POLICY_ANNOTATION_KEY: 'allow from label A=B; allow from label C=D'}
        annotations = {'annotations': policy}
        pod = {'metadata': annotations}

        # Mock out the policy parser
        self.plugin.policy_parser = Mock()

        # Call method under test
        self.plugin._generate_rules(pod, self.expected_profile_name)

        # Assert
        calls = [call("allow from label A=B"),
                 call(" allow from label C=D")]
        self.plugin.policy_parser.parse_line.assert_has_calls(calls)

    def test_apply_tags(self):
        # Intialize args
        pod = {
            'metadata': {'namespace': 'a', 'labels': {1: 2, "2/3": "4_5"}}}
        self.plugin.namespace = pod['metadata']['namespace']

        # Set up mock objs
        m_profile = Mock(spec=Profile, name=self.expected_profile_name)
        m_profile.tags = set()
        self.m_datastore_client.get_profile.return_value = m_profile

        check_tags = set()
        check_tags.add('namespace_a')
        check_tags.add('a_1_2')
        check_tags.add('a_2_3_4__5')

        # Call method under test
        self.plugin._apply_tags(pod, self.expected_profile_name)

        # Assert
        self.m_datastore_client.get_profile.assert_called_once_with(
            self.expected_profile_name)
        self.m_datastore_client.profile_update_tags.assert_called_once_with(
            m_profile)
        assert_equal(m_profile.tags, check_tags)

    def test_apply_tags_no_labels(self):
        # Intialize args
        pod = {}
        self.plugin.namespace = 'ns'
        self.m_datastore_client.get_profile.return_value = Mock()

        # Call method under test
        self.plugin._apply_tags(pod, self.expected_profile_name)

        # Assert
        assert_false(self.m_datastore_client.called)

    def test_apply_tags_profile_not_found(self):
        # Intialize args
        pod = {'metadata': {'labels': {1: 1, 2: 2}}}
        profile_name = 'profile_name'

        # Set up mock objs
        self.m_datastore_client.get_profile.side_effect = KeyError

        # Call method under test expecting sys exit
        assert_raises(SystemExit, self.plugin._apply_tags, pod, self.expected_profile_name)

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
                             call(['ip', 'netns', 'exec', str(ns), 'ip', 'addr'])
                         ])

    def test_log_error(self):
        with patch('calico_kubernetes.tests.kube_plugin_test.'
                   'calico_kubernetes.check_output',
                   autospec=True) as m_check_output:
            # Mock to throw Exception
            m_check_output.side_effect = CalledProcessError

            # Call function, assert Exception is caught.
            _log_interfaces("12345")

    @parameterized.expand([
        ('init'),
        ('setup'),
        ('status'),
        ('teardown'),
    ])
    @patch('sys.exit', autospec=True)
    @patch('calico_kubernetes.calico_kubernetes.run')
    @patch('calico_kubernetes.tests.kube_plugin_test.'
           'calico_kubernetes.configure_logger', autospec=True)
    @patch('calico_kubernetes.calico_kubernetes.load_config', autospec=True)
    def test_run_protected(self, m_mode, m_load_config, m_conf_logger, m_run, m_sys_exit):
        """Test global method run_protected

        Ensure code path not broken
        """
        if m_mode == 'init':
            patch_args = [None, m_mode]
        else:
            patch_args = [None, m_mode, 'ns/ns', 'pod/pod', 'id']

        with patch_object(sys, 'argv', patch_args) as m_argv:
            calico_kubernetes.run_protected()

        # Check that the logger was set up; don't care about the details.
        assert_true(len(m_conf_logger.mock_calls) > 0)
        # Check we actually called the work function.
        if m_mode == 'init':
            m_run.assert_called_with(mode=m_mode, namespace=None, pod_name=None, docker_id=None, config=m_load_config())
        else:
            m_run.assert_called_with(mode=m_mode, namespace='ns_ns', pod_name='pod_pod', docker_id='id', config=m_load_config())
        # We should exit without error.
        m_sys_exit.assert_called_with(0)

    @patch('sys.exit', autospec=True)
    @patch('calico_kubernetes.calico_kubernetes.run')
    @patch('calico_kubernetes.tests.kube_plugin_test.'
           'calico_kubernetes.configure_logger', autospec=True)
    @patch('calico_kubernetes.calico_kubernetes.load_config', autospec=True)
    def test_run_protected_sys_exit(self, m_load_config, _, m_run, m_sys_exit):
        """Test run_protected when SystemExit is called"""
        m_run.side_effect = SystemExit(555)

        with patch_object(sys, 'argv', [None, 'status', 'ns/ns', 'pod/pod', 'id']) as m_argv:
            calico_kubernetes.run_protected()

        # We should exit with error.
        m_sys_exit.assert_called_once_with(555)

    @patch('sys.exit', autospec=True)
    @patch('calico_kubernetes.calico_kubernetes.run')
    @patch('calico_kubernetes.tests.kube_plugin_test.'
           'calico_kubernetes.configure_logger', autospec=True)
    def test_run_protected_uncaught(self, _, m_run, m_sys_exit):
        """Test run_protected when uncaught Exception is called"""
        m_run.side_effect = RuntimeError

        with patch_object(sys, 'argv', ["config", 'status', 'ns/ns', 'pod/pod', 'id']) as m_argv:
            calico_kubernetes.run_protected()

        # We should exit with error.
        m_sys_exit.assert_called_once_with(1)

    # mode, namespace, pod_name, docker_id
    @parameterized.expand([
        ('init', None, None, None),
        ('setup', 'ns_ns', 'pod_pod', 'id'),
        ('teardown', 'ns_ns', 'pod_pod', 'id'),
        ('status', 'ns_ns', 'pod_pod', 'id'),
        ('invalid', 'ns_ns', 'pod_pod', 'id'),
    ])
    @patch('calico_kubernetes.calico_kubernetes.NetworkPlugin')
    def test_run(self, m_mode, m_namespace, m_pod_name, m_docker_id, m_plugin):
        """Test run method

        Check for desired calls given a variety of inputs
        """
        calico_kubernetes.run(m_mode, m_namespace, m_pod_name, m_docker_id, CONFIG)
        if m_mode == 'status':
            m_plugin().status.assert_called_once_with(m_namespace, m_pod_name, m_docker_id)
        elif m_mode == 'setup':
            m_plugin().create.assert_called_once_with(m_namespace, m_pod_name, m_docker_id)
        elif m_mode == 'teardown':
            m_plugin().delete.assert_called_once_with(m_namespace, m_pod_name, m_docker_id)
        else:
            assert_false(m_plugin.called)

    @patch('os.path', autospec=True)
    @patch('os.makedirs', autospec=True)
    @patch('calico_kubernetes.logutils.ConcurrentRotatingFileHandler',
           autospec=True)
    @patch('logging.StreamHandler', autospec=True)
    @patch('logging.Formatter', autospec=True)
    def test_configure_logger(self, m_logging_f, m_logging_sh,
                              m_logging_fh, m_os_makedirs, m_os_path):
        """Test configure_logger

        Check calls for valid arguments.
        """
        m_os_path.exists.return_value = False
        m_log = Mock()
        f_handler = Mock()
        s_handler = Mock()
        m_logging_fh.return_value = f_handler
        m_logging_sh.return_value = s_handler

        logutils.configure_logger(logger=m_log,
                                  log_level=logging.DEBUG,
                                  docker_id="abcd1234",
                                  log_format="FORMAT",
                                  log_dir='/mock/')

        m_os_makedirs.assert_called_once_with('/mock/')
        m_logging_fh.assert_called_once_with(filename='/mock/calico.log',
                                             maxBytes=1000000,
                                             backupCount=5)
        m_logging_f.assert_called_once_with("FORMAT")
        m_log.setLevel.assert_called_once_with(logging.DEBUG)

        # Test stdout config calls.
        m_log.addHandler.assert_has_calls([call(f_handler), 
                                           call(s_handler)])

    def test_filter(self):
        """Test filter method for IdentityFilterClass"""
        record = Mock(spec=LogRecord)
        identity_filter = logutils.IdentityFilter("ID")
        test_result = identity_filter.filter(record)

        assert_equal(record.identity, "ID")
        assert_true(test_result)

    def test_api_root_secure_true(self):
        """Test api_root_secure output for https

        Should return True
        """
        self.plugin.api_root = "https://test.com"
        return_val = self.plugin._api_root_secure()
        assert_true(return_val)

    def test_api_root_secure_false(self):
        """Test api_root_secure output for http

        Should return False
        """
        self.plugin.api_root = "http://test.com"
        return_val = self.plugin._api_root_secure()
        assert_false(return_val)

    def test_api_root_secure_error(self):
        """Test api_root_secure output for invalid http(s) scheme

        Should raise SystemExit
        """
        self.plugin.api_root = "invalid"
        assert_raises(SystemExit, self.plugin._api_root_secure)

    @patch("calico_kubernetes.calico_kubernetes.read_config_file", autospec=True)
    @patch("calico_kubernetes.calico_kubernetes.os.environ", autospec=True)
    def test_load_config_no_env(self, m_os_env, m_read_file):
        """test_load_config when no env vars defined

        When no environment varibles are defined, should use
        the file configuration.
        """
        # Mock
        file_resp = {
            ETCD_AUTHORITY_VAR: "etcd-auth",
            KUBE_AUTH_TOKEN_VAR: "kube-auth",
            KUBE_API_ROOT_VAR: "kube-api",
            DEFAULT_POLICY_VAR: "none",
            CALICO_IPAM_VAR: "calico-ipam",
            LOG_LEVEL_VAR: "log-level",
        }
        # Deepcopy so that the original is not modified.
        m_read_file.return_value = copy.deepcopy(file_resp)

        # Mock get() to return default value.
        m_os_env.get.side_effect = lambda x,y: y

        # Call method
        config = calico_kubernetes.load_config()

        # The response should equal the file config.
        file_resp[LOG_LEVEL_VAR] = "LOG-LEVEL"
        assert_equal(config, file_resp)

    @patch("calico_kubernetes.calico_kubernetes.read_config_file", autospec=True)
    @patch("calico_kubernetes.calico_kubernetes.os", autospec=True)
    def test_load_config_env(self, m_os, m_read_file):
        """test_load_config when env vars defined
        """
        # Mock
        file_resp = {
            ETCD_AUTHORITY_VAR: "",
            KUBE_AUTH_TOKEN_VAR: "",
            KUBE_API_ROOT_VAR: "",
            DEFAULT_POLICY_VAR: "",
            CALICO_IPAM_VAR: "",
            LOG_LEVEL_VAR: "",
        }
        m_read_file.return_value = file_resp
        m_os.environ.get.side_effect = lambda x,y: x

        # Mock out reading from environment.
        get_dict = {
            ETCD_AUTHORITY_VAR: "etcd",
            KUBE_AUTH_TOKEN_VAR: "auth",
            KUBE_API_ROOT_VAR: "api",
            DEFAULT_POLICY_VAR: "none",
            CALICO_IPAM_VAR: "ipam",
            LOG_LEVEL_VAR: "DEBUG",
        }
        m_os.environ.get.side_effect = lambda x,y : get_dict.get(x,y)
        # Call method
        config = calico_kubernetes.load_config()

        # The response should equal the file config.
        expected_resp = {
            ETCD_AUTHORITY_VAR: "etcd",
            KUBE_AUTH_TOKEN_VAR: "auth",
            KUBE_API_ROOT_VAR: "api",
            DEFAULT_POLICY_VAR: "none",
            CALICO_IPAM_VAR: "ipam",
            LOG_LEVEL_VAR: "DEBUG",
        }
        assert_equal(config, expected_resp)

    @patch("calico_kubernetes.calico_kubernetes.ConfigParser.ConfigParser", autospec=True)
    @patch("calico_kubernetes.calico_kubernetes.os", autospec=True)
    def test_read_config_file(self, m_os, m_parser):
        """test_read_config_file

        Tests reading from config file.
        """
        # Mock
        m_parser().sections.return_value = ["config"]
        m_parser().get.return_value = "default"
        m_os.path.isfile.return_value = True

        # Call method under test
        config = calico_kubernetes.read_config_file()

        # Assert config equal
        expected = {
            ETCD_AUTHORITY_VAR: "default",
            KUBE_AUTH_TOKEN_VAR: "default",
            KUBE_API_ROOT_VAR: "default",
            DEFAULT_POLICY_VAR: "default",
            CALICO_IPAM_VAR: "default",
            LOG_LEVEL_VAR: "default",
        }
        assert_equal(config, expected)

    @patch("calico_kubernetes.calico_kubernetes.ConfigParser.ConfigParser", autospec=True)
    @patch("calico_kubernetes.calico_kubernetes.os", autospec=True)
    def test_read_config_file_invalid(self, m_os, m_parser):
        """test_read_config_file_invalid no config section.

        Invalid config file - no [section]
        """
        # Mock
        m_parser().sections.return_value = []
        m_os.path.isfile.return_value = True

        # Call method under test
        assert_raises(SystemExit, calico_kubernetes.read_config_file)

    @patch("calico_kubernetes.calico_kubernetes.ConfigParser.ConfigParser", autospec=True)
    @patch("calico_kubernetes.calico_kubernetes.os", autospec=True)
    def test_read_config_file_missing(self, m_os, m_parser):
        """test_read_config_file_missing
        """
        # Mock
        m_os.path.isfile.return_value = False

        # Defaults
        defaults = {
            ETCD_AUTHORITY_VAR: "127.0.0.1:2379",
            CALICO_IPAM_VAR: "true",
            KUBE_API_ROOT_VAR: "http://kubernetes-master:8080/api/v1",
            DEFAULT_POLICY_VAR: "allow",
            KUBE_AUTH_TOKEN_VAR: None,
            LOG_LEVEL_VAR: "INFO",
        }

        # Call method under test
        assert_equal(defaults, calico_kubernetes.read_config_file())

    def test_validate_config(self):
        """
        Tests validation of config dictionary.
        """
        config = {
            DEFAULT_POLICY_VAR: "invalidvalue",
        }

        assert_raises(SystemExit, calico_kubernetes.validate_config, config)
