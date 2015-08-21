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

import json
import unittest
from mock import patch, Mock, call
from netaddr import IPAddress, IPNetwork
from subprocess import CalledProcessError
from docker.errors import APIError
from calico_kubernetes import calico_kubernetes
from pycalico.datastore import IF_PREFIX
from pycalico.datastore_datatypes import Profile, Endpoint

TEST_HOST = calico_kubernetes.HOSTNAME
TEST_ORCH_ID = calico_kubernetes.ORCHESTRATOR_ID



class NetworkPluginTest(unittest.TestCase):

    def setUp(self):
        # Mock out sh so it doesn't fail when trying to find the
        # calicoctl binary (which may not exist)
        with patch('calico_kubernetes.calico_kubernetes.sh.Command',
                   autospec=True) as m_sh:
            self.plugin = calico_kubernetes.NetworkPlugin()

    def test_create(self):
        with patch.object(self.plugin, '_configure_interface',
                    autospec=True) as m_configure_interface, \
                patch.object(self.plugin, '_configure_profile',
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
            self.assertEqual(namespace, self.plugin.namespace)
            self.assertEqual(pod_name, self.plugin.pod_name)
            self.assertEqual(docker_id, self.plugin.docker_id)
            self.assertEqual(profile_name, self.plugin.profile_name)
            m_configure_interface.assert_called_once_with()
            m_configure_profile.assert_called_once_with('endpt_id')

    def test_create_error(self):
        with patch.object(self.plugin, '_configure_interface',
                    autospec=True) as m_configure_interface, \
                patch('sys.exit', autospec=True) as m_sys_exit:
            # Set up mock objects
            m_configure_interface.side_effect = CalledProcessError(1,'','')

            # Set up args
            namespace = 'ns'
            pod_name = 'pod1'
            docker_id = 13

            # Call method under test
            self.plugin.create(namespace, pod_name, docker_id)

            # Assert
            m_sys_exit.assert_called_once_with(1)

    def test_delete(self):
        with patch.object(self.plugin, '_datastore_client', autospec=True) as m_datastore_client, \
                patch.object(self.plugin, '_docker_client', autospec=True) as m_docker_client, \
                patch.object(self.plugin, '_container_remove', autospec=True) as m_container_remove:
            # Set up mock objs
            workload_id = 19
            m_datastore_client.profile_exists.return_value = True

            # Set up args
            namespace = 'ns'
            pod_name = 'pod1'
            docker_id = 123456789101112
            profile_name = 'ns_pod1_123456789101'

            # Call method under test
            self.plugin.delete(namespace, pod_name, docker_id)

            # Assert
            m_container_remove.assert_called_once_with()
            self.assertEqual(namespace, self.plugin.namespace)
            self.assertEqual(pod_name, self.plugin.pod_name)
            self.assertEqual(docker_id, self.plugin.docker_id)
            self.assertEqual(profile_name, self.plugin.profile_name)
            m_datastore_client.remove_profile(profile_name)

    def test_configure_interface(self):
        with patch.object(self.plugin, '_read_docker_ip',
                    autospec=True) as m_read_docker_ip, \
                patch.object(self.plugin, '_get_container_pid', autospec=True) as m_get_container_pid, \
                patch.object(self.plugin, '_delete_docker_interface',
                    autospec=True) as m_delete_docker_interface, \
                patch.object(self.plugin, '_container_add',
                    autospec=True) as m_container_add, \
                patch.object(calico_kubernetes, 'generate_cali_interface_name',
                    autospec=True) as m_generate_cali_interface_name, \
                patch.object(self.plugin, '_get_node_ip',
                    autospec=True) as m_get_node_ip, \
                patch.object(calico_kubernetes, 'check_call',
                    autospec=True) as m_check_call:
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
            self.assertEqual(return_val, endpoint)


    def test_container_add(self):
        with patch.object(self.plugin, '_datastore_client',
                autospec=True) as m_datastore_client,\
            patch.object(self.plugin, '_validate_container_state',
                autospec=True) as m_validate_container_state, \
            patch('calico_kubernetes.calico_kubernetes.netns.PidNamespace', autospec=True) as m_pid_ns,\
            patch.object(self.plugin, '_read_docker_ip', autospec=True) as m_read_docker_ip:
            # Set up mock objs
            m_datastore_client.get_endpoint.side_effect = KeyError
            endpoint = Endpoint(TEST_HOST, TEST_ORCH_ID, '1234', '5678',
                                'active', 'mac')
            endpoint.provision_veth = Mock()
            endpoint.provision_veth.return_value = 'new_mac'
            m_datastore_client.create_endpoint.return_value = endpoint

            # Set up arguments
            container_name = 'container_name'
            self.plugin.docker_id = container_name
            pid = 'pid'
            ip = IPAddress('1.1.1.1')
            interface = 'eth0'
            hostname = TEST_HOST
            orchestrator_id = TEST_ORCH_ID

            # Call method under test
            test_return = self.plugin._container_add(pid, interface)

            # Assert
            m_datastore_client.get_endpoint.assert_called_once_with(
                hostname=hostname,
                orchestrator_id=orchestrator_id,
                workload_id=self.plugin.docker_id
            )
            m_validate_container_state.assert_called_once_with(container_name)
            m_datastore_client.set_endpoint.assert_called_once_with(endpoint)
            endpoint.provision_veth.assert_called_once_with(m_pid_ns(pid), interface)
            self.assertEqual(endpoint.mac, 'new_mac')
            self.assertEqual(test_return, endpoint)

    def test_container_add_container_exists(self):
        """
        Test _container_add method when container already exists.

        Expect system exit.
        """
        with patch.object(self.plugin, '_datastore_client',
                autospec=True) as m_datastore_client:
            # Set up arguments
            container_name = 'container_name'
            workload_id = 'workload_id'
            pid = 'pid'
            interface = 'eth0'
            hostname = TEST_HOST
            orchestrator_id = TEST_ORCH_ID

            # Call method under test
            self.assertRaises(SystemExit, self.plugin._container_add, pid, interface)

    def test_container_remove(self):
        with patch.object(self.plugin, '_datastore_client', autospec=True) as m_datastore_client,\
            patch('calico_kubernetes.calico_kubernetes.netns.remove_veth', autospec=True) as m_remove_veth:
            #Set up mock objs
            endpoint = Endpoint(TEST_HOST, TEST_ORCH_ID, '1234', '5678',
                                'active', 'mac')
            ipv4 = IPAddress('1.1.1.1')
            ipv6 = IPAddress('201:db8::')
            endpoint.ipv4_nets.add(IPNetwork(ipv4))
            endpoint.ipv6_nets.add(IPNetwork(ipv6))
            m_datastore_client.get_endpoint.return_value = endpoint

            # Set up arguments
            self.plugin.docker_id = "abcd"
            hostname = TEST_HOST
            orchestrator_id = TEST_ORCH_ID

            # Call method under test
            test_return = self.plugin._container_remove()

            # Assert
            m_datastore_client.get_endpoint.assert_called_once_with(
                hostname=hostname,
                orchestrator_id=orchestrator_id,
                workload_id='abcd'
            )

            m_remove_veth.assert_called_once_with(endpoint.name)

    def test_container_remove_no_endpoints(self):
        """
        Test _container_remove when the container does not container any endpoints

        Expect a system exit
        """
        with patch.object(self.plugin, '_datastore_client', autospec=True) as m_datastore_client:
            m_datastore_client.get_endpoint.side_effect = KeyError

            # Set up arguments
            hostname = TEST_HOST
            orchestrator_id = TEST_ORCH_ID

            # Call method under test
            self.assertRaises(SystemExit, self.plugin._container_remove)

    def test_validate_container_state(self):
        with patch.object(self.plugin, '_get_container_info', autospec=True) as m_get_container_info:
            # Set up mock objs
            info_dict = {'State': {'Running': 1}, 'HostConfig': {'NetworkMode': ''}}
            m_get_container_info.return_value = info_dict

            # Call method under test
            self.plugin._validate_container_state('container_name')

            # Assert
            m_get_container_info.assert_called_once_with('container_name')
            self.assertTrue(info_dict['State']['Running'])
            self.assertNotEqual(info_dict['HostConfig']['NetworkMode'], 'host')

    def test_validate_container_state_not_running(self):
        """
        Test _validate_container_state when the container is not running

        Expect system exit
        """
        with patch.object(self.plugin, '_get_container_info', autospec=True) as m_get_container_info:
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
        with patch.object(self.plugin, '_get_container_info', autospec=True) as m_get_container_info:
            # Set up mock objs
            info_dict = {'State': {'Running': 1}, 'HostConfig': {'NetworkMode': 'host'}}
            m_get_container_info.return_value = info_dict

            # Call method under test
            self.assertRaises(SystemExit, self.plugin._validate_container_state,
                              'container_name')

    def test_get_container_info(self):
        with patch.object(self.plugin, '_docker_client', autospec=True) as m_docker_client:
            # Set up args
            container_name = 'container_name'

            # Call method under test
            self.plugin._get_container_info(container_name)

            # Assert
            m_docker_client.inspect_container.assert_called_once_with(container_name)

    def test_get_container_info_docker_api_error(self):
        with patch.object(self.plugin, '_docker_client', autospec=True) as m_docker_client:
            # Create mock side effect APIError
            m_docker_client.inspect_container.side_effect = APIError('Error', Mock())

            # Set up args
            container_name = 'container_name'

            # Call method under test
            self.assertRaises(SystemExit, self.plugin._get_container_info, container_name)

    def test_get_container_pid(self):
        with patch.object(self.plugin, '_get_container_info', autospec=True) as m_get_container_info:
            # Set up args
            container_name = 'container_name'

            # Call method under test
            self.plugin._get_container_pid(container_name)

            # Assert
            m_get_container_info.assert_called_once_with(container_name)

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
            self.assertEqual(return_val, '1.2.3.4')

    def test_get_node_ip(self):
        with patch('calico_kubernetes.calico_kubernetes.get_host_ips',
                   autospec=True) as m_get_host_ips:
            # Set up mock objects
            m_get_host_ips.return_value = []

            # Call method under test
            self.assertRaises(SystemExit, self.plugin._get_node_ip)

    def test_read_docker_ip(self):
        with patch.object(self.plugin, '_get_container_info',
                          autospec=True) as m_get_container_info:
            # Set up mock objects
            m_get_container_info.return_value = {'NetworkSettings': {'IPAddress': '1.2.3.4'}}

            # Call method under test
            return_val = self.plugin._read_docker_ip()

            # Assert
            m_get_container_info.assert_called_once_with(self.plugin.docker_id)
            self.assertEqual(return_val, IPAddress('1.2.3.4'))

    def test_delete_docker_interface(self):
        with patch.object(calico_kubernetes, 'check_output',
                          autospec=True) as m_check_output,\
                patch.object(self.plugin, '_get_container_pid', autospec=True) as m_get_container_pid:
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
        with patch.object(self.plugin, '_datastore_client',
                    autospec=True) as m_datastore_client, \
                patch.object(self.plugin, '_get_namespace_tag',
                    autospec=True) as m_get_namespace_tag, \
                patch.object(self.plugin, '_get_pod_config',
                    autospec=True) as m_get_pod_config, \
                patch.object(self.plugin, '_apply_rules',
                    autospec=True) as m_apply_rules, \
                patch.object(self.plugin, '_apply_tags',
                    autospec=True) as m_apply_tags:
            # Set up mock objects
            m_datastore_client.profile_exists.return_value = False
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
            m_datastore_client.profile_exists.assert_called_once_with(self.plugin.profile_name)
            m_datastore_client.create_profile.assert_called_once_with(self.plugin.profile_name)
            m_get_pod_config.assert_called_once_with()
            m_apply_rules.assert_called_once_with('pod')
            m_apply_tags.assert_called_once_with('pod')
            m_datastore_client.set_profiles_on_endpoint.assert_called_once_with(
                [profile_name], endpoint_id=endpoint.endpoint_id)

    def test_configure_profile_profile_exists(self):
        """
        Test _configure_profile when profile already exists.

        Expect system exit.
        """
        with patch.object(self.plugin, '_datastore_client',
                    autospec=True) as m_datastore_client, \
                patch.object(self.plugin, '_get_pod_config',
                    autospec=True) as m_get_pod_config:
            # Set up mock objects
            m_datastore_client.profile_exists.return_value = True
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
            m_datastore_client.profile_exists.assert_called_once_with(profile_name)
            self.assertFalse(m_datastore_client.create_profile.called)


    def test_get_pod_ports(self):
        # Initialize pod dictionary and expected outcome
        pod = {'spec': {'containers': [{'ports': [1, 2, 3]},{'ports': [4, 5]}]}}
        ports = [1, 2, 3, 4, 5]

        # Call method under test
        return_val = self.plugin._get_pod_ports(pod)

        # Assert
        self.assertEqual(return_val, ports)

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
        with patch.object(self.plugin, '_get_api_path',
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
            self.assertEqual(return_val, pod2)

    def test_get_pod_config_error(self):
        with patch.object(self.plugin, '_get_api_path',
                    autospec=True) as m_get_api_path:
            # Set up mock object and class members
            pod1 = {'metadata': {'name': 'pod-1'}}
            pod2 = {'metadata': {'name': 'pod-2'}}
            pod3 = {'metadata': {'name': 'pod-3'}}
            pods = [pod1, pod2, pod3]
            m_get_api_path.return_value = pods

            # Set up class member
            self.plugin.pod_name = 'pod_4'

            # Call method under test expecting exception
            with self.assertRaises(KeyError):
                self.plugin._get_pod_config()

    def test_get_api_path(self):
        with patch.object(self.plugin, '_get_api_token',
                    autospec=True) as m_api_token, \
                patch('calico_kubernetes.calico_kubernetes.requests.Session',
                    autospec=True) as m_session, \
                patch.object(json, 'loads', autospec=True) as m_json_load:
            # Set up mock objects
            m_api_token.return_value = 'Token'
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

            # Assert
            m_api_token.assert_called_once_with()
            m_session.assert_called_once_with()
            m_session_return.headers.update.assert_called_once_with(
                {'Authorization': 'Bearer ' + 'Token'})
            m_session_return.get.assert_called_once_with(
                calico_kubernetes.KUBE_API_ROOT + 'path/to/api/object',
                verify=False)
            m_json_load.assert_called_once_with('response_body')

    def test_get_api_token(self):
        with patch('__builtin__.open', autospec=True) as m_open, \
                patch.object(json, 'loads', autospec=True) as m_json:
            # Set up mock objects
            m_open().__enter__().read.return_value = 'json_string'
            m_open.reset_mock()
            m_json.return_value = {'BearerToken' : 'correct_return'}

            # Call method under test
            return_val = self.plugin._get_api_token()

            # Assert
            m_open.assert_called_once_with('/var/lib/kubelet/kubernetes_auth')
            m_json.assert_called_once_with('json_string')
            self.assertEqual(return_val, 'correct_return')

    def test_get_api_token_no_auth_file(self):
        """
        Test _get_api_token when no autho token is found

        Assert that the method returns an empty string
        """
        with patch('__builtin__.open', autospec=True) as m_open, \
                patch.object(json, 'loads', autospec=True) as m_json:
            # Set up mock objects
            m_open.side_effect = IOError
            m_json.return_value = {'BearerToken' : 'correct_return'}

            # Call method under test
            return_val = self.plugin._get_api_token()

            m_open.assert_called_once_with('/var/lib/kubelet/kubernetes_auth')
            self.assertFalse(m_json.called)
            self.assertEqual(return_val, "")

    def test_generate_rules(self):
        pod = {'metadata': {'profile': 'name'}}

        # Call method under test empty annotations/namespace
        return_val = self.plugin._generate_rules(pod)

        # Assert
        self.assertEqual(return_val, ([["allow"]], [["allow"]]))

    def test_apply_rules(self):
        with patch.object(self.plugin, '_generate_rules',
                    autospec=True) as m_generate_rules, \
                patch.object(self.plugin, '_datastore_client',
                    autospec=True) as m_datastore_client, \
                patch.object(self.plugin, 'calicoctl',
                    autospec=True) as m_calicoctl:

            # Set up mock objects
            m_profile = Mock()
            m_datastore_client.get_profile.return_value = m_profile
            m_generate_rules.return_value = ([["allow"]], [["allow"]])
            m_calicoctl.return_value = None
            profile_name = 'a_b_c'
            self.plugin.profile_name = profile_name
            pod = {'metadata': {'namespace': 'a', 'profile': 'name'}}
            self.plugin.namespace = pod['metadata']['namespace']

            # Call method under test
            self.plugin._apply_rules(pod)

            # Assert
            m_datastore_client.get_profile.assert_called_once_with(profile_name)
            m_calicoctl.assert_has_calls([
                call('profile', profile_name, 'rule', 'remove', 'inbound', '--at=2'),
                call('profile', profile_name, 'rule', 'remove', 'inbound', '--at=1'),
                call('profile', profile_name, 'rule', 'remove', 'outbound', '--at=1')
                ])
            m_generate_rules.assert_called_once_with(pod)
            m_datastore_client.profile_update_rules(m_profile)

    def test_apply_rules_profile_not_found(self):
        with patch.object(self.plugin, '_datastore_client', autospec=True) as m_datastore_client:
            m_datastore_client.get_profile.side_effect = KeyError
            self.assertRaises(SystemExit, self.plugin._apply_rules, 'profile')

    def test_apply_tags(self):
        with patch.object(self.plugin, '_datastore_client', autospec=True) as m_datastore_client:
            # Intialize args
            pod = {'metadata': {'namespace': 'a', 'labels': {1: 2, "2/3": "4_5"}}}
            self.plugin.namespace = pod['metadata']['namespace']
            self.plugin.profile_name = 'profile_name'

            # Set up mock objs
            m_profile = Mock(spec=Profile, name = self.plugin.profile_name)
            m_profile.tags = set()
            m_datastore_client.get_profile.return_value = m_profile

            check_tags = set()
            check_tags.add('namespace_a')
            check_tags.add('a_1_2')
            check_tags.add('a_2_3_4__5')

            # Call method under test
            self.plugin._apply_tags(pod)

            # Assert
            m_datastore_client.get_profile.assert_called_once_with(self.plugin.profile_name)
            m_datastore_client.profile_update_tags.assert_called_once_with(m_profile)
            self.assertEqual(m_profile.tags, check_tags)

    def test_apply_tags_no_labels(self):
        with patch.object(self.plugin, '_datastore_client', autospec=True) as m_datastore_client:
            # Intialize args
            pod = {}
            self.plugin.profile_name = 'profile_name'
            m_datastore_client.get_profile.return_value = Mock()

            # Call method under test
            self.plugin._apply_tags(pod)

            # Assert
            self.assertFalse(m_datastore_client.called)

    def test_apply_tags_profile_not_found(self):
        with patch.object(self.plugin, '_datastore_client', autospec=True) as m_datastore_client:
            # Intialize args
            pod = {'metadata': {'labels': {1: 1, 2: 2}}}
            profile_name = 'profile_name'

            # Set up mock objs
            m_datastore_client.get_profile.side_effect = KeyError

            # Call method under test expecting sys exit
            self.assertRaises(SystemExit, self.plugin._apply_tags, pod)
