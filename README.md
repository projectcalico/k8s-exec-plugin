[![CircleCI branch](https://img.shields.io/circleci/project/projectcalico/calico-kubernetes/master.svg)](https://circleci.com/gh/projectcalico/calico-kubernetes/tree/master)
[![Coverage Status](https://coveralls.io/repos/projectcalico/calico-kubernetes/badge.svg?branch=master&service=github)](https://coveralls.io/github/projectcalico/calico-kubernetes?branch=master)
[![Slack Status](https://calicousers-slackin.herokuapp.com/badge.svg)](https://calicousers-slackin.herokuapp.com)
[![IRC Channel](https://img.shields.io/badge/irc-%23calico-blue.svg)](https://kiwiirc.com/client/irc.freenode.net/#calico)

# Calico Networking for Kubernetes
Calico can be integrated into Kubernetes using the native Kubernetes network plugin API.  Calico is particularly suitable for large Kubernetes deployments on bare metal or private clouds, where the performance and complexity costs of overlay networks can become significant. It can also be used in public clouds.

For more information on Project Calico see http://www.projectcalico.org/learn/.

### Getting Started
The easiest way to get started with the Calico Kubernetes plugin is by following one of our guides [in the calico-docker repository](https://github.com/projectcalico/calico-docker/tree/master/docs/kubernetes).

### Building the plugin
To build the calico-kubernetes plugin, clone this repository and run `make`.  This will build the binary, as well as run the unit tests.  To just build the binary, with no tests, run `make binary`.  To only run the unit tests, simply run `make ut`.

