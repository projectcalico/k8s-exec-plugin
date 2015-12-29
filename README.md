[![CircleCI branch](https://img.shields.io/circleci/project/projectcalico/calico-kubernetes/master.svg)](https://circleci.com/gh/projectcalico/calico-kubernetes/tree/master)
[![Coverage Status](https://coveralls.io/repos/projectcalico/calico-kubernetes/badge.svg?branch=master&service=github)](https://coveralls.io/github/projectcalico/calico-kubernetes?branch=master)
[![Slack Status](https://calicousers-slackin.herokuapp.com/badge.svg)](https://calicousers-slackin.herokuapp.com)
[![IRC Channel](https://img.shields.io/badge/irc-%23calico-blue.svg)](https://kiwiirc.com/client/irc.freenode.net/#calico)

# Calico Networking for Kubernetes
## Migration to CNI
Calico networking for Kubernetes can now be found in the [Calico CNI repository](https://github.com/caseydavenport/calico-cni). We recommend migrating to use the Calico CNI plugin for Kubernetes deployments.  We will be updating our existing guides and documentation to use the Calico CNI plugin shortly.

### Getting Started
The easiest way to get started with the Calico Kubernetes plugin is by following one of our guides [in the calico-docker repository](https://github.com/projectcalico/calico-docker/tree/master/docs/kubernetes).
...or just run `make run-kubernetes-master` which will build the calico plugin from source and then create a single node Kubernetes cluster.

For more information on Project Calico see http://www.projectcalico.org/learn/.

### Building the plugin
To build the calico-kubernetes plugin, clone this repository and run `make`.  This will build the binary, as well as run the unit tests.  To just build the binary, with no tests, run `make binary`.  To only run the unit tests, simply run `make ut`.

[![Analytics](https://ga-beacon.appspot.com/UA-52125893-3/calico-kubernetes/README.md?pixel)](https://github.com/igrigorik/ga-beacon)
