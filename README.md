# Calico Networking for Kubernetes
> NOTE: This repository is currently a work in progress and is not guarenteed to be stable.  For stable Kubernetes support and documentation, please see the Kubernetes section in the [calico-docker](https://github.com/projectcalico/calico-docker/tree/master/docs/kubernetes) repo. 

Calico can be integrated into Kubernetes using the native Kubernetes network plugin API.  Calico is particularly suitable for large Kubernetes deployments on bare metal or private clouds, where the performance and complexity costs of overlay networks can become significant. It can also be used in public clouds.

For more information on Project Calico see http://www.projectcalico.org/learn/.

### Getting Started
The easiest way to get started with the Calico Kubernetes plugin is by following one of our guides [here](https://github.com/projectcalico/calico-docker/tree/master/docs/kubernetes).

### Building the plugin
To build the calico-kubernetes plugin, clone this repository and run `make`.  This will build the binary, as well as run the unit tests.  To just build the binary, with no tests, run `make binary`.  To only run the unit tests, simply run `make ut`.

