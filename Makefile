.PHONY: all binary ut clean run-service-proxy run-kubernetes-master

SRCFILES=$(shell find calico_kubernetes)
LOCAL_IP_ENV?=$(shell ip route get 8.8.8.8 | head -1 | cut -d' ' -f8)
K8S_VERSION=1.1.2

default: all
all: binary test
test: ut
binary: dist/calico

dist/calico: $(SRCFILES)
	mkdir -p dist
	chmod 777 `pwd`/dist

	# Stop the master kubelet since if it's running it holds a lock on the file
	-docker stop calico-kubelet-master
	# Build the kubernetes plugin
	docker pull calico/build:latest
	docker run \
	-u user \
	-v `pwd`/dist:/code/dist \
	-v `pwd`/calico_kubernetes:/code/calico_kubernetes \
	calico/build pyinstaller calico_kubernetes/calico_kubernetes.py -n calico -a -F -s --clean

ut:
	docker run --rm -v `pwd`/calico_kubernetes:/code/calico_kubernetes \
	-v `pwd`/calico_kubernetes/nose.cfg:/code/nose.cfg \
	calico/test \
	nosetests calico_kubernetes/tests -c nose.cfg

# UT runs on Cicle
ut-circle: binary
	# Can't use --rm on circle
	# Circle also requires extra options for reporting.
	docker run \
	-v `pwd`:/code \
	-v $(CIRCLE_TEST_REPORTS):/circle_output \
	-e COVERALLS_REPO_TOKEN=$(COVERALLS_REPO_TOKEN) \
	calico/test sh -c \
	'	nosetests calico_kubernetes/tests -c nose.cfg \
	--with-xunit --xunit-file=/circle_output/output.xml; RC=$$?;\
	[[ ! -z "$$COVERALLS_REPO_TOKEN" ]] && coveralls || true; exit $$RC'

dist/calicoctl:
	mkdir -p dist
	curl -L http://www.projectcalico.org/latest/calicoctl -o dist/calicoctl
	chmod +x dist/calicoctl

run-kubernetes-master: stop-kubernetes-master run-etcd run-service-proxy binary dist/calicoctl kubectl
	# Run the kubelet which will launch the master components in a pod.
	docker run \
	--name calico-kubelet-master \
	--volume=`pwd`/dist:/usr/libexec/kubernetes/kubelet-plugins/net/exec/calico:ro \
	--volume=/:/rootfs:ro \
	--volume=/sys:/sys:ro \
	--volume=/dev:/dev \
	--volume=/var/lib/docker/:/var/lib/docker:rw \
	--volume=/var/lib/kubelet/:/var/lib/kubelet:rw \
	--volume=/var/run:/var/run:rw \
	--net=host \
	--pid=host \
	--privileged=true \
	-e KUBE_API_ROOT=http://localhost:8080/api/v1/ \
	-d \
	gcr.io/google_containers/hyperkube:v$(K8S_VERSION) \
	/hyperkube kubelet --network-plugin calico --v=5 --containerized --hostname-override="127.0.0.1" --address="0.0.0.0" --api-servers=http://localhost:8080 --config=/etc/kubernetes/manifests

	# Start the calico node
	sudo dist/calicoctl node

stop-kubernetes-master:
	# Stop any existing kubelet that we started
	-docker rm -f calico-kubelet-master

	# Remove any pods that the old kubelet may have started.
	-docker rm -f $$(docker ps | grep k8s_ | awk '{print $$1}')

run-kube-proxy:
	-docker rm -f calico-kube-proxy
	docker run --name calico-kube-proxy -d --net=host --privileged gcr.io/google_containers/hyperkube:v$(K8S_VERSION) /hyperkube proxy --master=http://127.0.0.1:8080 --v=2

kubectl:
	wget http://storage.googleapis.com/kubernetes-release/release/v$(K8S_VERSION)/bin/linux/amd64/kubectl
	chmod 755 kubectl

## Run etcd in a container. Used by the STs and generally useful.
run-etcd:
	@-docker rm -f calico-etcd
	docker run --detach \
	--net=host \
	--name calico-etcd quay.io/coreos/etcd:v2.2.2 \
	--advertise-client-urls "http://$(LOCAL_IP_ENV):2379,http://127.0.0.1:2379,http://$(LOCAL_IP_ENV):4001,http://127.0.0.1:4001" \
	--listen-client-urls "http://0.0.0.0:2379,http://0.0.0.0:4001"

clean:
	find . -name '*.pyc' -exec rm -f {} +
	-rm kubectl
	-rm -rf dist
	-docker run -v /var/run/docker.sock:/var/run/docker.sock -v /var/lib/docker:/var/lib/docker --rm martin/docker-cleanup-volumes

