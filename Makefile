.PHONY: all binary ut clean

BUILD_DIR=build_calico_kubernetes
BUILD_FILES=$(BUILD_DIR)/Dockerfile $(BUILD_DIR)/requirements.txt

default: all
all: binary test
binary: dist/calico_kubernetes
test: ut

# Build a new docker image to be used by binary or tests
kubernetesbuild.created: $(BUILD_FILES)
	cd build_calico_kubernetes; docker build -t calico/kubernetes-build .
	touch kubernetesbuild.created

dist/calico_kubernetes: kubernetesbuild.created
	mkdir -p dist
	chmod 777 `pwd`/dist
	
	# Build the kubernetes plugin
	docker run \
	-u user \
	-v `pwd`/calico_kubernetes:/code/calico_kubernetes \
	-v `pwd`/dist:/code/dist \
	-e PYTHONPATH=/code/calico_kubernetes \
	calico/kubernetes-build pyinstaller calico_kubernetes/calico_kubernetes.py -a -F -s --clean

ut: dist/calico_kubernetes
	docker run --rm -v `pwd`/calico_kubernetes:/code/calico_kubernetes \
	-v `pwd`/nose.cfg:/code/nose.cfg \
	calico/kubernetes-build bash -c \
	'/tmp/etcd -data-dir=/tmp/default.etcd/ >/dev/null 2>&1 & \
	PYTHONPATH=/code/calico_kubernetes nosetests calico_kubernetes/tests -c nose.cfg'

clean:
	-rm -f *.created
	find . -name '*.pyc' -exec rm -f {} +
	-rm -rf dist
	-docker rm -f calico-build
	-docker rmi calico/kubernetes-build
	-docker run -v /var/run/docker.sock:/var/run/docker.sock -v /var/lib/docker:/var/lib/docker --rm martin/docker-cleanup-volumes

