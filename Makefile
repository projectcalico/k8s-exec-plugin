.PHONY: all binary ut clean

SRCDIR=calico_kubernetes
BUILD_DIR=.
BUILD_FILES=$(BUILD_DIR)/Dockerfile $(BUILD_DIR)/requirements.txt

default: all
all: binary test
test: ut

# Build a new docker image to be used by binary or tests
buildcontainer.created: $(BUILD_FILES)
	docker build -t calico/kubernetes-cni-build .
	touch buildcontainer.created

binary: buildcontainer.created
	mkdir -p dist
	chmod 777 `pwd`/dist
	
	# Build the kubernetes plugin
	docker run \
	-u user \
	-v `pwd`/calico_kubernetes:/code/calico_kubernetes \
	-v `pwd`/dist:/code/dist \
	-e PYTHONPATH=/code/calico_kubernetes \
	calico/kubernetes-cni-build pyinstaller calico_kubernetes/calico_kubernetes_cni.py -a -F -s --clean

ut: buildcontainer.created
	docker run --rm -v `pwd`/calico_kubernetes:/code/calico_kubernetes \
	-v `pwd`/nose.cfg:/code/nose.cfg \
	calico/kubernetes-cni-build bash -c \
	'>/dev/null 2>&1 & PYTHONPATH=/code/calico_kubernetes \
	nosetests calico_kubernetes/tests -c nose.cfg'

# UT runs on Cicle
ut-circle: binary
	# Can't use --rm on circle
	# Circle also requires extra options for reporting.
	docker run \
	-v `pwd`/calico_kubernetes:/code/calico_kubernetes \
	-v `pwd`/nose.cfg:/code/nose.cfg \
	-v $(CIRCLE_TEST_REPORTS):/circle_output \
	-e COVERALLS_REPO_TOKEN=$(COVERALLS_REPO_TOKEN) \
	calico/kubernetes-cni-build bash -c \
	'>/dev/null 2>&1 & PYTHONPATH=/code/calico_kubernetes \
	nosetests calico_kubernetes/tests -c nose.cfg \
	--with-xunit --xunit-file=/circle_output/output.xml; RC=$$?;\
	[[ ! -z "$$COVERALLS_REPO_TOKEN" ]] && coveralls || true; exit $$RC'

clean:
	-rm -f *.created
	find . -name '*.pyc' -exec rm -f {} +
	-rm -rf dist
	-docker rmi -f calico/kubernetes-cni-build
	-docker run -v /var/run/docker.sock:/var/run/docker.sock -v /var/lib/docker:/var/lib/docker --rm martin/docker-cleanup-volumes

