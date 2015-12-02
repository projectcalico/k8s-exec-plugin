.PHONY: all binary ut clean

SRCFILES=$(shell find calico_kubernetes)

default: all
all: binary test
test: ut
binary: dist/calico_kubernetes

dist/calico_kubernetes: $(SRCFILES)
	mkdir -p dist
	chmod 777 `pwd`/dist
	
	# Build the kubernetes plugin
	docker run \
	-u user \
	-v `pwd`:/code \
	calico/build pyinstaller calico_kubernetes/calico_kubernetes.py -a -F -s --clean

ut:
	docker run --rm -v `pwd`:/code \
	calico/test sh -c \
	'pip install ConcurrentLogHandler && \
	nosetests calico_kubernetes/tests -c nose.cfg'

# UT runs on Cicle
ut-circle: binary
	# Can't use --rm on circle
	# Circle also requires extra options for reporting.
	docker run \
	-v `pwd`:/code \
	-v $(CIRCLE_TEST_REPORTS):/circle_output \
	-e COVERALLS_REPO_TOKEN=$(COVERALLS_REPO_TOKEN) \
	calico/test sh -c \
	'pip install ConcurrentLogHandler && \
	nosetests calico_kubernetes/tests -c nose.cfg \
	--with-xunit --xunit-file=/circle_output/output.xml; RC=$$?;\
	[[ ! -z "$$COVERALLS_REPO_TOKEN" ]] && coveralls || true; exit $$RC'

clean:
	find . -name '*.pyc' -exec rm -f {} +
	-rm -rf dist
	-docker run -v /var/run/docker.sock:/var/run/docker.sock -v /var/lib/docker:/var/lib/docker --rm martin/docker-cleanup-volumes

