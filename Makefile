.PHONEY: binary

binary: dist/calico

dist/calico:
	# Build docker container
	cd build_calico_kubernetes; docker build -t calico-kubernetes-build .
	mkdir -p dist
	chmod 777 `pwd`/dist
	
	# Build the kubernetes plugin
	docker run \
	-u user \
	-v `pwd`/calico_kubernetes:/code/calico_kubernetes \
	-v `pwd`/dist:/code/dist \
	-e PYTHONPATH=/code/calico_kubernetes \
	calico-kubernetes-build pyinstaller calico_kubernetes/calico_kubernetes.py -a -F -s --clean
