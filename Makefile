all: build test stop

# this is to forward X apps to host:
# See: http://stackoverflow.com/a/25280523/1336939
XSOCK=/tmp/.X11-unix
XAUTH=/tmp/.docker.xauth

# paths
TBB_PATH=/home/docker/corrcrawl/tor-browser_en-US/
CRAWL_PATH=/home/docker/corrcrawl
GUEST_SSH=/home/docker/.ssh
HOST_SSH=${HOME}/.ssh

ENV_VARS = \
	--env="DISPLAY=${DISPLAY}" 					\
	--env="XAUTHORITY=${XAUTH}"					\
	--env="VIRTUAL_DISPLAY=$(VIRTUAL_DISPLAY)"  \
	--env="START_XVFB=false"                    \
	--env="TBB_PATH=${TBB_PATH}"
VOLUMES = \
	--volume=${XSOCK}:${XSOCK}					\
	--volume=${XAUTH}:${XAUTH}					\
	--volume=${HOST_SSH}:${GUEST_SSH}			\
	--volume=`pwd`:${CRAWL_PATH}				\


# network interface on which to listen
DEVICE=eno1

# commandline arguments
CRAWL_PARAMS=--user corr --password thr0wAway --host 168.235.110.134 --start 1 --batches 10000 --sites top-1m.csv --nic ${DEVICE}

# Make routines
build:
	@docker build -t corrcrawl --rm .

run:
	@docker run -it --rm ${ENV_VARS} ${VOLUMES} --net host --privileged \
	corrcrawl ${CRAWL_PATH}/Entrypoint.sh "./crawler/main.py $(CRAWL_PARAMS)" ${DEVICE}

shell:
	@docker run -it --rm ${ENV_VARS} ${VOLUMES} --net host --privileged \
	corrcrawl /bin/bash

stop:
	@docker stop `docker ps -a -q -f ancestor=corrcrawl`
	@docker rm `docker ps -a -q -f ancestor=corrcrawl`

destroy:
	@docker rmi -f corrcrawl

reset: stop destroy
