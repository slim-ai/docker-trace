#!/bin/bash
set -eou pipefail
cd $(dirname $0)

# print usage
if echo "$@" | grep -e "\-h" -e "\-\-help" &>/dev/null; then
    echo
    echo "usage:   bash bpftrace.sh CONTAINER_ID scripts/SCRIPT.bt"
    echo
    echo "example: bash bpftrace.sh 1c95e3afaa122699f4732daec1f25ef6788bb289dc0eb49373745c8e890435c4 scripts/tcp.bt"
    echo
    echo scripts/
    ls scripts/ -1 | sed 's/^/  /'
    exit 1
fi

# check for cgroups v2
if ! ls /sys/fs/cgroup/ | grep cgroup.controllers &>/dev/null; then
    echo
    echo fatal: cgroups v2 are required
    echo
    echo https://wiki.archlinux.org/index.php/cgroups#Switching_to_cgroups_v2
    echo https://wiki.archlinux.org/index.php/Kernel_parameters#GRUB
    exit 1
fi

# build if needed
if ! docker inspect arch:bpftrace &>/dev/null; then
    docker build -t arch:bpftrace .
fi

# trace this container
container_id=$1

# trace using this script from scripts/*.bt
script=$2

# invoke
kernel=$(uname -r)
docker run ${DOCKER_OPTS:-} \
       -t \
       --rm \
       --privileged \
       --cap-add=SYS_ADMIN \
       --security-opt no-new-privileges \
       -v /sys/fs/cgroup:/sys/fs/cgroup:ro \
       -v /usr/lib/modules/$kernel:/usr/lib/modules/$kernel:ro \
       -v /sys/kernel/debug:/sys/kernel/debug:ro \
       -v $(pwd)/scripts:/scripts:ro \
       arch:bpftrace \
       bash -c "cat $script | sed s/CONTAINERID/$container_id/g | bpftrace -"
