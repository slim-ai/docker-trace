## what

easy bpftrace of docker from docker

## why

bpftrace should be easy to install and use

## usage

bpftrace example:
- terminal 1: `bash run.sh bpftrace syscalls.bt`
- terminal 2: `docker run -it --rm ubuntu bash -c 'echo hello world > test.txt`

bcc python example:
- terminal 1: `bash run.sh python -u execve.py`
- terminal 2: `docker run -it --rm ubuntu bash -c 'echo hello world > test.txt`
