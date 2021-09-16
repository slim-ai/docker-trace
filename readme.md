## what

easily bpftrace a single unprivileged container from a privileged container

## why

bpftracing containers should be easy

## install

```
go get github.com/nathants/docker-trace
```

## example

![](./example.gif)

## usage

```

# terminal 1

>> docker run -it --rm archlinux bash

# terminal 2

>> docker-trace files $(docker ps -q --no-trunc)
Attaching 19 probes...

# terminal 1

>> cat /etc/hosts
...

# terminal 2

newstat 678933 bash 0 .
newstat 678933 bash 2 /usr/local/sbin/cat
newstat 678933 bash 2 /usr/local/bin/cat
newstat 678933 bash 0 /usr/sbin/cat
newstat 678933 bash 0 /usr/sbin/cat
newstat 678933 bash 0 /usr/sbin/cat
newstat 678933 bash 0 /usr/sbin/cat
newstat 678933 bash 0 /usr/sbin/cat
newstat 678933 bash 0 /usr/sbin/cat
openat 679730 cat 0 /etc/ld.so.cache
openat 679730 cat 0 /usr/lib/libc.so.6
openat 679730 cat 0 /usr/lib/locale/locale-archive
openat 679730 cat 0 /etc/hosts
```
