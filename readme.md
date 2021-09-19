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

## basic usage

```
docker run -it --rm archlinux bash # terminal 1
docker-trace files $container_id   # terminal 2
```

## advanced usage

```
docker create -it --rm archlinux bash # terminal 1
docker-trace files $container_id      # terminal 2
docker start -ia $container_id        # terminal 1
```
