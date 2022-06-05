## what

analyze and minimize the filesystem of a container.

## why

containers have too much stuff in them.

## install

```
>> go install github.com/nathants/docker-trace@latest

>> sudo apt-get install -y bpftrace
```

## usage

```
>> docker-trace -h

dockerfile - scan a container and print the dockerfile
files      - bpftrace filesystem access in running container
minify     - minify a container keeping files passed on stdin
scan       - scan a container and list filesystem contents
unpack     - unpack a container into directories and files
```

## example

![](./example.gif)

## usage

```

>> docker-trace files > /tmp/trace.txt &

>> docker run -it --rm archlinux:latest curl https://google.com

>> cat /tmp/trace.txt | grep -e ssl -e curl | head

a1a54371 /usr/sbin/curl
a1a54371 /usr/lib/libcurl.so.4
a1a54371 /usr/lib/libssl.so.1.1
a1a54371 /etc/ssl/openssl.cnf

```

## minification

```

>> docker-trace files > /tmp/trace.txt &

>> docker run -it --rm archlinux:latest curl https://google.com

>> cat /tmp/trace.txt | awk '{print $2}' | docker-trace minify archlinux:latest archlinux:curl-https-minifed

>> docker images | grep archlinux

archlinux    curl-https-minifed    cbdc450d4009    23 seconds ago    16.1MB
archlinux    latest                1d6f90387c13    5 weeks ago       381MB

>> docker run -it --rm archlinux:curl-https-minifed curl -v https://google.com | grep '< HTTP'

< HTTP/2 301

```

## minification results from tests

```
>> docker images --format '{{.Tag}} {{.Size}}'|grep web | sort | column -t

minify-go-web-alpine-75b2c1029fa03869c64d4716e478a696           468MB
minify-go-web-alpine-75b2c1029fa03869c64d4716e478a696-min       7.93MB

minify-go-web-amzn-75b2c1029fa03869c64d4716e478a696             1.11GB
minify-go-web-amzn-75b2c1029fa03869c64d4716e478a696-min         9.97MB

minify-go-web-arch-75b2c1029fa03869c64d4716e478a696             995MB
minify-go-web-arch-75b2c1029fa03869c64d4716e478a696-min         9.95MB

minify-go-web-debian-75b2c1029fa03869c64d4716e478a696           847MB
minify-go-web-debian-75b2c1029fa03869c64d4716e478a696-min       10.2MB

minify-go-web-ubuntu-75b2c1029fa03869c64d4716e478a696           704MB
minify-go-web-ubuntu-75b2c1029fa03869c64d4716e478a696-min       11.3MB

minify-node-web-alpine-88fcdb538a144d54ec41b967f54c5e70         60.1MB
minify-node-web-alpine-88fcdb538a144d54ec41b967f54c5e70-min     45.2MB

minify-node-web-amzn-88fcdb538a144d54ec41b967f54c5e70           535MB
minify-node-web-amzn-88fcdb538a144d54ec41b967f54c5e70-min       54MB

minify-node-web-arch-88fcdb538a144d54ec41b967f54c5e70           591MB
minify-node-web-arch-88fcdb538a144d54ec41b967f54c5e70-min       94.9MB

minify-node-web-debian-88fcdb538a144d54ec41b967f54c5e70         960MB
minify-node-web-debian-88fcdb538a144d54ec41b967f54c5e70-min     82.7MB

minify-node-web-ubuntu-88fcdb538a144d54ec41b967f54c5e70         656MB
minify-node-web-ubuntu-88fcdb538a144d54ec41b967f54c5e70-min     68MB

minify-python3-web-alpine-3255592eda8a6eede400c674466b5e4b      84.2MB
minify-python3-web-alpine-3255592eda8a6eede400c674466b5e4b-min  16.6MB

minify-python3-web-amzn-3255592eda8a6eede400c674466b5e4b        652MB
minify-python3-web-amzn-3255592eda8a6eede400c674466b5e4b-min    22.9MB

minify-python3-web-arch-3255592eda8a6eede400c674466b5e4b        669MB
minify-python3-web-arch-3255592eda8a6eede400c674466b5e4b-min    24.3MB

minify-python3-web-debian-3255592eda8a6eede400c674466b5e4b      567MB
minify-python3-web-debian-3255592eda8a6eede400c674466b5e4b-min  21.8MB

minify-python3-web-ubuntu-3255592eda8a6eede400c674466b5e4b      459MB
minify-python3-web-ubuntu-3255592eda8a6eede400c674466b5e4b-min  21.5MB
```
