package dockertrace

import (
	"archive/tar"
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"strings"

	"github.com/alexflint/go-arg"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/client"
	"github.com/nathants/docker-trace/lib"
	specs "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/satori/go.uuid"
)

func init() {
	lib.Commands["files"] = files
	lib.Args["files"] = filesArgs{}
}

type filesArgs struct {
	ContainerID string `arg:"positional,required"`
}

func (filesArgs) Description() string {
	return "\nbpftrace filesystem access in a running container\n"
}

const filesDockerfile = `

FROM archlinux:latest

# faster mirrors
RUN echo 'Server = https://mirrors.kernel.org/archlinux/$repo/os/$arch' >  /etc/pacman.d/mirrorlist && \
    echo 'Server = https://mirrors.xtom.com/archlinux/$repo/os/$arch'   >> /etc/pacman.d/mirrorlist && \
    echo 'Server = https://mirror.lty.me/archlinux/$repo/os/$arch'      >> /etc/pacman.d/mirrorlist

# install bpftrace
RUN pacman -Syu --noconfirm bpftrace

`

const filesBpftrace = `#!/usr/bin/env bpftrace

// ENTER

tracepoint:syscalls:sys_enter_statfs,
tracepoint:syscalls:sys_enter_readlinkat
/cgroup == cgroupid("/sys/fs/cgroup/system.slice/docker-CONTAINERID.scope")/
{ @filename[tid] = args->pathname; }

tracepoint:syscalls:sys_enter_readlink
/cgroup == cgroupid("/sys/fs/cgroup/system.slice/docker-CONTAINERID.scope")/
{ @filename[tid] = args->path; }

tracepoint:syscalls:sys_enter_chdir,
tracepoint:syscalls:sys_enter_open,
tracepoint:syscalls:sys_enter_openat,
tracepoint:syscalls:sys_enter_statx,
tracepoint:syscalls:sys_enter_newstat,
tracepoint:syscalls:sys_enter_newlstat
/cgroup == cgroupid("/sys/fs/cgroup/system.slice/docker-CONTAINERID.scope")/
{ @filename[tid] = args->filename; }

// EXIT

tracepoint:syscalls:sys_exit_chdir
/cgroup == cgroupid("/sys/fs/cgroup/system.slice/docker-CONTAINERID.scope")/
{ $ret = args->ret; $errno = $ret >= 0 ? 0 : - $ret; printf("chdir %d %s %d %s\n", pid, comm, $errno, str(@filename[tid])); delete(@filename[tid]); }

tracepoint:syscalls:sys_exit_open
/cgroup == cgroupid("/sys/fs/cgroup/system.slice/docker-CONTAINERID.scope")/
{ $ret = args->ret; $errno = $ret >= 0 ? 0 : - $ret; printf("open %d %s %d %s\n", pid, comm, $errno, str(@filename[tid])); delete(@filename[tid]); }

tracepoint:syscalls:sys_exit_openat
/cgroup == cgroupid("/sys/fs/cgroup/system.slice/docker-CONTAINERID.scope")/
{ $ret = args->ret; $errno = $ret >= 0 ? 0 : - $ret; printf("openat %d %s %d %s\n", pid, comm, $errno, str(@filename[tid])); delete(@filename[tid]); }

tracepoint:syscalls:sys_exit_readlink
/cgroup == cgroupid("/sys/fs/cgroup/system.slice/docker-CONTAINERID.scope")/
{ $ret = args->ret; $errno = $ret >= 0 ? 0 : - $ret; printf("readlink %d %s %d %s\n", pid, comm, $errno, str(@filename[tid])); delete(@filename[tid]); }

tracepoint:syscalls:sys_exit_readlinkat
/cgroup == cgroupid("/sys/fs/cgroup/system.slice/docker-CONTAINERID.scope")/
{ $ret = args->ret; $errno = $ret >= 0 ? 0 : - $ret; printf("readlinkat %d %s %d %s\n", pid, comm, $errno, str(@filename[tid])); delete(@filename[tid]); }

tracepoint:syscalls:sys_exit_statfs
/cgroup == cgroupid("/sys/fs/cgroup/system.slice/docker-CONTAINERID.scope")/
{ $ret = args->ret; $errno = $ret >= 0 ? 0 : - $ret; printf("statfs %d %s %d %s\n", pid, comm, $errno, str(@filename[tid])); delete(@filename[tid]); }

tracepoint:syscalls:sys_exit_statx
/cgroup == cgroupid("/sys/fs/cgroup/system.slice/docker-CONTAINERID.scope")/
{ $ret = args->ret; $errno = $ret >= 0 ? 0 : - $ret; printf("statx %d %s %d %s\n", pid, comm, $errno, str(@filename[tid])); delete(@filename[tid]); }

tracepoint:syscalls:sys_exit_newstat
/cgroup == cgroupid("/sys/fs/cgroup/system.slice/docker-CONTAINERID.scope")/
{ $ret = args->ret; $errno = $ret >= 0 ? 0 : - $ret; printf("newstat %d %s %d %s\n", pid, comm, $errno, str(@filename[tid])); delete(@filename[tid]); }

tracepoint:syscalls:sys_exit_newlstat
/cgroup == cgroupid("/sys/fs/cgroup/system.slice/docker-CONTAINERID.scope")/
{ $ret = args->ret; $errno = $ret >= 0 ? 0 : - $ret; printf("newlstat %d %s %d %s\n", pid, comm, $errno, str(@filename[tid])); delete(@filename[tid]); }

// END

END
{ clear(@filename); }

`

func files() {
	var args filesArgs
	arg.MustParse(&args)
	//
	files, err := ioutil.ReadDir("/sys/fs/cgroup/")
	if err != nil {
	    lib.Logger.Fatal("error: ", err)
	}
	fail := true
	for _, file := range files {
		if file.Name() == "cgroup.controllers" {
			fail = false
			break
		}
	}
	if fail {
		lib.Logger.Println("fatal: cgroups v2 are required")
		lib.Logger.Println("https://wiki.archlinux.org/index.php/cgroups#Switching_to_cgroups_v2")
		lib.Logger.Println("https://wiki.archlinux.org/index.php/Kernel_parameters#GRUB")
		lib.Logger.Fatal("")
	}
	//
	if len(args.ContainerID) != 64 {
		lib.Logger.Fatal("error: you must use the full 64 charactor ContainerID, not:", args.ContainerID)
	}
	//
	cli, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		lib.Logger.Fatal("error: ", err)
	}
	ctx := context.Background()
	uid := uuid.NewV4().String()
	_, _, err = cli.ImageInspectWithRaw(ctx, "docker-trace:bpftrace")
	if err != nil {
		if err.Error() != "Error: No such image: docker-trace:bpftrace" {
			lib.Logger.Fatal("error: ", err)
		}
		fmt.Println("building image: docker-trace:bpftrace")
		//
		w, err := os.OpenFile("/tmp/Dockerfile."+uid, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0666)
		if err != nil {
			lib.Logger.Fatal("error: ", err)
		}
		_, err = w.Write([]byte(filesDockerfile))
		if err != nil {
			lib.Logger.Fatal("error: ", err)
		}
		err = w.Close()
		if err != nil {
			lib.Logger.Fatal("error: ", err)
		}
		//
		w, err = os.OpenFile("/tmp/context.tar."+uid, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0666)
		if err != nil {
			lib.Logger.Fatal("error: ", err)
		}
		tw := tar.NewWriter(w)
		//
		fi, err := os.Stat("/tmp/Dockerfile." + uid)
		if err != nil {
			lib.Logger.Fatal("error: ", err)
		}
		header, err := tar.FileInfoHeader(fi, "")
		header.Name = "/tmp/Dockerfile." + uid
		if err != nil {
			lib.Logger.Fatal("error: ", err)
		}
		err = tw.WriteHeader(header)
		if err != nil {
			lib.Logger.Fatal("error: ", err)
		}
		//
		r, err := os.Open("/tmp/Dockerfile." + uid)
		if err != nil {
			lib.Logger.Fatal("error: ", err)
		}
		_, err = io.Copy(tw, r)
		if err != nil {
			lib.Logger.Fatal("error: ", err)
		}
		//
		err = r.Close()
		if err != nil {
			lib.Logger.Fatal("error: ", err)
		}
		err = tw.Close()
		if err != nil {
			lib.Logger.Fatal("error: ", err)
		}
		err = w.Close()
		if err != nil {
			lib.Logger.Fatal("error: ", err)
		}
		//
		r, err = os.Open("/tmp/context.tar." + uid)
		if err != nil {
			lib.Logger.Fatal("error: ", err)
		}
		out, err := cli.ImageBuild(ctx, r, types.ImageBuildOptions{
			NoCache:     true,
			Tags:        []string{"docker-trace:bpftrace"},
			Dockerfile:  "/tmp/Dockerfile." + uid,
			NetworkMode: "host",
			Remove:      true,
		})
		if err != nil {
			lib.Logger.Fatal("error: ", err)
		}
		defer func() { _ = out.Body.Close() }()
		//
		scanner := bufio.NewScanner(out.Body)
		val := make(map[string]string)
		for scanner.Scan() {
			err := json.Unmarshal(scanner.Bytes(), &val)
			if err == nil {
				lib.Logger.Println(strings.Trim(val["stream"], "\n"))
			}
		}
		err = scanner.Err()
		if err != nil {
			lib.Logger.Fatal("error: ", err)
		}
		if val["stream"] != "Successfully tagged docker-trace:bpftrace\n" {
			lib.Logger.Fatal("error: failed to build docker-trace:bpftrace")
		}
	}
	//
	tempDir, err := ioutil.TempDir("", "docker-trace")
	if err != nil {
		lib.Logger.Fatal("error: ", err)
	}
	err = ioutil.WriteFile(tempDir+"/files.bt", []byte(strings.ReplaceAll(filesBpftrace, "CONTAINERID", args.ContainerID)), 0666)
	if err != nil {
		lib.Logger.Fatal("error: ", err)
	}
	cmd := exec.Command("uname", "-r")
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	err = cmd.Run()
	if err != nil {
		lib.Logger.Fatal("error: ", err)
	}
	kernel := strings.Trim(stdout.String(), "\n")
	out, err := cli.ContainerCreate(
		ctx,
		&container.Config{
			Cmd:   []string{"bpftrace", "/bpftrace/files.bt"},
			Image: "docker-trace:bpftrace",
		},
		&container.HostConfig{
			AutoRemove: true,
			Binds: []string{
				tempDir + ":/bpftrace",
				"/sys/fs/cgroup:/sys/fs/cgroup:ro",
				fmt.Sprintf("/usr/lib/modules/%s:/usr/lib/modules/%s:ro", kernel, kernel),
				"/sys/kernel/debug:/sys/kernel/debug:ro",
			},
			Privileged:  true,
			CapAdd:      []string{"SYS_ADMIN"},
			SecurityOpt: []string{"no-new-privileges"},
		},
		&network.NetworkingConfig{},
		&specs.Platform{
			Architecture: "amd64",
			OS:           "linux",
		},
		"docker-trace-"+uid,
	)
	if err != nil {
		lib.Logger.Fatal("error: ", err)
	}
	for _, warn := range out.Warnings {
		lib.Logger.Println(warn)
	}
	err = cli.ContainerStart(ctx, out.ID, types.ContainerStartOptions{})
	if err != nil {
		lib.Logger.Fatal("error: ", err)
	}
	lib.SignalHandler(func() {
		_ = cli.ContainerKill(ctx, out.ID, "kill")
	})
	logs, err := cli.ContainerLogs(ctx, out.ID, types.ContainerLogsOptions{
		ShowStdout: true,
		Follow:     true,
	})
	if err != nil {
		lib.Logger.Fatal("error: ", err)
	}
	defer func() { _ = logs.Close() }()
	buf := bufio.NewReader(logs)
	line, err := buf.ReadString('\n')
	if err != nil {
		if err != io.EOF {
			lib.Logger.Fatal("error:", err)
		}
		return
	}
	fmt.Fprint(os.Stderr, line)
	for {
		line, err := buf.ReadBytes('\n')
		if err != nil {
			if err != io.EOF {
				lib.Logger.Fatal("error:", err)
			}
			break
		}
		fmt.Print(string(line[8:])) // docker log uses the first 8 bytes for metadata
	}
	err = os.RemoveAll(tempDir)
	if err != nil {
	    lib.Logger.Fatal("error: ", err)
	}
}
