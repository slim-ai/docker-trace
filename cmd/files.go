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

#include <linux/sched.h>

tracepoint:cgroup:cgroup_mkdir { printf("cgroup_mkdir\t%d\t\t\t\t\t%s\n", args->id, str(args->path)); }

tracepoint:syscalls:sys_enter_exec* { printf("exec\t%d\t%d\t%d\t%s\t0\t%s\n", cgroup, pid, curtask->real_parent->pid, comm, str(args->filename)); }

tracepoint:syscalls:sys_enter_creat,
tracepoint:syscalls:sys_enter_statfs,
tracepoint:syscalls:sys_enter_readlinkat { @filename[tid] = args->pathname; }

tracepoint:syscalls:sys_enter_readlink,
tracepoint:syscalls:sys_enter_truncate { @filename[tid] = args->path; }

tracepoint:syscalls:sys_enter_utimensat,
tracepoint:syscalls:sys_enter_chdir,
tracepoint:syscalls:sys_enter_open,
tracepoint:syscalls:sys_enter_futimesat,
tracepoint:syscalls:sys_enter_access,
tracepoint:syscalls:sys_enter_openat,
tracepoint:syscalls:sys_enter_statx,
tracepoint:syscalls:sys_enter_mknod,
tracepoint:syscalls:sys_enter_mknodat,
tracepoint:syscalls:sys_enter_faccessat,
tracepoint:syscalls:sys_enter_utimes,
tracepoint:syscalls:sys_enter_newstat,
tracepoint:syscalls:sys_enter_newlstat { @filename[tid] = args->filename; }

tracepoint:syscalls:sys_exit_utimensat  { $ret = args->ret; $errno = $ret >= 0 ? 0 : - $ret; printf("utimensat\t%d\t%d\t%d\t%s\t%d\t%s\n", cgroup, pid, curtask->real_parent->pid, comm, $errno, str(@filename[tid])); delete(@filename[tid]); }
tracepoint:syscalls:sys_exit_faccessat  { $ret = args->ret; $errno = $ret >= 0 ? 0 : - $ret; printf("faccessat\t%d\t%d\t%d\t%s\t%d\t%s\n", cgroup, pid, curtask->real_parent->pid, comm, $errno, str(@filename[tid])); delete(@filename[tid]); }
tracepoint:syscalls:sys_exit_chdir      { $ret = args->ret; $errno = $ret >= 0 ? 0 : - $ret; printf("chdir\t%d\t%d\t%d\t%s\t%d\t%s\n", cgroup, pid, curtask->real_parent->pid, comm, $errno, str(@filename[tid])); delete(@filename[tid]); }
tracepoint:syscalls:sys_exit_access     { $ret = args->ret; $errno = $ret >= 0 ? 0 : - $ret; printf("access\t%d\t%d\t%d\t%s\t%d\t%s\n", cgroup, pid, curtask->real_parent->pid, comm, $errno, str(@filename[tid])); delete(@filename[tid]); }
tracepoint:syscalls:sys_exit_futimesat  { $ret = args->ret; $errno = $ret >= 0 ? 0 : - $ret; printf("futimesat\t%d\t%d\t%d\t%s\t%d\t%s\n", cgroup, pid, curtask->real_parent->pid, comm, $errno, str(@filename[tid])); delete(@filename[tid]); }
tracepoint:syscalls:sys_exit_open       { $ret = args->ret; $errno = $ret >= 0 ? 0 : - $ret; printf("open\t%d\t%d\t%d\t%s\t%d\t%s\n", cgroup, pid, curtask->real_parent->pid, comm, $errno, str(@filename[tid])); delete(@filename[tid]); }
tracepoint:syscalls:sys_exit_openat     { $ret = args->ret; $errno = $ret >= 0 ? 0 : - $ret; printf("openat\t%d\t%d\t%d\t%s\t%d\t%s\n", cgroup, pid, curtask->real_parent->pid, comm, $errno, str(@filename[tid])); delete(@filename[tid]); }
tracepoint:syscalls:sys_exit_readlink   { $ret = args->ret; $errno = $ret >= 0 ? 0 : - $ret; printf("readlink\t%d\t%d\t%d\t%s\t%d\t%s\n", cgroup, pid, curtask->real_parent->pid, comm, $errno, str(@filename[tid])); delete(@filename[tid]); }
tracepoint:syscalls:sys_exit_truncate   { $ret = args->ret; $errno = $ret >= 0 ? 0 : - $ret; printf("truncate\t%d\t%d\t%d\t%s\t%d\t%s\n", cgroup, pid, curtask->real_parent->pid, comm, $errno, str(@filename[tid])); delete(@filename[tid]); }
tracepoint:syscalls:sys_exit_readlinkat { $ret = args->ret; $errno = $ret >= 0 ? 0 : - $ret; printf("readlinkat\t%d\t%d\t%d\t%s\t%d\t%s\n", cgroup, pid, curtask->real_parent->pid, comm, $errno, str(@filename[tid])); delete(@filename[tid]); }
tracepoint:syscalls:sys_exit_statfs     { $ret = args->ret; $errno = $ret >= 0 ? 0 : - $ret; printf("statfs\t%d\t%d\t%d\t%s\t%d\t%s\n", cgroup, pid, curtask->real_parent->pid, comm, $errno, str(@filename[tid])); delete(@filename[tid]); }
tracepoint:syscalls:sys_exit_creat      { $ret = args->ret; $errno = $ret >= 0 ? 0 : - $ret; printf("creat\t%d\t%d\t%d\t%s\t%d\t%s\n", cgroup, pid, curtask->real_parent->pid, comm, $errno, str(@filename[tid])); delete(@filename[tid]); }
tracepoint:syscalls:sys_exit_statx      { $ret = args->ret; $errno = $ret >= 0 ? 0 : - $ret; printf("statx\t%d\t%d\t%d\t%s\t%d\t%s\n", cgroup, pid, curtask->real_parent->pid, comm, $errno, str(@filename[tid])); delete(@filename[tid]); }
tracepoint:syscalls:sys_exit_newstat    { $ret = args->ret; $errno = $ret >= 0 ? 0 : - $ret; printf("newstat\t%d\t%d\t%d\t%s\t%d\t%s\n", cgroup, pid, curtask->real_parent->pid, comm, $errno, str(@filename[tid])); delete(@filename[tid]); }
tracepoint:syscalls:sys_exit_mknod      { $ret = args->ret; $errno = $ret >= 0 ? 0 : - $ret; printf("mknod\t%d\t%d\t%d\t%s\t%d\t%s\n", cgroup, pid, curtask->real_parent->pid, comm, $errno, str(@filename[tid])); delete(@filename[tid]); }
tracepoint:syscalls:sys_exit_mknodat    { $ret = args->ret; $errno = $ret >= 0 ? 0 : - $ret; printf("mknodat\t%d\t%d\t%d\t%s\t%d\t%s\n", cgroup, pid, curtask->real_parent->pid, comm, $errno, str(@filename[tid])); delete(@filename[tid]); }
tracepoint:syscalls:sys_exit_utimes     { $ret = args->ret; $errno = $ret >= 0 ? 0 : - $ret; printf("utimes\t%d\t%d\t%d\t%s\t%d\t%s\n", cgroup, pid, curtask->real_parent->pid, comm, $errno, str(@filename[tid])); delete(@filename[tid]); }
tracepoint:syscalls:sys_exit_newlstat   { $ret = args->ret; $errno = $ret >= 0 ? 0 : - $ret; printf("newlstat\t%d\t%d\t%d\t%s\t%d\t%s\n", cgroup, pid, curtask->real_parent->pid, comm, $errno, str(@filename[tid])); delete(@filename[tid]); }

END { clear(@filename); }

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
	err = ioutil.WriteFile(tempDir+"/files.bt", []byte(filesBpftrace), 0666)
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
	//
	out, err := cli.ContainerCreate(
		ctx,
		&container.Config{
			Cmd:   []string{"bpftrace", "/bpftrace/files.bt"},
			Image: "docker-trace:bpftrace",
			Env:   []string{"BPFTRACE_STRLEN=200"},
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
		&specs.Platform{Architecture: "amd64", OS: "linux"},
		"docker-trace-"+uid,
	)
	if err != nil {
		lib.Logger.Fatal("error: ", err)
	}
	for _, warn := range out.Warnings {
		lib.Logger.Println(warn)
	}
	//
	err = cli.ContainerStart(ctx, out.ID, types.ContainerStartOptions{})
	if err != nil {
		lib.Logger.Fatal("error: ", err)
	}
	//
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	//
	cleanup := func() {
		_ = cli.ContainerKill(context.Background(), out.ID, "KILL")
		_ = os.RemoveAll(tempDir)
		cancel()
	}
	lib.SignalHandler(cleanup)
	//
	logs, err := cli.ContainerLogs(ctx, out.ID, types.ContainerLogsOptions{
		ShowStdout: true,
		ShowStderr: true,
		Follow:     true,
	})
	if err != nil {
		lib.Logger.Fatal("error: ", err)
	}
	defer func() { _ = logs.Close() }()
	//
	buf := bufio.NewReader(logs)
	line, err := buf.ReadBytes('\n')
	if err != nil {
		lib.Logger.Fatal("error: ", err)
	}
	if !(strings.HasPrefix(string(line[8:]), "Attaching ") && strings.HasSuffix(string(line[8:]), " probes...\n")) {
		lib.Logger.Fatalf("error: unexected startup log: %s", string(line))
	}
	fmt.Fprintln(os.Stderr, "ready")
	//
	cwds := make(map[string]string)
	cgroups := make(map[string]string)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		line, err := buf.ReadBytes('\n')
		if err != nil {
			cleanup()
			if err == io.EOF || err == context.Canceled {
				return
			}
			lib.Logger.Fatal("error:", err)
		}
		str := string(line[8 : len(line)-1]) // docker log uses the first 8 bytes for metadata https://ahmet.im/blog/docker-logs-api-binary-format-explained/
		switch line[0] {
		case 1:
			lib.FilesHandleLine(cwds, cgroups, str)
		case 2:
			_, _ = fmt.Fprint(os.Stderr, str)
		}
	}
}
