package dockertrace

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	"github.com/alexflint/go-arg"
	"github.com/nathants/docker-trace/lib"
)

func init() {
	lib.Commands["files"] = files
	lib.Args["files"] = filesArgs{}
}

type filesArgs struct {
	BpfRingBufferPages int `arg:"-p,--rb-pages" default:"65536" help:"double this value if you encounter 'Lost events' messages on stderr"`
}

func (filesArgs) Description() string {
	return "\nbpftrace filesystem access in a running container\n"
}

const filesBpftraceFilterFilename = `/strncmp("/proc/", str(args->filename), 6) != 0 && strncmp("/sys/", str(args->filename), 5) != 0 && strncmp("/dev/", str(args->filename), 5) != 0/`
const filesBpftraceFilterPathname = `/strncmp("/proc/", str(args->pathname), 6) != 0 && strncmp("/sys/", str(args->pathname), 5) != 0 && strncmp("/dev/", str(args->pathname), 5) != 0/`
const filesBpftraceFilterPath = `    /strncmp("/proc/", str(args->path),     6) != 0 && strncmp("/sys/", str(args->path),     5) != 0 && strncmp("/dev/", str(args->path),     5) != 0/`
const filesBpftraceFilterTID = `     /strncmp("/proc/", str(@filename[tid]), 6) != 0 && strncmp("/sys/", str(@filename[tid]), 5) != 0 && strncmp("/dev/", str(@filename[tid]), 5) != 0/`

const filesBpftrace = `#!/usr/bin/env bpftrace

#include <linux/sched.h>

tracepoint:cgroup:cgroup_mkdir { printf("cgroup_mkdir\t%d\t\t\t\t\t%s\n", args->id, str(args->path)); }

tracepoint:syscalls:sys_enter_exec* FILTER_FILENAME { printf("exec\t%d\t%d\t%d\t%s\t0\t%s\n", cgroup, pid, curtask->real_parent->pid, comm, str(args->filename)); }

tracepoint:syscalls:sys_enter_creat,
tracepoint:syscalls:sys_enter_statfs,
tracepoint:syscalls:sys_enter_readlinkat FILTER_PATHNAME { @filename[tid] = args->pathname; }

tracepoint:syscalls:sys_enter_readlink,
tracepoint:syscalls:sys_enter_truncate FILTER_PATH { @filename[tid] = args->path; }

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
tracepoint:syscalls:sys_enter_utime,
tracepoint:syscalls:sys_enter_utimes,
tracepoint:syscalls:sys_enter_newstat,
tracepoint:syscalls:sys_enter_newlstat FILTER_FILENAME { @filename[tid] = args->filename; }

tracepoint:syscalls:sys_exit_utimensat  FILTER_TID { $ret = args->ret; $errno = $ret >= 0 ? 0 : - $ret; printf("utimensat\t%d\t%d\t%d\t%s\t%d\t%s\n",  cgroup, pid, curtask->real_parent->pid, comm, $errno, str(@filename[tid])); delete(@filename[tid]); }
tracepoint:syscalls:sys_exit_faccessat  FILTER_TID { $ret = args->ret; $errno = $ret >= 0 ? 0 : - $ret; printf("faccessat\t%d\t%d\t%d\t%s\t%d\t%s\n",  cgroup, pid, curtask->real_parent->pid, comm, $errno, str(@filename[tid])); delete(@filename[tid]); }
tracepoint:syscalls:sys_exit_chdir      FILTER_TID { $ret = args->ret; $errno = $ret >= 0 ? 0 : - $ret; printf("chdir\t%d\t%d\t%d\t%s\t%d\t%s\n",      cgroup, pid, curtask->real_parent->pid, comm, $errno, str(@filename[tid])); delete(@filename[tid]); }
tracepoint:syscalls:sys_exit_access     FILTER_TID { $ret = args->ret; $errno = $ret >= 0 ? 0 : - $ret; printf("access\t%d\t%d\t%d\t%s\t%d\t%s\n",     cgroup, pid, curtask->real_parent->pid, comm, $errno, str(@filename[tid])); delete(@filename[tid]); }
tracepoint:syscalls:sys_exit_futimesat  FILTER_TID { $ret = args->ret; $errno = $ret >= 0 ? 0 : - $ret; printf("futimesat\t%d\t%d\t%d\t%s\t%d\t%s\n",  cgroup, pid, curtask->real_parent->pid, comm, $errno, str(@filename[tid])); delete(@filename[tid]); }
tracepoint:syscalls:sys_exit_open       FILTER_TID { $ret = args->ret; $errno = $ret >= 0 ? 0 : - $ret; printf("open\t%d\t%d\t%d\t%s\t%d\t%s\n",       cgroup, pid, curtask->real_parent->pid, comm, $errno, str(@filename[tid])); delete(@filename[tid]); }
tracepoint:syscalls:sys_exit_openat     FILTER_TID { $ret = args->ret; $errno = $ret >= 0 ? 0 : - $ret; printf("openat\t%d\t%d\t%d\t%s\t%d\t%s\n",     cgroup, pid, curtask->real_parent->pid, comm, $errno, str(@filename[tid])); delete(@filename[tid]); }
tracepoint:syscalls:sys_exit_readlink   FILTER_TID { $ret = args->ret; $errno = $ret >= 0 ? 0 : - $ret; printf("readlink\t%d\t%d\t%d\t%s\t%d\t%s\n",   cgroup, pid, curtask->real_parent->pid, comm, $errno, str(@filename[tid])); delete(@filename[tid]); }
tracepoint:syscalls:sys_exit_truncate   FILTER_TID { $ret = args->ret; $errno = $ret >= 0 ? 0 : - $ret; printf("truncate\t%d\t%d\t%d\t%s\t%d\t%s\n",   cgroup, pid, curtask->real_parent->pid, comm, $errno, str(@filename[tid])); delete(@filename[tid]); }
tracepoint:syscalls:sys_exit_readlinkat FILTER_TID { $ret = args->ret; $errno = $ret >= 0 ? 0 : - $ret; printf("readlinkat\t%d\t%d\t%d\t%s\t%d\t%s\n", cgroup, pid, curtask->real_parent->pid, comm, $errno, str(@filename[tid])); delete(@filename[tid]); }
tracepoint:syscalls:sys_exit_statfs     FILTER_TID { $ret = args->ret; $errno = $ret >= 0 ? 0 : - $ret; printf("statfs\t%d\t%d\t%d\t%s\t%d\t%s\n",     cgroup, pid, curtask->real_parent->pid, comm, $errno, str(@filename[tid])); delete(@filename[tid]); }
tracepoint:syscalls:sys_exit_creat      FILTER_TID { $ret = args->ret; $errno = $ret >= 0 ? 0 : - $ret; printf("creat\t%d\t%d\t%d\t%s\t%d\t%s\n",      cgroup, pid, curtask->real_parent->pid, comm, $errno, str(@filename[tid])); delete(@filename[tid]); }
tracepoint:syscalls:sys_exit_statx      FILTER_TID { $ret = args->ret; $errno = $ret >= 0 ? 0 : - $ret; printf("statx\t%d\t%d\t%d\t%s\t%d\t%s\n",      cgroup, pid, curtask->real_parent->pid, comm, $errno, str(@filename[tid])); delete(@filename[tid]); }
tracepoint:syscalls:sys_exit_newstat    FILTER_TID { $ret = args->ret; $errno = $ret >= 0 ? 0 : - $ret; printf("newstat\t%d\t%d\t%d\t%s\t%d\t%s\n",    cgroup, pid, curtask->real_parent->pid, comm, $errno, str(@filename[tid])); delete(@filename[tid]); }
tracepoint:syscalls:sys_exit_mknod      FILTER_TID { $ret = args->ret; $errno = $ret >= 0 ? 0 : - $ret; printf("mknod\t%d\t%d\t%d\t%s\t%d\t%s\n",      cgroup, pid, curtask->real_parent->pid, comm, $errno, str(@filename[tid])); delete(@filename[tid]); }
tracepoint:syscalls:sys_exit_mknodat    FILTER_TID { $ret = args->ret; $errno = $ret >= 0 ? 0 : - $ret; printf("mknodat\t%d\t%d\t%d\t%s\t%d\t%s\n",    cgroup, pid, curtask->real_parent->pid, comm, $errno, str(@filename[tid])); delete(@filename[tid]); }
tracepoint:syscalls:sys_exit_utimes     FILTER_TID { $ret = args->ret; $errno = $ret >= 0 ? 0 : - $ret; printf("utimes\t%d\t%d\t%d\t%s\t%d\t%s\n",     cgroup, pid, curtask->real_parent->pid, comm, $errno, str(@filename[tid])); delete(@filename[tid]); }
tracepoint:syscalls:sys_exit_newlstat   FILTER_TID { $ret = args->ret; $errno = $ret >= 0 ? 0 : - $ret; printf("newlstat\t%d\t%d\t%d\t%s\t%d\t%s\n",   cgroup, pid, curtask->real_parent->pid, comm, $errno, str(@filename[tid])); delete(@filename[tid]); }

END { clear(@filename); }

`

func filesUpdateFilters() string {
	filters := filesBpftrace
	filters = strings.ReplaceAll(filters, "FILTER_PATHNAME", filesBpftraceFilterPathname)
	filters = strings.ReplaceAll(filters, "FILTER_FILENAME", filesBpftraceFilterFilename)
	filters = strings.ReplaceAll(filters, "FILTER_PATH", filesBpftraceFilterPath)
	filters = strings.ReplaceAll(filters, "FILTER_TID", filesBpftraceFilterTID)
	return filters
}

func files() {
	var args filesArgs
	arg.MustParse(&args)
	//
	if exec.Command("bash", "-c", "mount | grep cgroup2").Run() != nil {
		lib.Logger.Println("fatal: cgroups v2 are required")
		lib.Logger.Println("https://wiki.archlinux.org/index.php/cgroups#Switching_to_cgroups_v2")
		lib.Logger.Println("https://wiki.archlinux.org/index.php/Kernel_parameters#GRUB")
		lib.Logger.Fatal("")
	}
	//
	//
	tempDir, err := os.MkdirTemp("", "docker-trace")
	if err != nil {
		lib.Logger.Fatal("error: ", err)
	}
	//
	// filter out events from cgroups created before this process started and from filepaths in /proc/, /sys/, /dev/
	err = os.WriteFile(tempDir+"/files.bt", []byte(filesUpdateFilters()), 0666)
	if err != nil {
		lib.Logger.Fatal("error: ", err)
	}
	//
	ctx, cancel := context.WithCancel(context.Background())
	//
	cleanup := func() {
		_ = os.RemoveAll(tempDir)
		cancel()
	}
	lib.SignalHandler(cleanup)
	//
	env := "BPFTRACE_STRLEN=200 BPFTRACE_MAP_KEYS_MAX=8192 BPFTRACE_PERF_RB_PAGES=" + fmt.Sprint(args.BpfRingBufferPages)
	cmd := exec.CommandContext(ctx, "/usr/bin/sudo", "bash", "-c", env+" bpftrace "+tempDir+"/files.bt")
	cmd.Stderr = os.Stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		lib.Logger.Fatal("error: ", err)
	}
	go func() {
		// defer func() {}()
		err := cmd.Run()
		if err != nil {
			lib.Logger.Fatal("error: ", err)
		}
	}()
	//
	buf := bufio.NewReader(stdout)
	line, err := buf.ReadBytes('\n')
	if err != nil {
		lib.Logger.Fatal("error: ", err)
	}
	if !(strings.HasPrefix(string(line), "Attaching ") && strings.HasSuffix(string(line), " probes...\n")) {
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
		line, err := buf.ReadString('\n')
		if err != nil {
			cleanup()
			if err == io.EOF || err == context.Canceled {
				return
			}
			lib.Logger.Fatal("error:", err)
		}
		line = strings.TrimRight(line, "\n")
		lib.FilesHandleLine(cwds, cgroups, line)
	}
}
