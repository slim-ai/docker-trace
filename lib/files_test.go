package lib

import (
	// "time"
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path"
	"runtime"
	"strings"
	"testing"
)

func md5Sum(bytes []byte) string {
	hash := md5.Sum(bytes)
	return hex.EncodeToString(hash[:])
}

func runStdout(command ...string) (string, error) {
	cmd := exec.Command(command[0], command[1:]...)
	var stdout bytes.Buffer
	cmd.Stderr = os.Stderr
	cmd.Stdout = &stdout
	err := cmd.Run()
	return strings.Trim(stdout.String(), "\n"), err
}

func run(command ...string) error {
	cmd := exec.Command(command[0], command[1:]...)
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	return cmd.Run()
}

func runQuiet(command ...string) error {
	cmd := exec.Command(command[0], command[1:]...)
	return cmd.Run()
}

const dockerfile = `
FROM archlinux:latest
RUN pacman -Syu --noconfirm go python gcc
`

var container = fmt.Sprintf("docker-trace:test-%s", md5Sum([]byte(dockerfile)))

func climbGitRoot() {
	_, filename, _, _ := runtime.Caller(1)
	err := os.Chdir(path.Dir(filename))
	if err != nil {
		panic(err)
	}
outer:
	for {
		files, err := ioutil.ReadDir(".")
		if err != nil {
			panic(err)
		}
		for _, file := range files {
			if file.IsDir() && file.Name() == ".git" {
				break outer
			}
			if file.Name() == "/" {
				panic("/")
			}
		}
		err = os.Chdir("..")
		if err != nil {
			panic(err)
		}
	}
}

func ensureTestContainer() {
	if runQuiet("docker", "inspect", container) != nil {
		dir, err := ioutil.TempDir("", "docker-trace-test.")
		if err != nil {
			panic(err)
		}
		err = ioutil.WriteFile(dir+"/Dockerfile", []byte(dockerfile), 0666)
		if err != nil {
			panic(err)
		}
		err = run("docker", "build", "-t", container, "--network", "host", dir)
		if err != nil {
			panic(err)
		}
		err = os.RemoveAll(dir)
		if err != nil {
			panic(err)
		}
	}
}

func ensureDockerTrace() {
	err := run("go", "build", ".")
	if err != nil {
		panic(err)
	}
}

func ensureSetup() {
	climbGitRoot()
	ensureTestContainer()
	ensureDockerTrace()
}

func TestTraceCat(t *testing.T) {
	ensureSetup()
	id, err := runStdout("docker", "create", "-t", "--rm", container, "bash", "-c", "cat /etc/hosts")
	if err != nil {
		t.Error(err)
		return
	}
	stdout, err := runStdout("./docker-trace", "files", id, "--start")
	if err != nil {
		t.Error(err)
		return
	}
	files := strings.Split(stdout, "\n")
	if !Contains(files, "/etc/hosts") {
		fmt.Println(stdout)
		t.Errorf("didnt find /etc/hosts")
		return
	}
}

func TestTraceCdCat(t *testing.T) {
	ensureSetup()
	id, err := runStdout("docker", "create", "-t", "--rm", container, "bash", "-c", "cd /etc && cat hosts")
	if err != nil {
		t.Error(err)
		return
	}
	stdout, err := runStdout("./docker-trace", "files", id, "--start")
	if err != nil {
		t.Error(err)
		return
	}
	files := strings.Split(stdout, "\n")
	if !Contains(files, "/etc/hosts") {
		fmt.Println(stdout)
		t.Errorf("didnt find /etc/hosts")
		return
	}
}

func TestTraceCdBashCat(t *testing.T) {
	ensureSetup()
	id, err := runStdout("docker", "create", "-t", "--rm", container, "bash", "-c", "cd /etc && bash -c \"cat hosts\"")
	if err != nil {
		t.Error(err)
		return
	}
	stdout, err := runStdout("./docker-trace", "files", id, "--start")
	if err != nil {
		t.Error(err)
		return
	}
	files := strings.Split(stdout, "\n")
	if !Contains(files, "/etc/hosts") {
		fmt.Println(stdout)
		t.Errorf("didnt find /etc/hosts")
		return
	}
}

func TestTracePythonOpen(t *testing.T) {
	ensureSetup()
	id, err := runStdout("docker", "create", "-t", "--rm", container, "python", "-c", "open('/etc/hosts')")
	if err != nil {
		t.Error(err)
		return
	}
	stdout, err := runStdout("./docker-trace", "files", id, "--start")
	if err != nil {
		t.Error(err)
		return
	}
	files := strings.Split(stdout, "\n")
	if !Contains(files, "/etc/hosts") {
		fmt.Println(stdout)
		t.Errorf("didnt find /etc/hosts")
		return
	}
}

func TestTraceBashCdPythonOpen(t *testing.T) {
	ensureSetup()
	id, err := runStdout("docker", "create", "-t", "--rm", container, "bash", "-c", "cd /etc && python -c \"open('hosts')\"")
	if err != nil {
		t.Error(err)
		return
	}
	stdout, err := runStdout("./docker-trace", "files", id, "--start")
	if err != nil {
		t.Error(err)
		return
	}
	files := strings.Split(stdout, "\n")
	if !Contains(files, "/etc/hosts") {
		fmt.Println(stdout)
		t.Errorf("didnt find /etc/hosts")
		return
	}
}

func TestTracePythonCdOpen(t *testing.T) {
	ensureSetup()
	id, err := runStdout("docker", "create", "-t", "--rm", container, "python", "-c", "import os; os.chdir('/etc'); open('hosts')")
	if err != nil {
		t.Error(err)
		return
	}
	stdout, err := runStdout("./docker-trace", "files", id, "--start")
	if err != nil {
		t.Error(err)
		return
	}
	files := strings.Split(stdout, "\n")
	if !Contains(files, "/etc/hosts") {
		fmt.Println(stdout)
		t.Errorf("didnt find /etc/hosts")
		return
	}
}

func TestTracePythonCdStat(t *testing.T) {
	ensureSetup()
	id, err := runStdout("docker", "create", "-t", "--rm", container, "python", "-c", "import os; os.chdir('/etc'); os.stat('hosts')")
	if err != nil {
		t.Error(err)
		return
	}
	stdout, err := runStdout("./docker-trace", "files", id, "--start")
	if err != nil {
		t.Error(err)
		return
	}
	files := strings.Split(stdout, "\n")
	if !Contains(files, "/etc/hosts") {
		fmt.Println(stdout)
		t.Errorf("didnt find /etc/hosts")
		return
	}
}

func TestTraceGoOpen(t *testing.T) {
	ensureSetup()
	dir, err := ioutil.TempDir("", "docker-trace-test.")
	if err != nil {
		t.Error(err)
		return
	}
	defer func() { _ = os.RemoveAll(dir) }()
	const code = `
package main
import (
    "os"
    "time"
)
func main() {
    go func() {
      _, err := os.Open("/etc/hosts")
      if err != nil {
          panic(err)
      }
      os.Exit(0)
    }()
    time.Sleep(time.Hour)
}
`
	err = ioutil.WriteFile(dir+"/main.go", []byte(code), 0666)
	if err != nil {
		t.Error(err)
		return
	}
	id, err := runStdout("docker", "create", "-t", "-v", dir+":/code", "--rm", container, "go", "run", "/code/main.go")
	if err != nil {
		t.Error(err)
		return
	}
	stdout, err := runStdout("./docker-trace", "files", id, "--start")
	if err != nil {
		t.Error(err)
		return
	}
	files := strings.Split(stdout, "\n")
	if !Contains(files, "/etc/hosts") {
		fmt.Println(stdout)
		t.Errorf("didnt find /etc/hosts")
		return
	}
}

func TestTraceGoCdOpen(t *testing.T) {
	ensureSetup()
	dir, err := ioutil.TempDir("", "docker-trace-test.")
	if err != nil {
		t.Error(err)
		return
	}
	defer func() { _ = os.RemoveAll(dir) }()
	const code = `
package main
import (
    "os"
    "time"
)
func main() {
    go func() {
      err := os.Chdir("/etc")
      if err != nil {
          panic(err)
      }
      _, err = os.Open("hosts")
      if err != nil {
          panic(err)
      }
      os.Exit(0)
    }()
    time.Sleep(time.Hour)
}
`
	err = ioutil.WriteFile(dir+"/main.go", []byte(code), 0666)
	if err != nil {
		t.Error(err)
		return
	}
	id, err := runStdout("docker", "create", "-t", "-v", dir+":/code", "--rm", container, "go", "run", "/code/main.go")
	if err != nil {
		t.Error(err)
		return
	}
	stdout, err := runStdout("./docker-trace", "files", id, "--start")
	if err != nil {
		t.Error(err)
		return
	}
	files := strings.Split(stdout, "\n")
	if !Contains(files, "/etc/hosts") {
		fmt.Println(stdout)
		t.Errorf("didnt find /etc/hosts")
		return
	}
}

func TestTraceGoCdStat(t *testing.T) {
	ensureSetup()
	dir, err := ioutil.TempDir("", "docker-trace-test.")
	if err != nil {
		t.Error(err)
		return
	}
	defer func() { _ = os.RemoveAll(dir) }()
	const code = `
package main
import (
    "os"
    "time"
)
func main() {
    go func() {
      err := os.Chdir("/etc")
      if err != nil {
          panic(err)
      }
      _, err = os.Stat("hosts")
      if err != nil {
          panic(err)
      }
      os.Exit(0)
    }()
    time.Sleep(time.Hour)
}
`
	err = ioutil.WriteFile(dir+"/main.go", []byte(code), 0666)
	if err != nil {
		t.Error(err)
		return
	}
	id, err := runStdout("docker", "create", "-t", "-v", dir+":/code", "--rm", container, "go", "run", "/code/main.go")
	if err != nil {
		t.Error(err)
		return
	}
	stdout, err := runStdout("./docker-trace", "files", id, "--start")
	if err != nil {
		t.Error(err)
		return
	}
	files := strings.Split(stdout, "\n")
	if !Contains(files, "/etc/hosts") {
		fmt.Println(stdout)
		t.Errorf("didnt find /etc/hosts")
		return
	}
}
