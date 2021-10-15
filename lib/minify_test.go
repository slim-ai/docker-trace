package lib

import (
	"bytes"
	"crypto/md5"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"path"
	"runtime"
	"strings"
	"testing"
	"time"
)

func md5SumMinify(bytes []byte) string {
	hash := md5.Sum(bytes)
	return hex.EncodeToString(hash[:])
}

func runStdinMinify(stdin string, command ...string) error {
	cmd := exec.Command(command[0], command[1:]...)
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	cmd.Stdin = bytes.NewBufferString(stdin + "\n")
	return cmd.Run()
}

func runStdoutMinify(command ...string) (string, error) {
	cmd := exec.Command(command[0], command[1:]...)
	var stdout bytes.Buffer
	cmd.Stderr = os.Stderr
	cmd.Stdout = &stdout
	err := cmd.Run()
	return strings.Trim(stdout.String(), "\n"), err
}

func runMinify(command ...string) error {
	cmd := exec.Command(command[0], command[1:]...)
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	return cmd.Run()
}

func runQuietMinify(command ...string) error {
	cmd := exec.Command(command[0], command[1:]...)
	return cmd.Run()
}

func climbGitRootMinify() {
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

func ensureDockerTraceMinify() {
	err := runMinify("go", "build", ".")
	if err != nil {
		panic(err)
	}
}

func ensureTestContainerMinify(app, kind string) string {
	stdout, err := runStdoutMinify("bash", "-c", fmt.Sprintf("cat examples/%s/*", app))
	if err != nil {
		panic(err)
	}
	hash := md5SumMinify([]byte(stdout))
	container := fmt.Sprintf("docker-trace:minify-%s-%s-%s", app, kind, hash)
	if runQuietMinify("docker", "inspect", container) != nil {
		err = runMinify("docker", "build", "-t", container, "--network", "host", "-f", "examples/"+app+"/Dockerfile."+kind, "examples/"+app)
		if err != nil {
			panic(err)
		}
	}
	return container
}

func ensureSetupMinify(app, kind string) string {
	_ = runQuietMinify("bash", "-c", "docker kill $(docker ps -q)")
	climbGitRootMinify()
	ensureDockerTraceMinify()
	container := ensureTestContainerMinify(app, kind)
	return container
}

func testWeb(t *testing.T, app, kind string) {
	container := ensureSetupMinify(app, kind)
	id, err := runStdoutMinify("docker", "create", "-t", "--rm", "--network", "host", container)
	if err != nil {
		t.Error(err)
		return
	}
	errChan := make(chan error)
	go func() {
		stdout, err := runStdoutMinify("./docker-trace", "files", id, "--start")
		if err != nil {
			errChan <- err
			return
		}
		fmt.Println("start minification")
		err = runStdinMinify(stdout, "./docker-trace", "minify", container, container+"-min")
		if err != nil {
			errChan <- err
			return
		}
		errChan <- nil
	}()
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		IdleConnTimeout: 1*time.Second,
		TLSHandshakeTimeout: 1*time.Second,
	}
	client := &http.Client{
		Transport: tr,
		Timeout: 1*time.Second,
	}
	//
	start := time.Now()
	for {
		if time.Since(start) > 10*time.Second {
			t.Error("timeout")
			return
		}
		out, err := client.Get("https://localhost:8080/hello/xyz")
		if err == nil {
			bytes, _ := ioutil.ReadAll(out.Body)
			_ = out.Body.Close()
			fmt.Println(out.StatusCode, string(bytes))
			break
		}
		fmt.Println(err)
		time.Sleep(1 * time.Second)
	}
	//
	err = runMinify("docker", "kill", id)
	if err != nil {
		t.Error(err)
		return
	}
	err = <-errChan
	if err != nil {
		t.Error(err)
		return
	}
	//
	out, err := client.Get("https://localhost:8080/hello/xyz")
	if err == nil {
		_ = out.Body.Close()
		t.Error("server should have been killed")
		return
	}
	//
	id, err = runStdoutMinify("docker", "run", "-d", "--network", "host", "--rm", container+"-min")
	if err != nil {
		t.Error(err)
		return
	}
	//
	start = time.Now()
	for {
		if time.Since(start) > 5*time.Second {
			t.Error("timeout")
			return
		}
		out, err := client.Get("https://localhost:8080/hello/xyz")
		if err == nil {
			bytes, _ := ioutil.ReadAll(out.Body)
			_ = out.Body.Close()
			fmt.Println(out.StatusCode, string(bytes))
			break
		}
		fmt.Println(err)
		time.Sleep(1 * time.Second)
	}
	//
	stdout, err := runStdoutMinify("docker", "inspect", container, "-f", "{{.Size}}")
	if err != nil {
		t.Error(err)
		return
	}
	size := lib.Atoi(stdout)
	//
	stdout, err = runStdoutMinify("docker", "inspect", container+"-min", "-f", "{{.Size}}")
	if err != nil {
		t.Error(err)
		return
	}
	sizeMin := lib.Atoi(stdout)
	if !(sizeMin < size) {
		t.Error("not smaller")
		return
	}
	err = runMinify("docker", "kill", id)
	if err != nil {
		t.Error(err)
		return
	}
}

func TestGoWebArch(t *testing.T) {
	testWeb(t, "go-web", "arch")
}

func TestGoWebAlpine(t *testing.T) {
	testWeb(t, "go-web", "alpine")
}

func TestGoWebDebian(t *testing.T) {
	testWeb(t, "go-web", "debian")
}

func TestGoWebUbuntu(t *testing.T) {
	testWeb(t, "go-web", "ubuntu")
}

func TestGoWebAmzn(t *testing.T) {
	testWeb(t, "go-web", "amzn")
}

func TestPythonWebArch(t *testing.T) {
	testWeb(t, "python3-web", "arch")
}

func TestPythonWebAlpine(t *testing.T) {
	testWeb(t, "python3-web", "alpine")
}

func TestPythonWebDebian(t *testing.T) {
	testWeb(t, "python3-web", "debian")
}

func TestPythonWebUbuntu(t *testing.T) {
	testWeb(t, "python3-web", "ubuntu")
}

func TestPythonWebAmzn(t *testing.T) {
	testWeb(t, "python3-web", "amzn")
}

func TestNodeWebArch(t *testing.T) {
	testWeb(t, "node-web", "arch")
}

func TestNodeWebAlpine(t *testing.T) {
	testWeb(t, "node-web", "alpine")
}

func TestNodeWebDebian(t *testing.T) {
	testWeb(t, "node-web", "debian")
}

func TestNodeWebUbuntu(t *testing.T) {
	testWeb(t, "node-web", "ubuntu")
}

func TestNodeWebAmzn(t *testing.T) {
	testWeb(t, "node-web", "amzn")
}
