// +build linux

package libcontainer

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
)

func newTestRoot() (string, error) {
	dir, err := ioutil.TempDir("", "libcontainer")
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}
	return dir, nil
}

func TestFactoryNew(t *testing.T) {
	root, rerr := newTestRoot()
	if rerr != nil {
		t.Fatal(rerr)
	}
	defer os.RemoveAll(root)

	factory, err := New(root)
	if err != nil {
		t.Fatal(err)
	}

	if factory == nil {
		t.Fatal("factory should not be nil")
	}

	lfactory, ok := factory.(*linuxFactory)
	if !ok {
		t.Fatal("expected linux factory returned on linux based systems")
	}

	if lfactory.root != root {
		t.Fatalf("expected factory root to be %q but received %q", root, lfactory.root)
	}
}

func TestFactoryLoadNotExists(t *testing.T) {
	root, rerr := newTestRoot()
	if rerr != nil {
		t.Fatal(rerr)
	}
	defer os.RemoveAll(root)

	factory, err := New(root)
	if err != nil {
		t.Fatal(err)
	}

	_, err = factory.Load("nocontainer")
	if err == nil {
		t.Fatal("expected nil error loading non-existing container")
	}

	lerr, ok := err.(Error)
	if !ok {
		t.Fatal("expected libcontainer error type")
	}
	if lerr.Code() != ContainerNotExists {
		t.Fatalf("expected error code %s but received %s", ContainerNotExists, lerr.Code())
	}
}

func TestFactoryLoadContainer(t *testing.T) {
	root, err := newTestRoot()
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)

	// setup default container config and state for mocking
	var (
		id             = "1"
		expectedConfig = &Config{
			RootFs: "/mycontainer/root",
		}
		expectedState = &State{
			InitPid: 1024,
		}
	)

	if err := os.Mkdir(filepath.Join(root, id), 0700); err != nil {
		t.Fatal(err)
	}
	if err := marshal(filepath.Join(root, id, configFilename), expectedConfig); err != nil {
		t.Fatal(err)
	}
	if err := marshal(filepath.Join(root, id, stateFilename), expectedState); err != nil {
		t.Fatal(err)
	}

	factory, err := New(root)
	if err != nil {
		t.Fatal(err)
	}

	container, err := factory.Load(id)
	if err != nil {
		t.Fatal(err)
	}

	if container.ID() != id {
		t.Fatalf("expected container id %q but received %q", id, container.ID())
	}

	config := container.Config()
	if config == nil {
		t.Fatal("expected non nil container config")
	}

	if config.RootFs != expectedConfig.RootFs {
		t.Fatalf("expected rootfs %q but received %q", expectedConfig.RootFs, config.RootFs)
	}

	lcontainer, ok := container.(*linuxContainer)
	if !ok {
		t.Fatal("expected linux container on linux based systems")
	}

	if lcontainer.state.InitPid != expectedState.InitPid {
		t.Fatalf("expected init pid %d but received %d", expectedState.InitPid, lcontainer.state.InitPid)
	}
}

func marshal(path string, v interface{}) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return json.NewEncoder(f).Encode(v)
}
