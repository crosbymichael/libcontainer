// +build linux

package libcontainer

import (
	"encoding/json"
	"os"
	"path/filepath"
)

const (
	configFilename = "config.json"
	stateFilename  = "state.json"
)

// New returns a linux based container factory based in the root directory.
func New(root string) (Factory, Error) {
	if err := os.MkdirAll(root, 0700); err != nil {
		return nil, newGenericError(err, SystemError)
	}

	return &linuxFactory{
		root: root,
	}, nil
}

// linuxFactory implements the default factory interface for linux based systems.
type linuxFactory struct {
	// root is the root directory
	root string
}

func (l *linuxFactory) Create(id string, config *Config) (Container, Error) {
	panic("not implemented")
}

func (l *linuxFactory) Load(id string) (ContainerInfo, Error) {
	containerRoot := filepath.Join(l.root, id)
	config, err := l.loadContainerConfig(containerRoot)
	if err != nil {
		return nil, err
	}

	state, err := l.loadContainerState(containerRoot)
	if err != nil {
		return nil, err
	}

	return &linuxContainer{
		id:     id,
		root:   containerRoot,
		config: config,
		state:  state,
	}, nil
}

func (l *linuxFactory) loadContainerConfig(root string) (*Config, Error) {
	f, err := os.Open(filepath.Join(root, configFilename))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, newGenericError(err, ContainerDestroyed)
		}
		return nil, newGenericError(err, SystemError)
	}
	defer f.Close()

	var config *Config
	if err := json.NewDecoder(f).Decode(&config); err != nil {
		return nil, newGenericError(err, ConfigInvalid)
	}
	return config, nil
}

func (l *linuxFactory) loadContainerState(root string) (*State, Error) {
	f, err := os.Open(filepath.Join(root, stateFilename))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, newGenericError(err, ContainerDestroyed)
		}
		return nil, newGenericError(err, SystemError)
	}
	defer f.Close()

	var state *State
	if err := json.NewDecoder(f).Decode(&state); err != nil {
		return nil, newGenericError(err, SystemError)
	}
	return state, nil
}
