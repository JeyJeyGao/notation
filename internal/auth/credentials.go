// Copyright The Notary Project Authors.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package auth

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/notaryproject/notation-go/dir"
	credentials "github.com/oras-project/oras-credentials-go"
)

// NewCredentialsStore returns a new credentials store from the settings in the
// configuration file.
func NewCredentialsStore() (credentials.Store, error) {
	configPath, err := dir.ConfigFS().SysPath(dir.PathConfigFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load config file: %w", err)
	}

	// use notation config
	opts := credentials.StoreOptions{AllowPlaintextPut: false}
	notationStore, err := credentials.NewStore(configPath, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to create credential store from config file: %w", err)
	}
	if notationStore.IsAuthConfigured() {
		fmt.Printf("Debug: use Notation config. Path: %s\n", configPath)
		return notationStore, nil
	}

	// use docker config
	dockerStore, err := credentials.NewStoreFromDocker(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to create credential store from docker config file: %w", err)
	}
	if dockerStore.IsAuthConfigured() {
		dockerConfig := os.Getenv("DOCKER_CONFIG")
		fmt.Println("Debug: use Docker config credential store.")
		fmt.Printf("Debug: DOCKER_CONFIG: %s", dockerConfig)

		dockerConfigPath := filepath.Join(dockerConfig, "config.json")
		_, err := os.Open(dockerConfigPath)
		if err != nil {
			if os.IsNotExist(err) {
				// init content and caches if the content file does not exist
				fmt.Printf("Debug: Docker config file does not exist. Path: %s\n", dockerConfigPath)
				return dockerStore, nil
			}
			return nil, fmt.Errorf("failed to open config file at %s: %w", configPath, err)
		}
		return dockerStore, nil
	}

	// detect platform-default native store
	if osDefaultStore, ok := credentials.NewDefaultNativeStore(); ok {
		fmt.Println("Debug: use default native store.")
		return osDefaultStore, nil
	}
	// if the default store is not available, still use notation store so that
	// there won't be errors when getting credentials
	fmt.Println("Debug: fallback to notation config due to no valid Docker config and no default native store.")
	return notationStore, nil
}
