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

package main

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/notaryproject/notation-go/config"

	"github.com/notaryproject/notation-go/log"
	"github.com/notaryproject/notation/cmd/notation/internal/option"
	"github.com/notaryproject/notation/internal/ioutil"
	"github.com/spf13/cobra"
)

type keyAddOpts struct {
	option.Logging
	option.Plugin
	option.IsDefaultKey
	name string
}

type keyUpdateOpts struct {
	option.Logging
	option.IsDefaultKey
	name string
}

type keyDeleteOpts struct {
	option.Logging
	names []string
}

func keyCommand() *cobra.Command {
	command := &cobra.Command{
		Use:   "key",
		Short: "Manage keys used for signing",
		Long: `Manage keys used for signing

Example - Add a key to signing key list:
  notation key add --plugin <plugin_name> --id <key_id> <key_name>

Example - List keys used for signing:
  notation key ls

Example - Update the default signing key:
  notation key set --default <key_name>

Example - Delete the key from signing key list:
  notation key delete <key_name>...
`,
	}
	command.AddCommand(keyAddCommand(nil), keyUpdateCommand(nil), keyListCommand(), keyDeleteCommand(nil))

	return command
}

func keyAddCommand(opts *keyAddOpts) *cobra.Command {
	if opts == nil {
		opts = &keyAddOpts{}
	}
	command := &cobra.Command{
		Use:   "add --plugin <plugin_name> [flags] <key_name>",
		Short: "Add key to Notation signing key list",
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return errors.New("either missing key name or unnecessary parameters passed")
			}
			opts.name = args[0]
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			return addKey(cmd.Context(), opts)
		},
	}
	opts.Logging.ApplyFlags(command.Flags())
	opts.Plugin.ApplyFlags(command)
	opts.IsDefaultKey.ApplyFlags(command.Flags())
	command.MarkFlagRequired("plugin")

	return command
}

func keyUpdateCommand(opts *keyUpdateOpts) *cobra.Command {
	if opts == nil {
		opts = &keyUpdateOpts{}
	}
	command := &cobra.Command{
		Use:     "update [flags] <key_name>",
		Aliases: []string{"set"},
		Short:   "Update key in Notation signing key list",
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return errors.New("missing key name")
			}
			opts.name = args[0]
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			return updateKey(cmd.Context(), opts)
		},
	}

	opts.Logging.ApplyFlags(command.Flags())
	opts.IsDefaultKey.ApplyFlags(command.Flags())

	return command
}

func keyListCommand() *cobra.Command {
	return &cobra.Command{
		Use:     "list [flags]",
		Aliases: []string{"ls"},
		Short:   "List keys used for signing",
		RunE: func(cmd *cobra.Command, args []string) error {
			return listKeys()
		},
	}
}

func keyDeleteCommand(opts *keyDeleteOpts) *cobra.Command {
	if opts == nil {
		opts = &keyDeleteOpts{}
	}

	command := &cobra.Command{
		Use:   "delete [flags] <key_name>...",
		Short: "Remove key from Notation signing key list",
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return errors.New("missing key names")
			}
			opts.names = args
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			return deleteKeys(cmd.Context(), opts)
		},
	}
	opts.Logging.ApplyFlags(command.Flags())

	return command
}

func addKey(ctx context.Context, opts *keyAddOpts) error {
	// set log level
	ctx = opts.Logging.InitializeLogger(ctx)

	pluginConfig, err := opts.PluginConfig.ToMap()
	if err != nil {
		return err
	}

	// core process
	exec := func(s *config.SigningKeys) error {
		return s.AddPlugin(ctx, opts.name, opts.KeyID, opts.PluginName, pluginConfig, opts.IsDefault)
	}
	if err := config.LoadExecSaveSigningKeys(exec); err != nil {
		return err
	}

	if opts.IsDefault {
		fmt.Printf("%s: marked as default\n", opts.name)
	} else {
		fmt.Println(opts.name)
	}

	return nil
}

func updateKey(ctx context.Context, opts *keyUpdateOpts) error {
	// set log level
	ctx = opts.Logging.InitializeLogger(ctx)
	logger := log.GetLogger(ctx)

	if !opts.IsDefault {
		logger.Warn("--default flag is not set, command did not take effect")
		return nil
	}

	// core process
	exec := func(s *config.SigningKeys) error {
		return s.UpdateDefault(opts.name)
	}
	if err := config.LoadExecSaveSigningKeys(exec); err != nil {
		return err
	}

	// write out
	fmt.Printf("%s: marked as default\n", opts.name)
	return nil
}

func listKeys() error {
	// core process
	signingKeys, err := config.LoadSigningKeys()
	if err != nil {
		return err
	}

	// write out
	return ioutil.PrintKeyMap(os.Stdout, signingKeys.Default, signingKeys.Keys)
}

func deleteKeys(ctx context.Context, opts *keyDeleteOpts) error {
	// set log level
	ctx = opts.Logging.InitializeLogger(ctx)
	logger := log.GetLogger(ctx)

	// core process
	var deletedNames []string
	var prevDefault string
	exec := func(s *config.SigningKeys) error {
		if s.Default != nil {
			prevDefault = *s.Default
		}
		var err error
		deletedNames, err = s.Remove(opts.names...)
		if err != nil {
			logger.Errorf("Keys deletion failed to complete with error: %v", err)
		}
		return err
	}
	if err := config.LoadExecSaveSigningKeys(exec); err != nil {
		return err
	}

	// write out
	if len(deletedNames) == 1 {
		name := deletedNames[0]
		if name == prevDefault {
			fmt.Printf("Removed default key %s from Notation signing key list. The source key still exists.\n", name)
		} else {
			fmt.Printf("Removed %s from Notation signing key list. The source key still exists.\n", name)
		}
	} else if len(deletedNames) > 1 {
		fmt.Println("Removed the following keys from Notation signing key list. The source keys still exist.")
		for _, name := range deletedNames {
			if name == prevDefault {
				fmt.Println(name, "(default)")
			} else {
				fmt.Println(name)
			}
		}
	}
	return nil
}
