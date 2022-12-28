package notation

import (
	"os"
	"path/filepath"

	"github.com/notaryproject/notation/test/e2e/internal/utils"
	. "github.com/onsi/ginkgo/v2"
)

// Host creates a virtualized notation testing host by modify
// the "XDG_CONFIG_HOME" environment variable of the Executor.
//
// options is the required testing environment options
// fn is the callback function containing the testing logic.
func Host(options []utils.HostOption, fn func(notation *utils.ExecOpts, artifact *Artifact, vhost *utils.VirtualHost)) {
	// create a notation vhost
	vhost, err := createNotationHost(NotationBinPath, options...)
	if err != nil {
		panic(err)
	}

	// generate a repository with an artifact
	artifact := GenerateArtifact("", "")
	DeferCleanup(artifact.Remove)

	// run the main logic
	fn(vhost.Executor, artifact, vhost)
}

// OldNotation create a notation ExecOpts for testing forward compatibility.
func OldNotation(options ...utils.HostOption) *utils.ExecOpts {
	if len(options) == 0 {
		options = BaseOptions()
	}

	vhost, err := createNotationHost(NotationOldBinPath, options...)
	if err != nil {
		panic(err)
	}

	return vhost.Executor
}

func createNotationHost(path string, options ...utils.HostOption) (*utils.VirtualHost, error) {
	vhost, err := utils.NewVirtualHost(path, CreateNotationDirOption())
	if err != nil {
		return nil, err
	}

	// set additional options
	vhost.SetOption(options...)
	return vhost, nil
}

// Opts is a grammar sugar to generate a list of HostOption
func Opts(options ...utils.HostOption) []utils.HostOption {
	return options
}

// BaseOptions returns a list of base Options for a valid notation
// testing environment.
func BaseOptions() []utils.HostOption {
	return Opts(
		AuthOption("", ""),
		AddTestKeyOption(),
		AddTestTrustStoreOption("e2e", NotationE2ECertPath),
		AddTrustPolicyOption("trustpolicy.json"),
	)
}

// CreateNotationDirOption creates the notation directory in temp user dir.
func CreateNotationDirOption() utils.HostOption {
	return func(vhost *utils.VirtualHost) error {
		return os.MkdirAll(vhost.UserPath(NotationDirName), os.ModePerm)
	}
}

// AuthOption sets the auth environment variables for notation.
func AuthOption(username, password string) utils.HostOption {
	if username == "" {
		username = TestRegistry.Username
	}
	if password == "" {
		password = TestRegistry.Password
	}
	return func(vhost *utils.VirtualHost) error {
		vhost.UpdateEnv(authEnv(username, password))
		return nil
	}
}

// AddTestKeyOption adds the test signingkeys.json, key and cert files to
// the notation directory.
func AddTestKeyOption() utils.HostOption {
	return func(vhost *utils.VirtualHost) error {
		return AddTestKeyPairs(vhost.UserPath(NotationDirName))
	}
}

// AddTestTrustStoreOption added the test cert to the trust store.
func AddTestTrustStoreOption(namedstore string, srcCertPath string) utils.HostOption {
	return func(vhost *utils.VirtualHost) error {
		vhost.Executor.
			Exec("cert", "add", "--type", "ca", "--store", namedstore, srcCertPath).
			MatchKeyWords("Successfully added following certificates")
		return nil
	}
}

// AddTrustPolicyOption added a valid trust policy for testing
func AddTrustPolicyOption(trustpolicyName string) utils.HostOption {
	return func(vhost *utils.VirtualHost) error {
		return copyFile(
			filepath.Join(NotationE2ETrustPolicyDir, trustpolicyName),
			vhost.UserPath(NotationDirName, TrustPolicyName),
		)
	}
}

// authEnv creates an auth info
// (By setting $NOTATION_USERNAME and $NOTATION_PASSWORD)
func authEnv(username, password string) map[string]string {
	env := make(map[string]string)
	env["NOTATION_USERNAME"] = username
	env["NOTATION_PASSWORD"] = password
	return env
}
