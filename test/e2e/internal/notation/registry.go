package notation

import (
	"context"
	"fmt"
	"math"
	"math/rand"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"oras.land/oras-go/v2/registry"
	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"
)

const (
	testRepo = "e2e"
	testTag  = "v1"
)

type Registry struct {
	Host     string
	Username string
	Password string
}

var TestRegistry = Registry{}

type Artifact struct {
	*Registry
	Repo   string
	Tag    string
	Digest string
}

// GenerateArtifact generates a new image with a new repository.
func GenerateArtifact() *Artifact {
	// generate new newRepo
	newRepo := newRepoId()

	// copy oci layout to the new repo
	if err := copyDir(filepath.Join(OCILayoutPath, testRepo), filepath.Join(RegistryStoragePath, newRepo)); err != nil {
		panic(err)
	}

	artifact := &Artifact{
		Registry: &Registry{
			Host:     TestRegistry.Host,
			Username: TestRegistry.Username,
			Password: TestRegistry.Password,
		},
		Repo: newRepo,
		Tag:  "v1",
	}

	if err := artifact.Validate(); err != nil {
		panic(err)
	}

	if err := artifact.fetchDigest(); err != nil {
		panic(err)
	}

	return artifact
}

// Validate validates the registry and artifact is valid.
func (r *Artifact) Validate() error {
	if _, err := url.ParseRequestURI(r.Host); err != nil {
		return err
	}
	ref, err := registry.ParseReference(r.ReferenceWithTag())
	if err != nil {
		return err
	}
	if ref.Registry != r.Host {
		return fmt.Errorf("registry host %q mismatch base image %q", r.Host, r.Repo)
	}
	return nil
}

func (r *Artifact) fetchDigest() error {
	// create repository
	ref, err := registry.ParseReference(r.ReferenceWithTag())
	if err != nil {
		return err
	}
	authClient := &auth.Client{
		Credential: func(ctx context.Context, registry string) (auth.Credential, error) {
			switch registry {
			case ref.Host():
				return auth.Credential{
					Username: TestRegistry.Username,
					Password: TestRegistry.Password,
				}, nil
			default:
				return auth.EmptyCredential, nil
			}
		},
		Cache:    auth.NewCache(),
		ClientID: "notation",
	}
	repo := &remote.Repository{
		Client:    authClient,
		Reference: ref,
		PlainHTTP: true,
	}

	// resolve descriptor
	descriptor, err := repo.Resolve(context.Background(), r.ReferenceWithTag())
	if err != nil {
		return err
	}

	// set digest
	r.Digest = descriptor.Digest.String()
	return nil
}

// ReferenceWithTag returns the <registryHost>/<Repository>:<Tag>
func (r *Artifact) ReferenceWithTag() string {
	return fmt.Sprintf("%s/%s:%s", r.Host, r.Repo, r.Tag)
}

// ReferenceWithDigest returns the <registryHost>/<Repository>@<alg>:<digest>
func (r *Artifact) ReferenceWithDigest() string {
	return fmt.Sprintf("%s/%s@%s", r.Host, r.Repo, r.Digest)
}

// Reference removes the the repository of the artifact.
func (r *Artifact) Remove() error {
	return os.RemoveAll(filepath.Join(RegistryStoragePath, r.Repo))
}

func newRepoId() string {
	var newRepo string
	for {
		// set the seed with nanosecond precision.
		rand.Seed(time.Now().UnixNano())
		newRepo = fmt.Sprintf("%s-%d", testRepo, rand.Intn(math.MaxInt32))

		// do the path existence check. Even with the check, it doesn't
		// guaranty generate unique repoId because we cannot prevent multiple
		// processes enter the check at the same moment with the same newRepo,
		// however, the possibility is very low.
		_, err := os.Stat(filepath.Join(RegistryStoragePath, newRepo))
		if err != nil {
			if os.IsNotExist(err) {
				// repo doesn't exist.
				break
			}
			panic(err)
		}
	}
	return newRepo
}
