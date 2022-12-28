package command

import (
	"fmt"
	"path/filepath"
	"time"

	. "github.com/notaryproject/notation/test/e2e/internal/notation"
	"github.com/notaryproject/notation/test/e2e/internal/utils"
	. "github.com/onsi/ginkgo/v2"
)

var _ = Describe("notation trust policy test", func() {
	It("test registryScope with a repository", func() {
		Host(BaseOptions(), func(notation *utils.ExecOpts, _ *Artifact, vhost *utils.VirtualHost) {
			// update trustpolicy.json
			vhost.SetOption(AddTrustPolicyOption("registry_scope_trustpolicy.json"))

			// generate an artifact with given repository name
			artifact := GenerateArtifact("", "test-repo")
			DeferCleanup(artifact.Remove)

			// test localhost:5000/test-repo
			OldNotation().Exec("sign", artifact.ReferenceWithDigest()).MatchKeyWords(signMessage)
			notation.Exec("verify", artifact.ReferenceWithDigest()).MatchKeyWords(verifyMessage)
		})
	})

	It("test registryScope with multiple repositories", func() {
		Host(BaseOptions(), func(notation *utils.ExecOpts, _ *Artifact, vhost *utils.VirtualHost) {
			// update trustpolicy.json
			vhost.SetOption(AddTrustPolicyOption("multiple_registry_scope_trustpolicy.json"))

			// generate an artifact with given repository name
			artifact2 := GenerateArtifact("", "test-repo2")
			DeferCleanup(artifact2.Remove)
			artifact3 := GenerateArtifact("", "test-repo3")
			DeferCleanup(artifact3.Remove)

			// test localhost:5000/test-repo2
			OldNotation().Exec("sign", artifact2.ReferenceWithDigest()).MatchKeyWords(signMessage)
			notation.Exec("verify", artifact2.ReferenceWithDigest()).MatchKeyWords(verifyMessage)

			// test localhost:5000/test-repo3
			OldNotation().Exec("sign", artifact3.ReferenceWithDigest()).MatchKeyWords(signMessage)
			notation.Exec("verify", artifact3.ReferenceWithDigest()).MatchKeyWords(verifyMessage)
		})
	})

	It("test registryScope with any(*) repository", func() {
		Host(BaseOptions(), func(notation *utils.ExecOpts, _ *Artifact, vhost *utils.VirtualHost) {
			// generate an artifact with given repository name
			artifact4 := GenerateArtifact("", "test-repo4")
			DeferCleanup(artifact4.Remove)
			artifact5 := GenerateArtifact("", "test-repo5")
			DeferCleanup(artifact5.Remove)

			// test localhost:5000/test-repo4
			OldNotation().Exec("sign", artifact4.ReferenceWithDigest()).MatchKeyWords(signMessage)
			notation.Exec("verify", artifact4.ReferenceWithDigest()).MatchKeyWords(verifyMessage)

			// test localhost:5000/test-repo5
			OldNotation().Exec("sign", artifact5.ReferenceWithDigest()).MatchKeyWords(signMessage)
			notation.Exec("verify", artifact5.ReferenceWithDigest()).MatchKeyWords(verifyMessage)
		})
	})

	It("test invalid registryScope", func() {
		Host(BaseOptions(), func(notation *utils.ExecOpts, artifact *Artifact, vhost *utils.VirtualHost) {
			// update trustpolicy.json
			vhost.SetOption(AddTrustPolicyOption("invalid_registry_scope_trustpolicy.json"))

			// test localhost:5000/test-repo
			OldNotation().Exec("sign", artifact.ReferenceWithDigest()).MatchKeyWords(signMessage)
			notation.ExpectFailure().Exec("verify", artifact.ReferenceWithDigest()).
				MatchErrContent(fmt.Sprintf("Error: signature verification failed: artifact %q has no applicable trust policy\n", artifact.ReferenceWithDigest()))
		})
	})

	It("test signatureVerification level strict with expired signature", func() {
		Host(BaseOptions(), func(notation *utils.ExecOpts, artifact *Artifact, vhost *utils.VirtualHost) {
			OldNotation().Exec("sign", "--expiry", "2s", artifact.ReferenceWithDigest()).
				MatchKeyWords(signMessage)

			// sleep to wait for expiry
			time.Sleep(2100 * time.Millisecond)

			notation.ExpectFailure().Exec("verify", artifact.ReferenceWithDigest(), "-v").
				MatchErrKeyWords("expiry validation failed.").
				MatchErrKeyWords("signature verification failed")
		})
	})

	It("test signatureVerification level strict with expired authentic timestamp", func() {
		Host(nil, func(notation *utils.ExecOpts, _ *Artifact, vhost *utils.VirtualHost) {
			artifact := GenerateArtifact("e2e-with-expired-cert", "")
			DeferCleanup(artifact.Remove)

			vhost.SetOption(AuthOption("", ""),
				AddTrustPolicyOption("trustpolicy.json"),
				AddTestTrustStoreOption("e2e", filepath.Join(NotationE2EConfigPath, "localkeys", "expired_e2e.crt")))

			notation.ExpectFailure().Exec("verify", artifact.ReferenceWithDigest(), "-v").
				MatchErrKeyWords("authenticTimestamp validation failed").
				MatchErrKeyWords("signature verification failed")
		})
	})
})
