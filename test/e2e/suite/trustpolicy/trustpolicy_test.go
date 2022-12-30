package trustpolicy

import (
	"fmt"
	"path/filepath"
	"testing"

	. "github.com/notaryproject/notation/test/e2e/internal/notation"
	"github.com/notaryproject/notation/test/e2e/internal/utils"
	. "github.com/notaryproject/notation/test/e2e/suite/common"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestTrustPolicy(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Trust Policy Suite")
}

var _ = Describe("notation trust policy test", func() {
	It("test registryScope with a repository", func() {
		Host(BaseOptions(), func(notation *utils.ExecOpts, _ *Artifact, vhost *utils.VirtualHost) {
			// update trustpolicy.json
			vhost.SetOption(AddTrustPolicyOption("registry_scope_trustpolicy.json"))

			// generate an artifact with given repository name
			artifact := GenerateArtifact("", "test-repo")

			// test localhost:5000/test-repo
			OldNotation().Exec("sign", artifact.ReferenceWithDigest()).MatchKeyWords(SignSuccessfully)
			notation.Exec("verify", artifact.ReferenceWithDigest()).MatchKeyWords(VerifySuccessfully)
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
			OldNotation().Exec("sign", artifact2.ReferenceWithDigest()).MatchKeyWords(SignSuccessfully)
			notation.Exec("verify", artifact2.ReferenceWithDigest()).MatchKeyWords(VerifySuccessfully)

			// test localhost:5000/test-repo3
			OldNotation().Exec("sign", artifact3.ReferenceWithDigest()).MatchKeyWords(SignSuccessfully)
			notation.Exec("verify", artifact3.ReferenceWithDigest()).MatchKeyWords(VerifySuccessfully)
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
			OldNotation().Exec("sign", artifact4.ReferenceWithDigest()).MatchKeyWords(SignSuccessfully)
			notation.Exec("verify", artifact4.ReferenceWithDigest()).MatchKeyWords(VerifySuccessfully)

			// test localhost:5000/test-repo5
			OldNotation().Exec("sign", artifact5.ReferenceWithDigest()).MatchKeyWords(SignSuccessfully)
			notation.Exec("verify", artifact5.ReferenceWithDigest()).MatchKeyWords(VerifySuccessfully)
		})
	})

	It("test invalid registryScope", func() {
		Host(BaseOptions(), func(notation *utils.ExecOpts, artifact *Artifact, vhost *utils.VirtualHost) {
			// update trustpolicy.json
			vhost.SetOption(AddTrustPolicyOption("invalid_registry_scope_trustpolicy.json"))

			// test localhost:5000/test-repo
			OldNotation().Exec("sign", artifact.ReferenceWithDigest()).MatchKeyWords(SignSuccessfully)
			notation.ExpectFailure().Exec("verify", artifact.ReferenceWithDigest()).
				MatchErrContent(fmt.Sprintf("Error: signature verification failed: artifact %q has no applicable trust policy\n", artifact.ReferenceWithDigest()))
		})
	})

	It("test strict signatureVerification level with expired signature", func() {
		Host(BaseOptions(), func(notation *utils.ExecOpts, _ *Artifact, vhost *utils.VirtualHost) {
			artifact := GenerateArtifact("e2e-expired-signature", "")

			notation.ExpectFailure().Exec("verify", artifact.ReferenceWithDigest(), "-v").
				MatchErrKeyWords("expiry validation failed.",
					VerifyFailed)
		})
	})

	It("test strict signatureVerification level with expired authentic timestamp", func() {
		Host(nil, func(notation *utils.ExecOpts, _ *Artifact, vhost *utils.VirtualHost) {
			artifact := GenerateArtifact("e2e-with-expired-cert", "")

			vhost.SetOption(AuthOption("", ""),
				AddTrustPolicyOption("trustpolicy.json"),
				AddTrustStoreOption("e2e", filepath.Join(NotationE2EConfigPath, "localkeys", "expired_e2e.crt")))

			notation.ExpectFailure().Exec("verify", artifact.ReferenceWithDigest(), "-v").
				MatchErrKeyWords("authenticTimestamp validation failed",
					VerifyFailed)
		})
	})

	It("test strict signatureVerification level with invalid authenticity", func() {
		Host(nil, func(notation *utils.ExecOpts, _ *Artifact, vhost *utils.VirtualHost) {
			vhost.SetOption(AuthOption("", ""),
				AddTrustPolicyOption("trustpolicy.json"),
				AddTrustStoreOption("e2e", filepath.Join(NotationE2ELocalKeysDir, "new_e2e.crt")))

			// the artifact signed with a different cert from the cert in
			// trust store.
			artifact := GenerateArtifact("e2e-valid-signature", "")

			notation.ExpectFailure().Exec("verify", artifact.ReferenceWithDigest(), "-v").
				MatchErrKeyWords("authenticity validation failed",
					VerifyFailed)
		})
	})

	It("test strict signatureVerification level with invalid integrity", func() {
		Host(BaseOptions(), func(notation *utils.ExecOpts, _ *Artifact, vhost *utils.VirtualHost) {
			artifact := GenerateArtifact("e2e-invalid-signature", "")

			notation.ExpectFailure().Exec("verify", artifact.ReferenceWithDigest(), "-v").
				MatchErrKeyWords("integrity validation failed",
					VerifyFailed)
		})
	})

	It("test permissive signatureVerification level with expired signature", func() {
		Host(BaseOptions(), func(notation *utils.ExecOpts, _ *Artifact, vhost *utils.VirtualHost) {
			vhost.SetOption(AddTrustPolicyOption("permissive_trustpolicy.json"))

			artifact := GenerateArtifact("e2e-expired-signature", "")

			notation.Exec("verify", artifact.ReferenceWithDigest(), "-v").
				MatchKeyWords("digital signature has expired",
					"expiry was set to \"log\"",
					VerifySuccessfully)
		})
	})

	It("test permissive signatureVerification level with expired authentic timestamp", func() {
		Host(nil, func(notation *utils.ExecOpts, _ *Artifact, vhost *utils.VirtualHost) {
			artifact := GenerateArtifact("e2e-with-expired-cert", "")

			vhost.SetOption(AuthOption("", ""),
				AddTrustPolicyOption("permissive_trustpolicy.json"),
				AddTrustStoreOption("e2e", filepath.Join(NotationE2EConfigPath, "localkeys", "expired_e2e.crt")))

			notation.Exec("verify", artifact.ReferenceWithDigest(), "-v").
				MatchKeyWords("Warning: authenticTimestamp was set to \"log\"",
					"error: certificate \"O=Internet Widgits Pty Ltd,ST=Some-State,C=AU\" is not valid anymore, it was expired",
					VerifySuccessfully)
		})
	})

	It("test permissive signatureVerification level with invalid authenticity", func() {
		Host(nil, func(notation *utils.ExecOpts, _ *Artifact, vhost *utils.VirtualHost) {
			vhost.SetOption(AuthOption("", ""),
				AddTrustPolicyOption("permissive_trustpolicy.json"),
				AddTrustStoreOption("e2e", filepath.Join(NotationE2ELocalKeysDir, "new_e2e.crt")))

			// the artifact signed with a different cert from the cert in
			// trust store.
			artifact := GenerateArtifact("e2e-valid-signature", "")

			notation.ExpectFailure().Exec("verify", artifact.ReferenceWithDigest(), "-v").
				MatchErrKeyWords("authenticity validation failed",
					VerifyFailed)
		})
	})

	It("test permissive signatureVerification level with invalid integrity", func() {
		Host(BaseOptions(), func(notation *utils.ExecOpts, _ *Artifact, vhost *utils.VirtualHost) {
			vhost.SetOption(AddTrustPolicyOption("permissive_trustpolicy.json"))

			artifact := GenerateArtifact("e2e-invalid-signature", "")

			notation.ExpectFailure().Exec("verify", artifact.ReferenceWithDigest(), "-v").
				MatchErrKeyWords("integrity validation failed",
					VerifyFailed)
		})
	})

	It("test audit signatureVerification level with expired signature", func() {
		Host(BaseOptions(), func(notation *utils.ExecOpts, _ *Artifact, vhost *utils.VirtualHost) {
			vhost.SetOption(AddTrustPolicyOption("audit_trustpolicy.json"))

			artifact := GenerateArtifact("e2e-expired-signature", "")

			notation.Exec("verify", artifact.ReferenceWithDigest(), "-v").
				MatchKeyWords("digital signature has expired",
					"expiry was set to \"log\"",
					VerifySuccessfully)
		})
	})

	It("test audit signatureVerification level with expired authentic timestamp", func() {
		Host(nil, func(notation *utils.ExecOpts, _ *Artifact, vhost *utils.VirtualHost) {
			artifact := GenerateArtifact("e2e-with-expired-cert", "")

			vhost.SetOption(AuthOption("", ""),
				AddTrustPolicyOption("audit_trustpolicy.json"),
				AddTrustStoreOption("e2e", filepath.Join(NotationE2EConfigPath, "localkeys", "expired_e2e.crt")))

			notation.Exec("verify", artifact.ReferenceWithDigest(), "-v").
				MatchKeyWords("Warning: authenticTimestamp was set to \"log\"",
					"error: certificate \"O=Internet Widgits Pty Ltd,ST=Some-State,C=AU\" is not valid anymore, it was expired",
					VerifySuccessfully)
		})
	})

	It("test audit signatureVerification level with invalid authenticity", func() {
		Host(nil, func(notation *utils.ExecOpts, _ *Artifact, vhost *utils.VirtualHost) {
			vhost.SetOption(AuthOption("", ""),
				AddTrustPolicyOption("audit_trustpolicy.json"),
				AddTrustStoreOption("e2e", filepath.Join(NotationE2ELocalKeysDir, "new_e2e.crt")))

			// the artifact signed with a different cert from the cert in
			// trust store.
			artifact := GenerateArtifact("e2e-valid-signature", "")

			notation.Exec("verify", artifact.ReferenceWithDigest(), "-v").
				MatchKeyWords("Warning: authenticity was set to \"log\"",
					"signature is not produced by a trusted signer",
					VerifySuccessfully)
		})
	})

	It("test audit signatureVerification level with invalid integrity", func() {
		Host(BaseOptions(), func(notation *utils.ExecOpts, _ *Artifact, vhost *utils.VirtualHost) {
			vhost.SetOption(AddTrustPolicyOption("audit_trustpolicy.json"))

			artifact := GenerateArtifact("e2e-invalid-signature", "")

			notation.ExpectFailure().Exec("verify", artifact.ReferenceWithDigest(), "-v").
				MatchErrKeyWords("integrity validation failed",
					VerifyFailed)
		})
	})

	It("test skip signatureVerification level with invalid integrity", func() {
		Host(BaseOptions(), func(notation *utils.ExecOpts, _ *Artifact, vhost *utils.VirtualHost) {
			vhost.SetOption(AddTrustPolicyOption("skip_trustpolicy.json"))

			artifact := GenerateArtifact("e2e-invalid-signature", "")

			notation.Exec("verify", artifact.ReferenceWithDigest(), "-v").
				MatchKeyWords("Trust policy is configured to skip signature verification")
		})
	})

	It("test override strict signatureVerification level with Expiry set to log", func() {
		Host(BaseOptions(), func(notation *utils.ExecOpts, _ *Artifact, vhost *utils.VirtualHost) {
			vhost.SetOption(AddTrustPolicyOption("override_strict_trustpolicy.json"))

			artifact := GenerateArtifact("e2e-expired-signature", "")

			notation.Exec("verify", artifact.ReferenceWithDigest(), "-v").
				MatchKeyWords("digital signature has expired",
					"expiry was set to \"log\"",
					VerifySuccessfully)
		})
	})

	It("test override strict signatureVerification level with Authentic timestamp set to log", func() {
		Host(nil, func(notation *utils.ExecOpts, _ *Artifact, vhost *utils.VirtualHost) {
			artifact := GenerateArtifact("e2e-with-expired-cert", "")

			vhost.SetOption(AuthOption("", ""),
				AddTrustPolicyOption("override_strict_trustpolicy.json"),
				AddTrustStoreOption("e2e", filepath.Join(NotationE2EConfigPath, "localkeys", "expired_e2e.crt")))

			notation.Exec("verify", artifact.ReferenceWithDigest(), "-v").
				MatchKeyWords("Warning: authenticTimestamp was set to \"log\"",
					"error: certificate \"O=Internet Widgits Pty Ltd,ST=Some-State,C=AU\" is not valid anymore, it was expired",
					VerifySuccessfully)
		})
	})

	It("test override strict signatureVerification level with Authenticity set to log", func() {
		Host(nil, func(notation *utils.ExecOpts, _ *Artifact, vhost *utils.VirtualHost) {
			vhost.SetOption(AuthOption("", ""),
				AddTrustPolicyOption("override_strict_trustpolicy.json"),
				AddTrustStoreOption("e2e", filepath.Join(NotationE2ELocalKeysDir, "new_e2e.crt")))
			// the artifact signed with a different cert from the cert in
			// trust store.
			artifact := GenerateArtifact("e2e-valid-signature", "")

			notation.Exec("verify", artifact.ReferenceWithDigest(), "-v").
				MatchKeyWords("Warning: authenticity was set to \"log\"",
					"signature is not produced by a trusted signer",
					VerifySuccessfully)
		})
	})

	It("test override permissive signatureVerification level with Expiry set to enforced", func() {
		Host(BaseOptions(), func(notation *utils.ExecOpts, _ *Artifact, vhost *utils.VirtualHost) {
			vhost.SetOption(AddTrustPolicyOption("override_permissive_trustpolicy.json"))

			artifact := GenerateArtifact("e2e-expired-signature", "")

			notation.ExpectFailure().Exec("verify", artifact.ReferenceWithDigest(), "-v").
				MatchErrKeyWords("expiry validation failed.",
					VerifyFailed)
		})
	})

	It("test override permissive signatureVerification level with Authentic timestamp set to enforced", func() {
		Host(nil, func(notation *utils.ExecOpts, _ *Artifact, vhost *utils.VirtualHost) {
			vhost.SetOption(AddTrustPolicyOption("override_permissive_trustpolicy.json"))

			artifact := GenerateArtifact("e2e-with-expired-cert", "")

			vhost.SetOption(AuthOption("", ""),
				AddTrustPolicyOption("trustpolicy.json"),
				AddTrustStoreOption("e2e", filepath.Join(NotationE2EConfigPath, "localkeys", "expired_e2e.crt")))

			notation.ExpectFailure().Exec("verify", artifact.ReferenceWithDigest(), "-v").
				MatchErrKeyWords("authenticTimestamp validation failed",
					VerifyFailed)
		})
	})

	It("test override permissive signatureVerification level with Authenticity set to log", func() {
		Host(nil, func(notation *utils.ExecOpts, _ *Artifact, vhost *utils.VirtualHost) {
			vhost.SetOption(AuthOption("", ""),
				AddTrustPolicyOption("override_permissive_trustpolicy.json"),
				AddTrustStoreOption("e2e", filepath.Join(NotationE2ELocalKeysDir, "new_e2e.crt")))

			artifact := GenerateArtifact("e2e-valid-signature", "")

			notation.Exec("verify", artifact.ReferenceWithDigest(), "-v").
				MatchKeyWords("Warning: authenticity was set to \"log\"",
					"signature is not produced by a trusted signer",
					VerifySuccessfully)
		})
	})

	It("test invalid trust store", func() {
		Host(BaseOptions(), func(notation *utils.ExecOpts, _ *Artifact, vhost *utils.VirtualHost) {
			vhost.SetOption(AddTrustPolicyOption("invalid_trust_store_trustpolicy.json"))

			artifact := GenerateArtifact("e2e-valid-signature", "")

			notation.ExpectFailure().Exec("verify", artifact.ReferenceWithDigest(), "-v").
				MatchErrKeyWords("authenticity validation failed",
					"truststore/x509/ca/invalid_store\\\" does not exist",
					VerifyFailed)
		})
	})

	It("test multiple trust stores", func() {
		Host(nil, func(notation *utils.ExecOpts, artifact1 *Artifact, vhost *utils.VirtualHost) {
			// artifact1 signed with new_e2e.crt
			OldNotation(AuthOption("", ""), AddKeyOption("e2e.key", "new_e2e.crt")).
				Exec("sign", artifact1.ReferenceWithDigest(), "-v").
				MatchKeyWords(SignSuccessfully)

			// artifact2 signed with e2e.crt
			artifact2 := GenerateArtifact("e2e-valid-signature", "")

			// setup multiple trust store
			vhost.SetOption(AuthOption("", ""),
				AddTrustPolicyOption("multiple_trust_store_trustpolicy.json"),
				AddTrustStoreOption("e2e-new", filepath.Join(NotationE2ELocalKeysDir, "new_e2e.crt")),
				AddTrustStoreOption("e2e", filepath.Join(NotationE2ELocalKeysDir, "e2e.crt")))

			notation.WithDescription("verify artifact1 with trust store ca/e2e-new").
				Exec("verify", artifact1.ReferenceWithDigest(), "-v").
				MatchKeyWords(VerifySuccessfully)

			notation.WithDescription("verify artifact2 with trust store ca/e2e").
				Exec("verify", artifact2.ReferenceWithDigest(), "-v").
				MatchKeyWords(VerifySuccessfully)
		})
	})

	It("test valid trusted identity", func() {
		Host(BaseOptions(), func(notation *utils.ExecOpts, _ *Artifact, vhost *utils.VirtualHost) {
			vhost.SetOption(AddTrustPolicyOption("valid_trusted_identity_trustpolicy.json"))
			artifact := GenerateArtifact("e2e-valid-signature", "")

			notation.Exec("verify", artifact.ReferenceWithDigest(), "-v").
				MatchKeyWords(VerifySuccessfully)
		})
	})

	It("test invalid trusted identity", func() {
		Host(BaseOptions(), func(notation *utils.ExecOpts, _ *Artifact, vhost *utils.VirtualHost) {
			vhost.SetOption(AddTrustPolicyOption("invalid_trusted_identity_trustpolicy.json"))
			artifact := GenerateArtifact("e2e-valid-signature", "")

			notation.ExpectFailure().Exec("verify", artifact.ReferenceWithDigest(), "-v").
				MatchErrKeyWords("Failure reason: signing certificate from the digital signature does not match the X.509 trusted identities",
					VerifyFailed)
		})
	})

	It("test multiple trusted identity", func() {
		Host(nil, func(notation *utils.ExecOpts, artifact1 *Artifact, vhost *utils.VirtualHost) {
			// artifact1 signed with new_e2e.crt
			OldNotation(AuthOption("", ""), AddKeyOption("e2e.key", "new_e2e.crt")).
				Exec("sign", artifact1.ReferenceWithDigest(), "-v").
				MatchKeyWords(SignSuccessfully)

			// artifact2 signed with e2e.crt
			artifact2 := GenerateArtifact("e2e-valid-signature", "")

			// setup multiple trusted identity
			vhost.SetOption(AuthOption("", ""),
				AddTrustPolicyOption("multiple_trusted_identity_trustpolicy.json"),
				AddTrustStoreOption("e2e", filepath.Join(NotationE2ELocalKeysDir, "new_e2e.crt")),
				AddTrustStoreOption("e2e", filepath.Join(NotationE2ELocalKeysDir, "e2e.crt")),
			)

			notation.Exec("verify", artifact1.ReferenceWithDigest(), "-v").
				MatchKeyWords(VerifySuccessfully)

			notation.Exec("verify", artifact2.ReferenceWithDigest(), "-v").
				MatchKeyWords(VerifySuccessfully)
		})
	})
})
