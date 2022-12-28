package command

import (
	"fmt"
	"time"

	. "github.com/notaryproject/notation/test/e2e/internal/notation"
	"github.com/notaryproject/notation/test/e2e/internal/utils"
	. "github.com/onsi/ginkgo/v2"
)

const signMessage = "Successfully signed"

var _ = Describe("notation sign", func() {
	It("sign digest", func() {
		Host(BaseOptions(), func(notation *utils.ExecOpts, artifact *Artifact, vhost *utils.VirtualHost) {
			notation.Exec("sign", artifact.ReferenceWithDigest()).
				MatchKeyWords(signMessage)

			OldNotation().WithDescription("verify by digest").
				Exec("verify", artifact.ReferenceWithDigest()).
				MatchKeyWords(verifyMessage)

			OldNotation().WithDescription("verify by tag").
				Exec("verify", artifact.ReferenceWithTag()).
				MatchKeyWords(verifyMessage)
		})
	})

	It("sign digest in COSE format", func() {
		Host(BaseOptions(), func(notation *utils.ExecOpts, artifact *Artifact, vhost *utils.VirtualHost) {
			notation.Exec("sign", "--signature-format", "cose", artifact.ReferenceWithDigest()).
				MatchKeyWords(signMessage)

			OldNotation().WithDescription("verify by digest").
				Exec("verify", artifact.ReferenceWithTag()).
				MatchKeyWords(verifyMessage)

			OldNotation().WithDescription("verify by tag").
				Exec("verify", artifact.ReferenceWithTag()).
				MatchKeyWords(verifyMessage)
		})
	})

	It("sign by tag in JWS signature format", func() {
		Host(BaseOptions(), func(notation *utils.ExecOpts, artifact *Artifact, vhost *utils.VirtualHost) {
			notation.WithDescription("sign with JWS").
				Exec("sign", artifact.ReferenceWithTag(), "--signature-format", "jws").
				MatchKeyWords(signMessage)

			OldNotation().WithDescription("verify JWS signature").
				Exec("verify", artifact.ReferenceWithTag()).
				MatchKeyWords(verifyMessage)
		})
	})

	It("sign by tag in COSE signature format", func() {
		Host(BaseOptions(), func(notation *utils.ExecOpts, artifact *Artifact, vhost *utils.VirtualHost) {
			notation.WithDescription("sign with COSE").
				Exec("sign", artifact.ReferenceWithTag(), "--signature-format", "cose").
				MatchKeyWords(signMessage)

			OldNotation().WithDescription("verify COSE signature").
				Exec("verify", artifact.ReferenceWithTag()).
				MatchKeyWords(verifyMessage)
		})
	})

	It("sign by specific key", func() {
		Host(BaseOptions(), func(notation *utils.ExecOpts, artifact *Artifact, vhost *utils.VirtualHost) {
			const keyName = "sKey"
			notation.Exec("cert", "generate-test", keyName).
				MatchKeyWords(fmt.Sprintf("notation/localkeys/%s.crt", keyName))

			notation.Exec("sign", "--key", keyName, artifact.ReferenceWithDigest()).
				MatchKeyWords(signMessage)

			// copy the generated cert file and create the new trust policy for verify signature with generated new key.
			OldNotation(AuthOption("", ""),
				AddTestTrustStoreOption(keyName, vhost.UserPath(NotationDirName, LocalkeysDirName, keyName+".crt")),
				AddTrustPolicyOption("generate_test_trustpolicy.json"),
			).Exec("verify", artifact.ReferenceWithTag()).
				MatchKeyWords(verifyMessage)
		})
	})

	It("sign with expiry in 24h", func() {
		Host(BaseOptions(), func(notation *utils.ExecOpts, artifact *Artifact, vhost *utils.VirtualHost) {
			notation.Exec("sign", "--expiry", "24h", artifact.ReferenceWithDigest()).
				MatchKeyWords(signMessage)

			OldNotation().Exec("verify", artifact.ReferenceWithTag()).
				MatchKeyWords(verifyMessage)
		})
	})

	It("sign with expiry in 2s", func() {
		Host(BaseOptions(), func(notation *utils.ExecOpts, artifact *Artifact, vhost *utils.VirtualHost) {
			notation.Exec("sign", "--expiry", "2s", artifact.ReferenceWithDigest()).
				MatchKeyWords(signMessage)

			// sleep to wait for expiry
			time.Sleep(2100 * time.Millisecond)

			OldNotation().ExpectFailure().Exec("verify", artifact.ReferenceWithDigest(), "-v").
				MatchErrKeyWords("expiry validation failed.").
				MatchErrKeyWords("signature verification failed for all the signatures")
		})
	})
})
