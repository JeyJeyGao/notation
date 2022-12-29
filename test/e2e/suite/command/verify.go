package command

import (
	"fmt"

	. "github.com/notaryproject/notation/test/e2e/internal/notation"
	"github.com/notaryproject/notation/test/e2e/internal/utils"
	. "github.com/notaryproject/notation/test/e2e/suite/common"
	. "github.com/onsi/ginkgo/v2"
)

var _ = Describe("notation verify", func() {
	It("verify by digest", func() {
		Host(BaseOptions(), func(notation *utils.ExecOpts, artifact *Artifact, vhost *utils.VirtualHost) {
			OldNotation().Exec("sign", artifact.ReferenceWithDigest()).
				MatchKeyWords(SuccessfullySigned)

			notation.Exec("verify", artifact.ReferenceWithDigest()).
				MatchKeyWords(SuccessfullyVerified)
		})
	})

	It("verify by tag", func() {
		Host(BaseOptions(), func(notation *utils.ExecOpts, artifact *Artifact, vhost *utils.VirtualHost) {
			OldNotation().Exec("sign", artifact.ReferenceWithDigest()).
				MatchKeyWords(SuccessfullySigned)

			notation.Exec("verify", artifact.ReferenceWithTag()).
				MatchKeyWords(SuccessfullyVerified)
		})
	})

	It("verify with debug log", func() {
		Host(BaseOptions(), func(notation *utils.ExecOpts, artifact *Artifact, vhost *utils.VirtualHost) {
			OldNotation().Exec("sign", artifact.ReferenceWithDigest()).
				MatchKeyWords(SuccessfullySigned)

			notation.Exec("verify", artifact.ReferenceWithDigest(), "-d").
				// debug log message outputs to stderr
				MatchErrKeyWords(
					"Check verification level",
					fmt.Sprintf("Verify signature against artifact %s", artifact.Digest),
					"Validating cert chain",
					"Validating trust identity",
					"Validating expiry",
					"Validating authentic timestamp",
					"Validating revocation",
				).
				MatchKeyWords(SuccessfullyVerified)
		})
	})
})
