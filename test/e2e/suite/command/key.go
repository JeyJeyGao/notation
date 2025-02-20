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

package command

import (
	"fmt"

	. "github.com/notaryproject/notation/test/e2e/internal/notation"
	"github.com/notaryproject/notation/test/e2e/internal/utils"

	// . "github.com/notaryproject/notation/test/e2e/suite/common"
	. "github.com/onsi/ginkgo/v2"
)

var _ = Describe("notation key", func() {
	It("list", func() {
		Host(BaseOptions(), func(notation *utils.ExecOpts, artifact *Artifact, vhost *utils.VirtualHost) {
			userConfigDir := vhost.AbsolutePath()
			notation.Exec("key", "list").
				MatchKeyWords(
					"NAME    KEY PATH                                           CERTIFICATE PATH                                   ID   PLUGIN NAME",
					fmt.Sprintf("* e2e   %s/notation/localkeys/e2e.key   %s/notation/localkeys/e2e.crt", userConfigDir, userConfigDir),
				)
		})
	})
})
