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

package cert

import (
	"reflect"
	"testing"

	"github.com/notaryproject/notation/cmd/notation/internal/option"
)

func TestCertListCommand(t *testing.T) {
	opts := &certListOpts{}
	cmd := certListCommand(opts)
	expected := &certListOpts{
		TrustStore: option.TrustStore{
			StoreType:  "ca",
			NamedStore: "test",
		},
	}
	if err := cmd.ParseFlags([]string{
		"-t", "ca",
		"-s", "test"}); err != nil {
		t.Fatalf("Parse Flag failed: %v", err)
	}
	if !reflect.DeepEqual(*expected, *opts) {
		t.Fatalf("Expect cert list opts: %v, got: %v", expected, opts)
	}
}
