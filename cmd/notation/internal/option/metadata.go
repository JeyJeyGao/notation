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

package option

import (
	"github.com/notaryproject/notation/internal/cmd"
	"github.com/spf13/pflag"
)

const userMetadataFlag = "user-metadata"

// UserMetadata contains metadata-related flag values
type UserMetadata []string

// ApplyFlags set flags and their default values for the FlagSet.
func (m *UserMetadata) ApplyFlags(fs *pflag.FlagSet) {
	usage := "{key}={value} pairs that are added to the signature payload"
	fs.StringArrayVarP((*[]string)(m), userMetadataFlag, "m", nil, usage)
}

// UserMetadataMap parses user-metadata flag into a map.
func (m *UserMetadata) UserMetadataMap() (map[string]string, error) {
	return cmd.ParseFlagMap(*m, userMetadataFlag)
}

// VerificationUserMetadata contains metadata-related flag values for
// verification.
type VerificationUserMetadata struct {
	UserMetadata
}

// ApplyFlags set flags and their default values for the FlagSet.
func (m *VerificationUserMetadata) ApplyFlags(fs *pflag.FlagSet) {
	usage := "user defined {key}={value} pairs that must be present in the signature for successful verification if provided"
	fs.StringArrayVarP((*[]string)(&m.UserMetadata), userMetadataFlag, "m", nil, usage)
}
