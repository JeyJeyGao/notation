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

package blob

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/notaryproject/notation-go"
	"github.com/notaryproject/notation/v2/cmd/notation/internal/display"
	"github.com/notaryproject/notation/v2/cmd/notation/internal/display/output"
	"github.com/notaryproject/notation/v2/cmd/notation/internal/flag"
	"github.com/notaryproject/notation/v2/cmd/notation/internal/verify"
	"github.com/spf13/cobra"
)

type blobQuickVerifyOpts struct {
	flag.LoggingFlagOpts
	printer           *output.Printer
	blobPath          string
	signaturePath     string
	pluginConfig      []string
	userMetadata      []string
	blobMediaType     string
	certificate       string
	certificateURL    string
	certificateSHA256 string
	trustedIdentity   string
}

func quickVerifyCommand(opts *blobQuickVerifyOpts) *cobra.Command {
	if opts == nil {
		opts = &blobQuickVerifyOpts{}
	}
	longMessage := `Quick verify a signature associated with a blob using a provided certificate.

Example - Quick verify a signature on a blob artifact with a local certificate:
  notation blob quick-verify --certificate <certificate_path> --trusted-identity <trusted_identity> --signature <signature_path> <blob_path>

Example - Quick verify a signature on a blob artifact with a certificate from URL:
  notation blob quick-verify --certificate-url <certificate_url> --trusted-identity <trusted_identity> --signature <signature_path> <blob_path>

Example - Quick verify a signature on a blob artifact with user metadata:
  notation blob quick-verify --certificate <certificate_path> --trusted-identity <trusted_identity> --user-metadata <metadata> --signature <signature_path> <blob_path>

Example - Quick verify a signature on a blob artifact with media type:
  notation blob quick-verify --certificate <certificate_path> --trusted-identity <trusted_identity> --media-type <media_type> --signature <signature_path> <blob_path>
`
	command := &cobra.Command{
		Use:   "quick-verify [flags] --signature <signature_path> <blob_path>",
		Short: "Quick verify a signature associated with a blob using a provided certificate",
		Long:  longMessage,
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return errors.New("missing path to the blob artifact: use `notation blob quick-verify --help` to see what parameters are required")
			}
			opts.blobPath = args[0]
			return nil
		},
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if opts.signaturePath == "" {
				return errors.New("filepath of the signature cannot be empty")
			}
			if opts.certificate == "" && opts.certificateURL == "" {
				return errors.New("either --certificate or --certificate-url is required")
			}
			if opts.certificate != "" && opts.certificateURL != "" {
				return errors.New("cannot use both --certificate and --certificate-url")
			}
			if opts.certificateSHA256 != "" && opts.certificate != "" {
				return errors.New("--certificate-sha256-fingerprint can only be used with --certificate-url")
			}
			if opts.certificateURL != "" && opts.certificateSHA256 == "" {
				cmd.PrintErrf("Warning: Downloading certificate without verifying fingerprint. Consider using --certificate-sha256-fingerprint for security.\n")
			}
			if opts.trustedIdentity == "" {
				return errors.New("--trusted-identity is required")
			}
			if cmd.Flags().Changed("media-type") && opts.blobMediaType == "" {
				return errors.New("--media-type is set but with empty value")
			}
			opts.printer = output.NewPrinter(cmd.OutOrStdout(), cmd.OutOrStderr())
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			return runQuickVerify(cmd, opts)
		},
	}
	opts.LoggingFlagOpts.ApplyFlags(command.Flags())
	command.Flags().StringVarP(&opts.signaturePath, "signature", "s", "", "filepath of the signature to be verified")
	command.Flags().StringVar(&opts.certificate, "certificate", "", "filepath of the certificate to verify the signature")
	command.Flags().StringVar(&opts.certificateURL, "certificate-url", "", "URL to download the certificate to verify the signature")
	command.Flags().StringVar(&opts.certificateSHA256, "certificate-sha256-fingerprint", "", "SHA-256 fingerprint of the certificate to verify when downloading from URL")
	command.Flags().StringVar(&opts.trustedIdentity, "trusted-identity", "", "trusted identity for signature verification (e.g. x509.subject=CN=example)")
	command.Flags().StringArrayVar(&opts.pluginConfig, "plugin-config", nil, "{key}={value} pairs that are passed as it is to a plugin, if the verification is associated with a verification plugin, refer plugin documentation to set appropriate values")
	command.Flags().StringVar(&opts.blobMediaType, "media-type", "", "media type of the blob to verify")
	flag.SetPflagUserMetadata(command.Flags(), &opts.userMetadata, flag.PflagUserMetadataVerifyUsage)
	command.MarkFlagRequired("signature")
	command.MarkFlagsOneRequired("certificate", "certificate-url")
	command.MarkFlagRequired("trusted-identity")
	return command
}

func runQuickVerify(command *cobra.Command, cmdOpts *blobQuickVerifyOpts) error {
	// set log level
	ctx := cmdOpts.LoggingFlagOpts.InitializeLogger(command.Context())

	// initialize
	displayHandler := display.NewBlobVerifyHandler(cmdOpts.printer)
	blobFile, err := os.Open(cmdOpts.blobPath)
	if err != nil {
		return err
	}
	defer blobFile.Close()

	signatureBytes, err := os.ReadFile(cmdOpts.signaturePath)
	if err != nil {
		return err
	}

	// Load certificate
	var cert *x509.Certificate
	if cmdOpts.certificate != "" {
		// If certificate is from local file, validate permission
		fileInfo, err := os.Stat(cmdOpts.certificate)
		if err != nil {
			return fmt.Errorf("failed to access certificate file: %w", err)
		}

		// Check file permission (0600)
		if fileInfo.Mode().Perm()&0177 != 0 {
			return fmt.Errorf("certificate file %s has invalid permissions. Expected 0600, got %o", cmdOpts.certificate, fileInfo.Mode().Perm())
		}

		// Read certificate from file
		certBytes, err := os.ReadFile(cmdOpts.certificate)
		if err != nil {
			return fmt.Errorf("failed to read certificate file: %w", err)
		}

		cert, err = parseCertificate(certBytes)
		if err != nil {
			return fmt.Errorf("failed to parse certificate: %w", err)
		}
	} else {
		// Download certificate from URL
		resp, err := http.Get(cmdOpts.certificateURL)
		if err != nil {
			return fmt.Errorf("failed to download certificate from URL: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("failed to download certificate, HTTP status: %d", resp.StatusCode)
		}

		certBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("failed to read certificate data: %w", err)
		}

		cert, err = parseCertificate(certBytes)
		if err != nil {
			return fmt.Errorf("failed to parse certificate: %w", err)
		}

		if cmdOpts.certificateSHA256 == "" {
			return fmt.Errorf("certificate fingerprint verification is required when downloading from URL")
		}

		// Calculate SHA-256 fingerprint of the downloaded certificate
		fingerprint := sha256.Sum256(cert.Raw)
		calculatedFingerprint := hex.EncodeToString(fingerprint[:])

		// Clean up user-provided fingerprint (remove colons, spaces, and convert to lowercase)
		expectedFingerprint := strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(cmdOpts.certificateSHA256, ":", ""), " ", ""))

		// Compare fingerprints
		if calculatedFingerprint != expectedFingerprint {
			return fmt.Errorf("certificate fingerprint verification failed: expected %s, got %s",
				expectedFingerprint, calculatedFingerprint)
		}
	}

	// set up trusted identity
	trustedIdentities := []string{cmdOpts.trustedIdentity}

	// Get the quick verifier
	blobVerifier, err := verify.GetBlobQuickVerifier(ctx, cert, trustedIdentities)
	if err != nil {
		return err
	}

	// set up verification plugin config
	pluginConfigs, err := flag.ParseFlagMap(cmdOpts.pluginConfig, flag.PflagPluginConfig.Name)
	if err != nil {
		return err
	}

	// set up user metadata
	userMetadata, err := flag.ParseFlagMap(cmdOpts.userMetadata, flag.PflagUserMetadata.Name)
	if err != nil {
		return err
	}

	signatureMediaType, err := parseSignatureMediaType(cmdOpts.signaturePath)
	if err != nil {
		return err
	}

	verifyBlobOpts := notation.VerifyBlobOptions{
		BlobVerifierVerifyOptions: notation.BlobVerifierVerifyOptions{
			SignatureMediaType: signatureMediaType,
			PluginConfig:       pluginConfigs,
			UserMetadata:       userMetadata,
		},
		ContentMediaType: cmdOpts.blobMediaType,
	}

	_, outcome, err := notation.VerifyBlob(ctx, blobVerifier, blobFile, signatureBytes, verifyBlobOpts)
	outcomes := []*notation.VerificationOutcome{outcome}
	err = verify.ComposeBlobVerificationFailurePrintout(outcomes, cmdOpts.blobPath, err)
	if err != nil {
		return err
	}

	displayHandler.OnVerifySucceeded(outcomes, cmdOpts.blobPath)
	return displayHandler.Render()
}

// parseCertificate parses a PEM-encoded certificate.
func parseCertificate(certBytes []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(certBytes)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("failed to decode PEM block containing certificate")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}

	return cert, nil
}
