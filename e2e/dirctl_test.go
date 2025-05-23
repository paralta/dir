// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package e2e

import (
	"bytes"
	_ "embed"
	"os"
	"path/filepath"
	"strings"

	clicmd "github.com/agntcy/dir/cli/cmd"
	initcmd "github.com/agntcy/dir/cli/cmd/network/init"
	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
	"github.com/opencontainers/go-digest"
)

//go:embed testdata/agent.json
var expectedAgentJSON []byte

var _ = ginkgo.Describe("dirctl end-to-end tests", func() {
	// Test params
	var tempAgentDigest string

	tempAgentDir := os.Getenv("E2E_COMPILE_OUTPUT_DIR")
	if tempAgentDir == "" {
		tempAgentDir = os.TempDir()
	}
	tempAgentPath := filepath.Join(tempAgentDir, "agent.json")

	ginkgo.Context("agent build", func() {
		ginkgo.It("should build an agent", func() {
			var outputBuffer bytes.Buffer

			compileCmd := clicmd.RootCmd
			compileCmd.SetOut(&outputBuffer)
			compileCmd.SetArgs([]string{
				"build",
				"testdata",
			})

			err := compileCmd.Execute()
			gomega.Expect(err).NotTo(gomega.HaveOccurred())

			err = os.MkdirAll(filepath.Dir(tempAgentPath), 0o755)
			gomega.Expect(err).NotTo(gomega.HaveOccurred())

			err = os.WriteFile(tempAgentPath, outputBuffer.Bytes(), 0o600)
			gomega.Expect(err).NotTo(gomega.HaveOccurred())

			// Compare the output with the expected JSON
			equal, err := compareJSONAgents(outputBuffer.Bytes(), expectedAgentJSON)
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			gomega.Expect(equal).To(gomega.BeTrue())
		})
	})

	ginkgo.Context("agent push and pull", func() {
		ginkgo.It("should push an agent", func() {
			var outputBuffer bytes.Buffer

			pushCmd := clicmd.RootCmd
			pushCmd.SetOut(&outputBuffer)
			pushCmd.SetArgs([]string{
				"push",
				tempAgentPath,
			})

			err := pushCmd.Execute()
			gomega.Expect(err).NotTo(gomega.HaveOccurred())

			tempAgentDigest = outputBuffer.String()

			// Ensure the digest is valid
			_, err = digest.Parse(tempAgentDigest)
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
		})

		ginkgo.It("should pull an existing agent", func() {
			var outputBuffer bytes.Buffer

			pullCmd := clicmd.RootCmd
			pullCmd.SetOut(&outputBuffer)
			pullCmd.SetArgs([]string{
				"pull",
				tempAgentDigest,
			})

			err := pullCmd.Execute()
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
		})

		ginkgo.It("should push the same agent again and return the same digest", func() {
			var outputBuffer bytes.Buffer

			pushCmd := clicmd.RootCmd
			pushCmd.SetOut(&outputBuffer)
			pushCmd.SetArgs([]string{
				"push",
				tempAgentPath,
			})

			err := pushCmd.Execute()
			gomega.Expect(err).NotTo(gomega.HaveOccurred())

			// Ensure the digests are the same
			newAgentDigest := outputBuffer.String()
			gomega.Expect(newAgentDigest).To(gomega.Equal(tempAgentDigest))
		})

		ginkgo.It("should push two different agents and return different digests", func() {
			var outputBuffer bytes.Buffer

			// Modify the agent file to create a different agent
			tempAgentPath2 := filepath.Join(tempAgentDir, "agent2.json")
			err := os.WriteFile(tempAgentPath2, []byte(`{"name": "different-agent"}`), 0o600)
			gomega.Expect(err).NotTo(gomega.HaveOccurred())

			// Push second agent
			pushCmd2 := clicmd.RootCmd
			pushCmd2.SetOut(&outputBuffer)
			pushCmd2.SetArgs([]string{
				"push",
				tempAgentPath2,
			})

			err = pushCmd2.Execute()
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			newAgentDigest := outputBuffer.String()

			// Ensure the digests are different
			gomega.Expect(newAgentDigest).NotTo(gomega.Equal(tempAgentDigest))
		})

		ginkgo.It("should pull a non-existent agent and return an error", func() {
			var outputBuffer bytes.Buffer

			pullCmd := clicmd.RootCmd
			pullCmd.SetOut(&outputBuffer)
			pullCmd.SetArgs([]string{
				"pull",
				"non-existent-digest",
			})

			err := pullCmd.Execute()
			gomega.Expect(err).To(gomega.HaveOccurred())
		})
	})

	ginkgo.Context("agent delete", func() {
		ginkgo.It("should delete an agent", func() {
			var outputBuffer bytes.Buffer

			deleteCmd := clicmd.RootCmd
			deleteCmd.SetOut(&outputBuffer)
			deleteCmd.SetArgs([]string{
				"delete",
				tempAgentDigest,
			})

			err := deleteCmd.Execute()
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
		})

		ginkgo.It("should fail to pull a deleted agent", func() {
			var outputBuffer bytes.Buffer

			pullCmd := clicmd.RootCmd
			pullCmd.SetOut(&outputBuffer)
			pullCmd.SetArgs([]string{
				"pull",
				tempAgentDigest,
			})

			err := pullCmd.Execute()
			gomega.Expect(err).To(gomega.HaveOccurred())
		})
	})

	ginkgo.Context("network commands", func() {
		var (
			tempDir     string
			tempKeyPath string
		)

		ginkgo.BeforeEach(func() {
			// Create temporary directory for test keys
			var err error
			tempDir, err = os.MkdirTemp("", "network-test")
			gomega.Expect(err).NotTo(gomega.HaveOccurred())

			// Generate OpenSSL-style ED25519 key
			_, privateKey, err := initcmd.GenerateED25519OpenSSLKey()
			gomega.Expect(err).NotTo(gomega.HaveOccurred())

			// Write the private key to a temporary file
			tempKeyPath = filepath.Join(tempDir, "test_key")
			err = os.WriteFile(tempKeyPath, privateKey, 0o0600)
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
		})

		ginkgo.AfterEach(func() {
			// Cleanup temporary directory
			err := os.RemoveAll(tempDir)
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
		})

		ginkgo.Context("info command", func() {
			ginkgo.It("should generate a peer ID from a valid ED25519 key", func() {
				var outputBuffer bytes.Buffer

				infoCmd := clicmd.RootCmd
				infoCmd.SetOut(&outputBuffer)
				infoCmd.SetArgs([]string{
					"network",
					"info",
					tempKeyPath,
				})

				err := infoCmd.Execute()
				gomega.Expect(err).NotTo(gomega.HaveOccurred())

				// Verify that the output is not empty
				output := strings.TrimSpace(outputBuffer.String())
				gomega.Expect(output).NotTo(gomega.BeEmpty())
			})

			ginkgo.It("should fail with non-existent key file", func() {
				var outputBuffer bytes.Buffer

				infoCmd := clicmd.RootCmd
				infoCmd.SetOut(&outputBuffer)
				infoCmd.SetArgs([]string{
					"network",
					"info",
					"non-existent-key-file",
				})

				err := infoCmd.Execute()
				gomega.Expect(err).To(gomega.HaveOccurred())
			})

			ginkgo.It("should fail with empty key path", func() {
				var outputBuffer bytes.Buffer

				infoCmd := clicmd.RootCmd
				infoCmd.SetOut(&outputBuffer)
				infoCmd.SetArgs([]string{
					"network",
					"info",
					"",
				})

				err := infoCmd.Execute()
				gomega.Expect(err).To(gomega.HaveOccurred())
			})
		})

		ginkgo.Context("init command", func() {
			ginkgo.It("should generate a new peer ID and save the key to specified output", func() {
				outputPath := filepath.Join(tempDir, "generated.key")
				var outputBuffer bytes.Buffer

				initCmd := clicmd.RootCmd
				initCmd.SetOut(&outputBuffer)
				initCmd.SetArgs([]string{
					"network",
					"init",
					"--output",
					outputPath,
				})

				err := initCmd.Execute()
				gomega.Expect(err).NotTo(gomega.HaveOccurred())

				// Verify that the output file exists
				_, err = os.Stat(outputPath)
				gomega.Expect(err).NotTo(gomega.HaveOccurred())

				// Verify file permissions
				info, err := os.Stat(outputPath)
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				gomega.Expect(info.Mode().Perm()).To(gomega.Equal(os.FileMode(0o0600)))

				// Verify that the output is not empty and is a valid peer ID
				output := strings.TrimSpace(outputBuffer.String())
				gomega.Expect(output).NotTo(gomega.BeEmpty())
				gomega.Expect(output).To(gomega.HavePrefix("12D3"))

				// Verify that the generated key can be used with the info command
				var infoBuffer bytes.Buffer
				infoCmd := clicmd.RootCmd
				infoCmd.SetOut(&infoBuffer)
				infoCmd.SetArgs([]string{
					"network",
					"info",
					outputPath,
				})

				err = infoCmd.Execute()
				gomega.Expect(err).NotTo(gomega.HaveOccurred())

				// Verify that info command returns the same peer ID
				infoOutput := strings.TrimSpace(infoBuffer.String())
				gomega.Expect(infoOutput).To(gomega.Equal(output))
			})

			ginkgo.It("should fail when output directory doesn't exist and cannot be created", func() {
				// Try to write to a location that should fail
				var outputBuffer bytes.Buffer

				initCmd := clicmd.RootCmd
				initCmd.SetOut(&outputBuffer)
				initCmd.SetArgs([]string{
					"network",
					"init",
					"--output",
					"/nonexistent/directory/key.pem",
				})

				err := initCmd.Execute()
				gomega.Expect(err).To(gomega.HaveOccurred())
			})
		})
	})
})
