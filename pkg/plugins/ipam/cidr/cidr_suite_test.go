package cidr_test

import (
	"os"
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var tempDir = "./temp"

func TestCidr(t *testing.T) {
	BeforeSuite(func() {
		err := os.MkdirAll(tempDir, 0755)
		Expect(err).NotTo(HaveOccurred())
	})
	AfterSuite(func() {
		err := os.RemoveAll(tempDir)
		Expect(err).NotTo(HaveOccurred())
	})
	RegisterFailHandler(Fail)
	RunSpecs(t, "plugins/ipam/cidr")
}
