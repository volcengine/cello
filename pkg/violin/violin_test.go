// Copyright 2023 The Cello Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package violin_test

import (
	"context"
	"fmt"
	"net"
	"os"
	"path"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/volcengine/cello/pkg/pbrpc"
	"github.com/volcengine/cello/pkg/violin"
)

// createCelloClient creates a client with default parameters connecting to UNIX domain socket
// and waits for agent became available.
func createCelloClient(ctx context.Context, apiAddress string) (pbrpc.CelloClient, *grpc.ClientConn, error) {
	grpcConn, err := grpc.DialContext(ctx, apiAddress, grpc.WithBlock(),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(
			func(ctx context.Context, s string) (net.Conn, error) {
				unixAddr, err := net.ResolveUnixAddr("unix", apiAddress)
				if err != nil {
					return nil, fmt.Errorf("error while resolve unix addr:%w", err)
				}
				d := net.Dialer{}
				return d.DialContext(ctx, "unix", unixAddr.String())
			}))
	if err != nil {
		return nil, nil, fmt.Errorf("error dial cello grpc server: %w", err)
	}

	celloClient := pbrpc.NewCelloClient(grpcConn)
	return celloClient, grpcConn, nil
}

var _ = Describe("Test for cello-lite daemon ", func() {
	var (
		daemon      violin.Daemon
		nodeName    string
		namespace   string
		podname     string
		apiEndpoint string
		k8sClient   kubernetes.Interface
		celloClient pbrpc.CelloClient
		timeout     time.Duration
		tempdir     string
	)

	BeforeSuite(func() {
		nodeName = "test"
		namespace = "test"
		podname = "test-pod"
		timeout = 3 * time.Second
		temp, err := os.MkdirTemp("/tmp", "cello-test")
		Expect(err).NotTo(HaveOccurred())
		tempdir = temp
		apiEndpoint = path.Join(temp, "cni.sock")

		k8sClient = fake.NewSimpleClientset()
		_, err = k8sClient.CoreV1().Nodes().Create(context.Background(), &corev1.Node{
			TypeMeta: metav1.TypeMeta{},
			ObjectMeta: metav1.ObjectMeta{
				Name: nodeName,
			},
			Spec: corev1.NodeSpec{},
			Status: corev1.NodeStatus{
				Addresses: []corev1.NodeAddress{
					{
						Type:    corev1.NodeExternalIP,
						Address: "172.16.0.3",
					},
					{
						Type:    corev1.NodeHostName,
						Address: "172.16.0.3",
					},
				},
			},
		}, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		_, err = k8sClient.CoreV1().Pods(namespace).Create(context.Background(), &corev1.Pod{
			TypeMeta: metav1.TypeMeta{},
			ObjectMeta: metav1.ObjectMeta{
				Name:              podname,
				Namespace:         namespace,
				CreationTimestamp: metav1.Time{},
				Labels:            map[string]string{"app": "test"},
				Annotations:       nil,
			},
			Spec:   corev1.PodSpec{},
			Status: corev1.PodStatus{},
		}, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

	})
	AfterSuite(func() {
		Expect(os.RemoveAll(tempdir)).NotTo(HaveOccurred())
	})

	Describe("test RPC calls", func() {
		BeforeEach(func() {
			var err error
			defer GinkgoRecover()
			daemon, err = violin.NewDaemonWithOptions(context.Background(), nodeName,
				violin.WithAgentAPIAddress(apiEndpoint),
				violin.WithKubeClient(k8sClient))
			Expect(err).NotTo(HaveOccurred())
			Expect(daemon).NotTo(BeNil())
			daemonHasStarted := make(chan struct{})
			go func() {
				err = daemon.Start(daemonHasStarted)
			}()
			<-daemonHasStarted
			Expect(err).NotTo(HaveOccurred())

			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()
			celloClient, _, err = createCelloClient(ctx, apiEndpoint)
			Expect(err).NotTo(HaveOccurred())
		})
		AfterEach(func() {
			Expect(daemon).NotTo(BeNil())
			daemon.Stop()
			_, err := os.ReadFile(apiEndpoint)
			Expect(os.IsNotExist(err)).To(BeTrue())
		})

		It("should successfully connect grpc endpoint", func() {
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()
			conn, err := grpc.DialContext(ctx, apiEndpoint, grpc.WithBlock(),
				grpc.WithTransportCredentials(insecure.NewCredentials()),
				grpc.WithContextDialer(
					func(ctx context.Context, s string) (net.Conn, error) {
						unixAddr, err := net.ResolveUnixAddr("unix", apiEndpoint)
						if err != nil {
							return nil, fmt.Errorf("error while resolve unix addr:%w", err)
						}
						d := net.Dialer{}
						return d.DialContext(ctx, "unix", unixAddr.String())
					}))
			Expect(err).NotTo(HaveOccurred())
			Expect(conn).NotTo(BeNil())
			err = conn.Close()
			Expect(err).NotTo(HaveOccurred())
		})

		It("should successfully get meta info for pod", func() {
			info, err := celloClient.GetPodMetaInfo(context.TODO(), &pbrpc.GetPodMetaRequest{
				Name:      podname,
				Namespace: namespace,
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(info).NotTo(BeNil())
		})

		It("should successfully patch pod annotation", func() {
			_, err := celloClient.PatchPodAnnotation(context.TODO(), &pbrpc.PatchPodAnnotationRequest{
				Name:        podname,
				Namespace:   namespace,
				Annotations: map[string]string{"ping": "pong"},
			})
			Expect(err).NotTo(HaveOccurred())
		})

	})
})
