// Copyright 2023 The Cello Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package client

import (
	"context"
	"fmt"
	"net"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/volcengine/cello/pkg/cni/log"
	"github.com/volcengine/cello/pkg/daemon"
	"github.com/volcengine/cello/pkg/pbrpc"
)

// NewCelloClient creates a client with default parameters connecting to UNIX domain socket and waits for cello-agent availability.
func NewCelloClient(ctx context.Context) (pbrpc.CelloClient, *grpc.ClientConn, error) {
	grpcConn, err := grpc.DialContext(ctx, daemon.DefaultSocketPath, grpc.WithBlock(),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(
			func(ctx context.Context, s string) (net.Conn, error) {
				unixAddr, err := net.ResolveUnixAddr("unix", daemon.DefaultSocketPath)
				if err != nil {
					return nil, fmt.Errorf("error while resolve unix addr:%w", err)
				}
				d := net.Dialer{}
				return d.DialContext(ctx, "unix", unixAddr.String())
			}))
	if err != nil {
		log.Log.Errorf("dial to grpc server failed: %v", err)
		return nil, nil, fmt.Errorf("error dial cello grpc server: %w", err)
	}

	celloClient := pbrpc.NewCelloClient(grpcConn)
	return celloClient, grpcConn, nil
}
