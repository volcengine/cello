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

package credential

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/volcengine/volcengine-go-sdk/volcengine/credentials"

	"github.com/volcengine/cello/pkg/provider/volcengine/metadata"
)

// InstanceProviderName provides a name of MetadataRole provider
const InstanceProviderName = "InstanceRoleProvider"

type InstanceRoleProvider struct {
	credentials.Expiry
	RoleName     string
	Client       metadata.ClientWrapper
	ExpiryWindow time.Duration
	timeOut      time.Duration
}

// InstanceCredential for access volcengine service.
type InstanceCredential struct {
	ExpiredTime     time.Time `json:"ExpiredTime"`
	CurrentTime     time.Time `json:"CurrentTime"`
	AccessKeyId     string    `json:"AccessKeyId,omitempty"`
	SecretAccessKey string    `json:"SecretAccessKey,omitempty"`
	SessionToken    string    `json:"SessionToken,omitempty"`
}

func NewInstanceRoleCredentials(client metadata.ClientWrapper, roleName string, options ...func(*InstanceRoleProvider)) *credentials.Credentials {
	return credentials.NewCredentials(NewInstanceRoleProvider(client, roleName, options...))
}

func NewInstanceRoleProvider(client metadata.ClientWrapper, roleName string, options ...func(*InstanceRoleProvider)) *InstanceRoleProvider {
	p := &InstanceRoleProvider{
		Client:   client,
		RoleName: roleName,
		timeOut:  time.Second * 10,
	}
	for _, option := range options {
		option(p)
	}
	return p
}

func (m *InstanceRoleProvider) Retrieve() (credentials.Value, error) {
	ctx, cancel := context.WithTimeout(context.Background(), m.timeOut)
	defer cancel()
	return m.RetrieveWithContext(ctx)
}

func (m *InstanceRoleProvider) RetrieveWithContext(ctx context.Context) (credentials.Value, error) {

	roleCreds, err := requestCred(ctx, m.Client, m.RoleName)
	if err != nil {
		return credentials.Value{ProviderName: InstanceProviderName}, err
	}

	m.SetExpiration(roleCreds.ExpiredTime, m.ExpiryWindow)

	return credentials.Value{
		AccessKeyID:     roleCreds.AccessKeyId,
		SecretAccessKey: roleCreds.SecretAccessKey,
		SessionToken:    roleCreds.SessionToken,
		ProviderName:    InstanceProviderName,
	}, nil
}

func requestCred(ctx context.Context, client metadata.ClientWrapper, roleName string) (*InstanceCredential, error) {
	resp, err := client.STSCredential(ctx, roleName)
	if err != nil {
		return nil, fmt.Errorf("failed to get credential from instance metadata, err: %v", err)
	}

	respCreds := InstanceCredential{}
	if err = json.NewDecoder(strings.NewReader(resp)).Decode(&respCreds); err != nil {
		return nil, fmt.Errorf("failed to decode %s instance role credentials, err: %v", roleName, err)
	}

	return &respCreds, nil
}
