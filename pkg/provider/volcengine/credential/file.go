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
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/volcengine/volcengine-go-sdk/volcengine/credentials"
)

// SecretFileProviderName provides a name of MetadataRole provider
const SecretFileProviderName = "SecretFileProvider"

type SecretFileProvider struct {
	credentials.Expiry
	ExpiryWindow time.Duration
	Path         string
}

type SecretFileCredential struct {
	AccessKeyID     string    `json:"access_key"`
	AccessSecretKey string    `json:"secret_key"`
	Token           string    `json:"token"`
	Expiration      time.Time `json:"expiration"`
}

func NewSecretFileCredentials(path string) *credentials.Credentials {
	return credentials.NewCredentials(&SecretFileProvider{
		Path: path,
	})
}

func NewSecretFileProvider(path string, options ...func(*SecretFileProvider)) *SecretFileProvider {
	p := &SecretFileProvider{
		Path: path,
	}
	for _, option := range options {
		option(p)
	}
	return p
}

func (p *SecretFileProvider) Retrieve() (credentials.Value, error) {
	data, err := os.ReadFile(p.Path)
	if err != nil {
		return credentials.Value{ProviderName: SecretFileProviderName},
			fmt.Errorf("failed to read secret file %v error: %v", p.Path, err)
	}

	var cred SecretFileCredential
	err = json.Unmarshal(data, &cred)
	if err != nil {
		return credentials.Value{ProviderName: SecretFileProviderName},
			fmt.Errorf("failed to unmarshal secret file %v error: %v", p.Path, err)
	}
	p.SetExpiration(cred.Expiration, p.ExpiryWindow)

	if p.IsExpired() {
		return credentials.Value{ProviderName: SecretFileProviderName},
			fmt.Errorf("secret file %v is expired at %v", p.Path, cred.Expiration)
	}

	return credentials.Value{
		AccessKeyID:     cred.AccessKeyID,
		SecretAccessKey: cred.AccessSecretKey,
		SessionToken:    cred.Token,
		ProviderName:    SecretFileProviderName,
	}, nil

}
