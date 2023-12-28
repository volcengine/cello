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
	"time"

	v1 "k8s.io/api/core/v1"

	"github.com/volcengine/cello/pkg/provider/volcengine/metadata"
	"github.com/volcengine/cello/pkg/tracing"
	"github.com/volcengine/cello/pkg/utils/logger"
)

var log = logger.GetLogger().WithFields(logger.Fields{"subsys": "credential"})

const (
	MetadataCredentialPath = "iam/security_credentials"
)

// STSProvider provide dynamic Credential from metadata.
type STSProvider struct {
	role              string
	currentCredential *Credential
}

func (p *STSProvider) Get() *Credential {
	return p.currentCredential
}

func (p *STSProvider) refresh() *Credential {
	log.DebugS("Start to refresh sts", "role", p.role)
	for {
		c, err := p.getNewSTS()
		if err != nil {
			log.ErrorS(err, "Failed to get new sts")
			t := time.NewTimer(10 * time.Second)
			<-t.C
			continue
		}
		log.DebugS("STS refreshed", "CurrentTime", c.CurrentTime.String(), "ExpiredTime", c.ExpiredTime.String())
		return c
	}
}

func (p *STSProvider) init() {
	log.InfoS("Init STSProvider")
	p.currentCredential = p.refresh()
	go func() {
		for {
			d := p.currentCredential.ExpiredTime.Sub(p.currentCredential.CurrentTime) / 2
			log.DebugS("Next refresh task will be scheduled", "after", d.String())
			t := time.NewTimer(d)
			<-t.C
			p.currentCredential = p.refresh()
		}
	}()
}

func (p *STSProvider) getNewSTS() (cr *Credential, err error) {
	var data string
	defer func() {
		if err != nil {
			_ = tracing.RecordNodeEvent(v1.EventTypeWarning, tracing.EventCredentialServiceAbnormal, err.Error())
		}
	}()

	data, err = metadata.New().GetMetadata(context.TODO(), "GetIamRoleCredential", fmt.Sprintf("%s/%s", MetadataCredentialPath, p.role))
	if err != nil {
		err = fmt.Errorf("get sts failed, %v", err)
		return
	}

	credential := &Credential{}
	err = json.Unmarshal([]byte(data), &credential)
	if err != nil {
		return
	}
	cr = credential
	return
}

func NewSTSProvider(role string) *STSProvider {
	stsProvider := &STSProvider{
		role: role,
	}
	stsProvider.init()
	return stsProvider
}
