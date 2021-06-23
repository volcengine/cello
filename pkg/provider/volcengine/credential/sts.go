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
	"io/ioutil"
	"net/http"
	"time"

	v1 "k8s.io/api/core/v1"

	"github.com/volcengine/cello/pkg/tracing"
	"github.com/volcengine/cello/pkg/utils/logger"
)

const (
	credentialServerAddress = "http://100.96.0.96/volcstack/latest/iam/security_credentials/"
)

var log = logger.GetLogger().WithFields(logger.Fields{"subsys": "credential"})

// STSProvider provide dynamic Credential.
type STSProvider struct {
	role              string
	currentCredential *Credential
}

func (p *STSProvider) Get() *Credential {
	return p.currentCredential
}

func (p *STSProvider) refresh() *Credential {
	log.Debugf("start to refresh sts for role %s", p.role)
	for {
		c, err := p.getNewSTS(p.role)
		if err != nil {
			log.Warnf("failed to get new sts: %s", err.Error())
			t := time.NewTimer(10 * time.Second)
			<-t.C
			continue
		}
		log.Debugf("STS refreshed, current time %s, expired time %s", c.CurrentTime.String(), c.ExpiredTime.String())
		return c
	}
}

func (p *STSProvider) init() {
	log.Infof("Init STSProvider")
	p.currentCredential = p.refresh()
	go func() {
		for {
			d := p.currentCredential.ExpiredTime.Sub(p.currentCredential.CurrentTime) / 2
			log.Debugf("Next refresh task was scheduled after %s", d.String())
			t := time.NewTimer(d)
			<-t.C
			p.currentCredential = p.refresh()
		}
	}()
}

func (p *STSProvider) getNewSTS(role string) (cr *Credential, err error) {
	var resp *http.Response

	defer func() {
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
		}
		if err != nil {
			fmtErr := fmt.Sprintf("get sts failed, %v", err)
			_ = tracing.RecordNodeEvent(v1.EventTypeWarning, tracing.EventCredentialServiceAbnormal, fmtErr)
		}
	}()

	if resp, err = http.Get(credentialServerAddress + role); err != nil || resp.StatusCode != http.StatusOK {
		err = fmt.Errorf("get sts with role %s failed, status: %v, err: %v", role, resp.StatusCode, err)
		return
	}

	var data []byte
	if data, err = ioutil.ReadAll(resp.Body); err != nil {
		err = fmt.Errorf("read response body failed, %s", err.Error())
		return
	}

	credential := &Credential{}
	err = json.Unmarshal(data, &credential)
	if err != nil {
		return
	}
	cr = credential
	return
}

func NewTSTProvider(role string) *STSProvider {
	stsProvider := &STSProvider{
		role: role,
	}
	stsProvider.init()
	return stsProvider
}
