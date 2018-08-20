/*
Copyright 2018 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package gcbsigner

import (
	"github.com/golang/glog"
	"github.com/grafeas/kritis/pkg/kritis/apis/kritis/v1beta1"
	"github.com/grafeas/kritis/pkg/kritis/crd/authority"
	"github.com/grafeas/kritis/pkg/kritis/crd/buildpolicy"
	"github.com/grafeas/kritis/pkg/kritis/metadata"
	"github.com/grafeas/kritis/pkg/kritis/secrets"
	"github.com/grafeas/kritis/pkg/kritis/util"
)

type Signer struct {
	config *Config
	client metadata.Fetcher
}

type Config struct {
	Secret    secrets.Fetcher
	Authority authority.Fetcher
	Validate  buildpolicy.ValidateFunc
}

func New(client metadata.Fetcher, c *Config) Signer {
	return Signer{
		client: client,
		config: c,
	}
}

type BuildProvenance struct {
	BuildID   string
	ImageRef  string
	BuiltFrom string
}

// ValidateAndSign validates builtFrom against the build policies and creates
// attestations for all authorities for the matching policies.
// Returns an error if creating an attestation for any authority fails.
func (s Signer) ValidateAndSign(prov BuildProvenance, bps []v1beta1.BuildPolicy) error {
	for _, bp := range bps {
		glog.Infof("Validating %q against BuildPolicy %q", prov.ImageRef, bp.Name)
		if result := s.config.Validate(bp, prov.BuiltFrom); result != nil {
			glog.Errorf("Image %q does not match BuildPolicy %q: %s", prov.ImageRef, bp.ObjectMeta.Name, result)
			continue
		}
		glog.Infof("Image %q matches BuildPolicy %s, creating attestations", prov.ImageRef, bp.Name)
		aa, err := r.config.Authority(bp.Namespace, bp.Spec.AttestationAuthorityName)
		if err != nil {
			return err
		}
		if err := r.addAttestation(aa, prov.ImageRef); err != nil {
			return err
		}
	}
	return nil
}

func (r Signer) addAttestation(aa *v1beta1.AttestationAuthority, image string) error {
	glog.Infof("Ceate attestation by %q for %q", image, aa.Name)
	// Get or Create Note for this this Authority
	n, err := r.getOrCreateAttestationNote(aa)
	if err != nil {
		return fmt.Errorf("error getting note for %q: %v", aa.Name, err)
	}
	// Get secret for this Authority
	s, err := r.config.Secret(aa.ObjectMeta.Namespace, aa.Spec.PrivateKeySecretName)
	if err != nil {
		return fmt.Errorf("error getting secret for %q: %v", aa.Name, err)
	}
	// Create Attestation Signature
	if _, err := r.client.CreateAttestationOccurence(n, image, s); err != nil {
		return fmt.Errorf("error adding attestation for %q: %v", aa.Name, err)
	}
	return nil
}

func (r Signer) getOrCreateAttestationNote(a *v1beta1.AttestationAuthority) (*containeranalysispb.Note, error) {
	n, err := r.client.GetAttestationNote(a)
	if err == nil {
		return n, nil
	}
	// Create Attestation Signature
	_, err = s.client.CreateAttestationOccurence(n, image, sec)
	return err
}
