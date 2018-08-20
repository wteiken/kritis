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
	"fmt"
	"reflect"
	"testing"

	"github.com/grafeas/kritis/pkg/kritis/apis/kritis/v1beta1"
	"github.com/grafeas/kritis/pkg/kritis/crd/buildpolicy"
	"github.com/grafeas/kritis/pkg/kritis/secrets"
	"github.com/grafeas/kritis/pkg/kritis/testutil"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestValidateAndSign(t *testing.T) {
	keys := map[string]*secrets.PGPSigningSecret{
		"auth1_key": testutil.CreateSecret(t, "auth1_key"),
		"auth2_key": testutil.CreateSecret(t, "auth2_key"),
		"auth3_key": testutil.CreateSecret(t, "auth3_key"),
	}
	sMock := func(namespace string, name string) (*secrets.PGPSigningSecret, error) {
		sec, ok := keys[name]
		if ok {
			return sec, nil
		} else {
			return nil, fmt.Errorf("No key for %q", name)
		}
	}
	var bps = []v1beta1.BuildPolicy{
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "bp_auth1",
				Namespace: "foo",
			},
			Spec: v1beta1.BuildPolicySpec{
				AttestationAuthorityName: "auth1",
				BuildRequirements: v1beta1.BuildRequirements{
					BuiltFrom: "single_attestor",
				},
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "bp_auth2",
				Namespace: "foo",
			},
			Spec: v1beta1.BuildPolicySpec{
				AttestationAuthorityName: "auth2",
				BuildRequirements: v1beta1.BuildRequirements{
					BuiltFrom: "multi_attestor",
				},
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "bp_auth3",
				Namespace: "foo",
			},
			Spec: v1beta1.BuildPolicySpec{
				AttestationAuthorityName: "auth3",
				BuildRequirements: v1beta1.BuildRequirements{
					BuiltFrom: "multi_attestor",
				},
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "bp_auth4",
				Namespace: "foo",
			},
			Spec: v1beta1.BuildPolicySpec{
				AttestationAuthorityName: "auth4",
				BuildRequirements: v1beta1.BuildRequirements{
					BuiltFrom: "no_key_attestor",
				},
			},
		},
	}
	aMock := func(ns string, auth string) (*v1beta1.AttestationAuthority, error) {
		switch auth {
		case "auth1", "auth2", "auth3":
			return &v1beta1.AttestationAuthority{
				ObjectMeta: metav1.ObjectMeta{
					Name:      auth,
					Namespace: "foo",
				},
				Spec: v1beta1.AttestationAuthoritySpec{
					NoteReference:        auth + "_note",
					PrivateKeySecretName: auth + "_key",
					PublicKeyData:        keys[auth+"_key"].PublicKey,
				},
			}, nil
		case "auth4":
			return &v1beta1.AttestationAuthority{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "auth4",
					Namespace: "foo",
				},
				Spec: v1beta1.AttestationAuthoritySpec{
					NoteReference:        "auth4_note",
					PrivateKeySecretName: "missing_key",
				},
			}, nil
		default:
			return nil, fmt.Errorf("unknown aa")
		}
	}

	tests := []struct {
		name                 string
		provenance           BuildProvenance
		expectedAttestations map[string]string
		shdErr               bool
	}{
		{
			name: "build matches single attestor",
			provenance: BuildProvenance{
				ImageRef:  "image1",
				BuiltFrom: "single_attestor",
			},
			expectedAttestations: map[string]string{
				"image1-auth1_note": "auth1_key",
			},
		},
		{
			name: "build matches multiple attestors",
			provenance: BuildProvenance{
				ImageRef:  "image1",
				BuiltFrom: "multi_attestor",
			},
			expectedAttestations: map[string]string{
				"image1-auth2_note": "auth2_key",
				"image1-auth3_note": "auth3_key",
			},
		},
		{
			name: "build matches no attestor",
			provenance: BuildProvenance{
				ImageRef:  "image1",
				BuiltFrom: "no_attestor",
			},
		},
		{
			name: "build matches attestor without key",
			provenance: BuildProvenance{
				ImageRef:  "image1",
				BuiltFrom: "no_key_attestor",
			},
			shdErr: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cMock := &testutil.MockMetadataClient{}
			r := New(cMock, &Config{
				Validate:  buildpolicy.ValidateBuildPolicy,
				Secret:    sMock,
				Authority: aMock,
			})
			if err := r.ValidateAndSign(tc.provenance, bps); (err != nil) != tc.shdErr {
				t.Errorf("ValidateAndSign returned error %s, want %t", err, tc.shdErr)
			}
			if !reflect.DeepEqual(cMock.Occ, tc.expectedAttestations) {
				t.Errorf("Got attestations: %v, Expected: %v\n ", cMock.Occ, tc.expectedAttestations)
			}
		})
	}
}
