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

package review

import (
	"fmt"

	"github.com/golang/glog"
	"github.com/grafeas/kritis/pkg/kritis/apis/kritis/v1beta1"
	"github.com/grafeas/kritis/pkg/kritis/container"
	"github.com/grafeas/kritis/pkg/kritis/crd/authority"
	"github.com/grafeas/kritis/pkg/kritis/crd/securitypolicy"
	"github.com/grafeas/kritis/pkg/kritis/metadata"
	"github.com/grafeas/kritis/pkg/kritis/secrets"
	"github.com/grafeas/kritis/pkg/kritis/util"
	"github.com/grafeas/kritis/pkg/kritis/violation"
	containeranalysispb "google.golang.org/genproto/googleapis/devtools/containeranalysis/v1alpha1"

	corev1 "k8s.io/api/core/v1"
)

type Reviewer struct {
	config *Config
	client metadata.Fetcher
}

type Config struct {
	Validate  securitypolicy.ValidateFunc
	Secret    secrets.Fetcher
	Authority authority.Fetcher
	Strategy  violation.Strategy
	IsWebhook bool
}

func New(client metadata.Fetcher, c *Config) Reviewer {
	return Reviewer{
		client: client,
		config: c,
	}
}

// Review reviews a set of images against a set of policies
// Returns error if violations are found and handles them as per violation strategy
func (r Reviewer) Review(images []string, isps []v1beta1.ImageSecurityPolicy, pod *corev1.Pod) error {
	images = util.RemoveGloballyWhitelistedImages(images)
	if len(images) == 0 {
		glog.Info("images are all globally whitelisted, returning successful status", images)
		return nil
	}
	for _, isp := range isps {
		glog.Infof("Validating against ImageSecurityPolicy %s", isp.Name)
		aa, err := r.config.Authority(isp.ObjectMeta.Namespace, isp.Spec.AttestationAuthorityName)
		if err != nil {
			return fmt.Errorf("error getting authority %q: %v", isp.Spec.AttestationAuthorityName, err)
		}

		for _, image := range images {
			glog.Infof("Check if %s as valid Attestations.", image)
			isAttested, err := r.verifyAttestations(aa, image, pod)
			if err != nil {
				return fmt.Errorf("error getting attestations for %q: %v", aa.Name, err)
			}
			// Skip vulnerability check for Webhook if attestations found.
			if isAttested && r.config.IsWebhook {
				continue
			}

			glog.Infof("Getting vulnz for %s", image)
			violations, err := r.config.Validate(isp, image, r.client)
			if err != nil {
				return fmt.Errorf("error validating image security policy %v", err)
			}
			if len(violations) != 0 {
				return r.handleViolations(image, pod, violations)
			}
			if r.config.IsWebhook {
				if err := r.addAttestations(aa, image); err != nil {
					glog.Errorf("error adding attestations %s", err)
				}
			}
			glog.Infof("Found no violations in %s", image)
		}
	}
	return nil
}

func (r Reviewer) verifyAttestations(aa *v1beta1.AttestationAuthority, image string, pod *corev1.Pod) (bool, error) {
	attestations, err := r.client.GetAttestations(aa, image)
	if err != nil {
		return false, fmt.Errorf("Error while fetching attestations %s", err)
	}
	isAttested := r.hasValidImageAttestations(aa, image, attestations)
	if err := r.config.Strategy.HandleAttestation(image, pod, isAttested); err != nil {
		return false, fmt.Errorf("error handling attestations %v", err)
	}
	return isAttested, nil
}

// hasValidImageAttestations return true if any one image attestation is verified.
func (r Reviewer) hasValidImageAttestations(aa *v1beta1.AttestationAuthority, image string, attestations []metadata.PGPAttestation) bool {
	if len(attestations) == 0 {
		glog.Infof(`No attestations found for image %s.
This normally happens when you deploy a pod before kritis or no attestation authority is deployed.
Please see instructions `, image)
	}
	host, err := container.NewAtomicContainerSig(image, map[string]string{})
	if err != nil {
		glog.Error(err)
		return false
	}
	for _, a := range attestations {
		// Get Secret from key id.
		secret, err := r.config.Secret(aa.ObjectMeta.Namespace, aa.Spec.PrivateKeySecretName)
		if err != nil {
			glog.Errorf("Could not find secret %s in namespace %s for attestation verification", aa.Spec.PrivateKeySecretName, aa.ObjectMeta.Namespace)
			continue
		}
		if err = host.VerifyAttestationSignature(secret.PublicKey, a.Signature); err != nil {
			glog.Errorf("Could not find verify attestation for attestation authority %s", a.KeyID)
		} else {
			return true
		}
	}
	return false
}

func (r Reviewer) handleViolations(image string, pod *corev1.Pod, violations []securitypolicy.Violation) error {
	errMsg := fmt.Sprintf("found violations in %s", image)
	// Check if one of the violations is that the image is not fully qualified
	for _, v := range violations {
		if v.Violation == securitypolicy.UnqualifiedImageViolation {
			errMsg = fmt.Sprintf(`%s is not a fully qualified image.
			  You can run 'kubectl plugin resolve-tags' to qualify all images with a digest.
			  Instructions for installing the plugin can be found at https://github.com/grafeas/kritis/blob/master/cmd/kritis/kubectl/plugins/resolve`, image)
		}
	}
	if err := r.config.Strategy.HandleViolation(image, pod, violations); err != nil {
		return fmt.Errorf("%s. error handling violation %v", errMsg, err)
	}
	return fmt.Errorf(errMsg)
}

func (r Reviewer) addAttestations(aa *v1beta1.AttestationAuthority, image string) error {
	n, err := r.getOrCreateAttestationNote(aa)
	if err != nil {
		return fmt.Errorf("error getting note for %q: %v", aa.Name, err)
	}
	// Get secret for this Authority
	s, err := r.config.Secret(aa.ObjectMeta.Namespace, aa.Spec.PrivateKeySecretName)
	if err != nil {
		return fmt.Errorf("error getting secret %q: %v", aa.Name, err)
	}
	// Create Attestation Signature
	if _, err := r.client.CreateAttestationOccurence(n, image, s); err != nil {
		return fmt.Errorf("error creating attestation for image %q by %q: %v", image, aa.Name, err)
	}
	return nil
}
