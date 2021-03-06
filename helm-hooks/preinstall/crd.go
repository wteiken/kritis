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

package main

const (
	attestationAuthorityCRD = `apiVersion: apiextensions.k8s.io/v1beta1
kind: CustomResourceDefinition
metadata:
    name: attestationauthorities.kritis.grafeas.io
    labels:
        %s: ""
spec:
    group: kritis.grafeas.io
    version: v1beta1
    scope: Namespaced
    names:
        plural: attestationauthorities
        singular: attestationauthority
        kind: AttestationAuthority`

	imageSecurityPolicyCRD = `apiVersion: apiextensions.k8s.io/v1beta1
kind: CustomResourceDefinition
metadata:
    name: imagesecuritypolicies.kritis.grafeas.io
    labels:
        %s: ""
spec:
    group: kritis.grafeas.io
    version: v1beta1
    names:
        kind: ImageSecurityPolicy
        plural: imagesecuritypolicies
        scope: Namespaced`
)
