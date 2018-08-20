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

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/golang/glog"
	"golang.org/x/net/context"

	ca "cloud.google.com/go/devtools/containeranalysis/apiv1alpha1"
	"cloud.google.com/go/pubsub"
	capb "google.golang.org/genproto/googleapis/devtools/containeranalysis/v1alpha1"
)

func main() {
	gcrProject := flag.String("gcr_project", "", "Id of the project running vulnerability scans for GCR")
	gcrSubscription := flag.String("gcr_subscription", "vuln-signer", "Name of the Container Analysis subscription")
	resourceNamespace := flag.String("resource_namespace", os.Getenv("SIGNER_NAMESPACE"), "Namespace the signer CRDs and secrets are stored in")
	flag.Parse()

	err := run(*gcrProject, *gcrSubscription, *resourceNamespace)
	if err != nil {
		glog.Fatalf("Error running signer: %v", err)
	}
}

func run(gcrProject string, gcrSubscription string, ns string) error {
	ctx := context.Background()
	client, err := pubsub.NewClient(ctx, gcrProject)
	if err != nil {
		return fmt.Errorf("Could not create pubsub Client: %v", err)
	}

	sub := client.Subscription(gcrSubscription)
	for err == nil {
		glog.Infof("Listening")
		err = sub.Receive(ctx, func(ctx context.Context, msg *pubsub.Message) {
			if err := process(ns, msg); err != nil {
				glog.Errorf("Error signing: %v", err)
				msg.Nack()
			} else {
				msg.Ack()
			}
		})
	}
	return fmt.Errorf("Error receiving message: %v", err)
}

func process(ns string, msg *pubsub.Message) error {
	glog.Infof(string(msg.Data))

	var event ContainerAnalysisEvent
	if err := json.Unmarshal(msg.Data, &event); err != nil {
		return err
	}

	ctx := context.Background()
	client, err := ca.NewClient(ctx)
	if err != nil {
		return err
	}
	req := &capb.GetOccurrenceRequest{
		Name: event.OccurrenceName,
	}
	occ, err := client.GetOccurrence(ctx, req)
	if err != nil {
		return err
	}
	if occ.Kind != capb.Note_DISCOVERY {
		return nil
	}
	if occ.GetDiscovered().GetAnalysisStatus() == capb.Discovery_Discovered_FINISHED_SUCCESS {

	}
	return nil
}

type ContainerAnalysisEvent struct {
	OccurrenceName string
}
