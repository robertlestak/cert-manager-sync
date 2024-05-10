package main

import (
	"os"
	"time"

	"github.com/robertlestak/cert-manager-sync/pkg/certmanagersync"
	"github.com/robertlestak/cert-manager-sync/pkg/state"
	log "github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
)

func init() {
	ll, lerr := log.ParseLevel(os.Getenv("LOG_LEVEL"))
	if lerr != nil {
		ll = log.InfoLevel
	}
	log.SetLevel(ll)
	l := log.WithFields(
		log.Fields{
			"action": "init",
		},
	)
	if os.Getenv("OPERATOR_NAME") != "" {
		state.OperatorName = os.Getenv("OPERATOR_NAME")
	}
	cerr := state.CreateKubeClient()
	if cerr != nil {
		l.Fatal(cerr)
	}
}

func secretWorker(jobs chan v1.Secret, results chan error) {
	for s := range jobs {
		if err := certmanagersync.HandleSecret(&s); err != nil {
			results <- err
			continue
		}
		results <- nil
	}
}

func main() {
	l := log.WithFields(
		log.Fields{
			"fn": "main",
		},
	)
	l.Info("starting cert-manager-sync")
	// main loop
	for {
		l.Debug("main loop")
		// if namespace is not specified all namespaces will be searched
		// assuming the operator has the correct permissions
		namespace := os.Getenv("SECRETS_NAMESPACE")
		secrets, serr := state.GetSecrets(namespace)
		if serr != nil {
			l.Fatal(serr)
		}
		workerCount := 10
		if len(secrets) < workerCount {
			workerCount = len(secrets)
		}
		jobs := make(chan v1.Secret, len(secrets))
		results := make(chan error, len(secrets))
		for w := 1; w <= workerCount; w++ {
			go secretWorker(jobs, results)
		}
		for _, s := range secrets {
			jobs <- s
		}
		close(jobs)
		errCount := 0
		for a := 1; a <= len(secrets); a++ {
			err := <-results
			if err != nil {
				l.Error(err)
				errCount++
			}
		}
		if errCount > 0 {
			l.WithFields(log.Fields{
				"errCount": errCount,
			}).Error("sync errors occurred")
		}
		time.Sleep(60 * time.Second)
	}
}
