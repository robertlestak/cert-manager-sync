package main

import (
	"cmp"
	"flag"
	"os"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/pflag"
	v1 "k8s.io/api/core/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/tools/cache"

	"github.com/robertlestak/cert-manager-sync/internal/metrics"
	"github.com/robertlestak/cert-manager-sync/pkg/certmanagersync"
	"github.com/robertlestak/cert-manager-sync/pkg/flags"
	"github.com/robertlestak/cert-manager-sync/pkg/state"
)

var metricsPort int

func init() {
	pflag.CommandLine.AddGoFlagSet(flag.CommandLine)
	logLevel := pflag.String("log.level", "info", "log level")
	logFmt := pflag.String("log.format", "console", "log format")
	pflag.IntVar(&metricsPort, "metrics.port", 9090, "http port for metrics handler, 0 means disable")

	flags.SetFromEnv(pflag.CommandLine)
	pflag.Parse()

	ll, lerr := log.ParseLevel(*logLevel)
	if lerr != nil {
		ll = log.InfoLevel
	}
	log.SetLevel(ll)
	if *logFmt == "json" {
		log.SetFormatter(&log.JSONFormatter{})
	}

	l := log.WithFields(
		log.Fields{
			"action": "init",
		},
	)
	state.OperatorName = cmp.Or(os.Getenv("OPERATOR_NAME"), state.OperatorName)
	cerr := state.CreateKubeClient()
	if cerr != nil {
		l.Fatal(cerr)
	}
}

func main() {
	l := log.WithFields(
		log.Fields{
			"fn": "main",
		},
	)
	l.Info("starting cert-manager-sync")
	if metricsPort > 0 {
		go metrics.Serve(metricsPort, "/metrics")
	}
	factory := informers.NewSharedInformerFactory(state.KubeClient, 30*time.Second)
	secretInformer := factory.Core().V1().Secrets().Informer()

	stopper := make(chan struct{})
	defer close(stopper)

	secretInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			s := obj.(*v1.Secret)
			if !state.SecretWatched(s) {
				return
			}
			if err := certmanagersync.HandleSecret(s); err != nil {
				l.Error(err)
			}
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			s := newObj.(*v1.Secret)
			if !state.SecretWatched(s) {
				return
			}
			if err := certmanagersync.HandleSecret(s); err != nil {
				l.Error(err)
			}
		},
	})

	factory.Start(stopper)

	// Wait for the caches to sync
	if !cache.WaitForCacheSync(stopper, secretInformer.HasSynced) {
		panic("Timed out waiting for caches to sync")
	}

	// Run the informer
	<-stopper
}
