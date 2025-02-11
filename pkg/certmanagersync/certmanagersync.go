package certmanagersync

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	log "github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	_ "github.com/robertlestak/cert-manager-sync/stores/acm"
	_ "github.com/robertlestak/cert-manager-sync/stores/cloudflare"
	_ "github.com/robertlestak/cert-manager-sync/stores/digitalocean"
	_ "github.com/robertlestak/cert-manager-sync/stores/filepath"
	_ "github.com/robertlestak/cert-manager-sync/stores/gcpcm"
	_ "github.com/robertlestak/cert-manager-sync/stores/heroku"
	_ "github.com/robertlestak/cert-manager-sync/stores/incapsula"
	_ "github.com/robertlestak/cert-manager-sync/stores/tencentcloud"
	_ "github.com/robertlestak/cert-manager-sync/stores/threatx"
	_ "github.com/robertlestak/cert-manager-sync/stores/vault"

	"github.com/robertlestak/cert-manager-sync/internal/metrics"
	"github.com/robertlestak/cert-manager-sync/pkg/state"
	"github.com/robertlestak/cert-manager-sync/pkg/tlssecret"
	"github.com/robertlestak/cert-manager-sync/stores"
)

// maxRetries returns the max number of sync attempts allowed for a secret
// if the secret has a max-sync-attempts annotation
// if the annotation is not present, -1 is returned, indicating unlimited retries
func maxRetries(s *corev1.Secret) int {
	l := log.WithFields(log.Fields{
		"action": "maxRetries",
	})
	l.Debugf("maxRetries %s", s.Name)
	if s.Annotations == nil {
		return -1
	}
	if s.Annotations[state.OperatorName+"/max-sync-attempts"] != "" {
		iv, err := strconv.ParseInt(s.Annotations[state.OperatorName+"/max-sync-attempts"], 10, 64)
		if err != nil {
			l.WithError(err).Errorf("ParseInt error")
			return -1
		}
		return int(iv)
	}
	return -1
}

// consumedRetries returns the number of sync attempts that have been made for a secret
// if the secret has a failed-sync-attempts annotation
// if the annotation is not present, 0 is returned, indicating no retries have been made
func consumedRetries(s *corev1.Secret) int {
	l := log.WithFields(log.Fields{
		"action": "consumedRetries",
	})
	l.Debugf("consumedRetries %s", s.Name)
	if s.Annotations == nil {
		return 0
	}
	if s.Annotations[state.OperatorName+"/failed-sync-attempts"] != "" {
		iv, err := strconv.ParseInt(s.Annotations[state.OperatorName+"/failed-sync-attempts"], 10, 64)
		if err != nil {
			l.WithError(err).Errorf("ParseInt error")
			return 0
		}
		return int(iv)
	}
	return 0
}

// nextRetryTime returns the time when the next sync attempt should be made
// it will return zero time if the secret has not exceeded the max retries
func nextRetryTime(s *corev1.Secret) time.Time {
	l := log.WithFields(log.Fields{
		"action":    "nextRetryTime",
		"namespace": s.Namespace,
		"name":      s.Name,
	})

	if s.Annotations == nil {
		return time.Time{}
	}
	if s.Annotations[state.OperatorName+"/next-retry"] != "" {
		t, err := time.Parse(time.RFC3339, s.Annotations[state.OperatorName+"/next-retry"])
		if err != nil {
			l.WithError(err).Errorf("Parse error")
			return time.Time{}
		}
		l = l.WithFields(log.Fields{
			"next-retry": t,
		})
		l.Debugf("nextRetryTime %s", t)
		return t
	}
	return time.Time{}
}

func readyToRetry(s *corev1.Secret) bool {
	l := log.WithFields(log.Fields{
		"action": "readyToRetry",
	})
	l.Debugf("readyToRetry %s", s.Name)
	maxR := maxRetries(s)
	// if the secret has exceeded the max retries, return false
	consumedR := consumedRetries(s)
	if maxR != -1 && consumedR >= maxR {
		l.Errorf("max retries reached")
		return false
	}
	// if the secret is ready to retry, return true
	nextR := nextRetryTime(s)
	if nextR.IsZero() || time.Now().After(nextR) {
		l.Debugf("ready to retry")
		return true
	}
	// otherwise, return false
	return false
}

func calculateNextRetryTime(secret *corev1.Secret) time.Time {
	// Get the number of failed sync attempts from the annotations
	retries := consumedRetries(secret)

	// Calculate the delay using binary exponential backoff
	var delay time.Duration
	if retries < 31 {
		delay = time.Duration(1<<uint(retries)) * time.Minute
	} else {
		delay = 32 * time.Hour
	}

	// Cap the delay at 32 hours
	if delay > 32*time.Hour {
		delay = 32 * time.Hour
	}

	// Calculate the next retry time
	nextRetryTime := time.Now().Add(delay)
	return nextRetryTime
}

func HandleSecret(s *corev1.Secret) error {
	l := log.WithFields(log.Fields{
		"action":    "HandleSecret",
		"namespace": s.Namespace,
		"name":      s.Name,
	})

	// ensure we haven't exceeded the allotted retries
	if !readyToRetry(s) {
		l.Debug("not ready to retry")
		return nil
	}
	// check if the secret has changed since last sync
	if !state.CacheChanged(s) {
		return nil
	}
	cert := tlssecret.ParseSecret(s)
	if cert == nil {
		l.Errorf("error parsing secret")
		return fmt.Errorf("error parsing secret %s/%s", s.Namespace, s.Name)
	}
	var errs []error
	for _, sync := range cert.Syncs {
		ll := l.WithFields(log.Fields{
			"store": sync.Store,
		})
		ll.Debugf("syncing to store %s", sync.Store)
		rs, err := stores.New(sync.Store, *sync)
		if err != nil {
			l.WithError(err).Errorf("NewStore error")
			continue
		}
		updates, err := rs.Sync(cert)
		if err != nil {
			l.WithError(err).Errorf("Sync error")
			metrics.SetFailure(s.Namespace, s.Name, sync.Store)
			state.EventRecorder.Event(s, corev1.EventTypeWarning, "SyncFailed", fmt.Sprintf("Secret sync failed to store %s", sync.Store))
			errs = append(errs, err)
			continue
		}
		if len(updates) > 0 {
			l.WithField("updates", updates).Debug("synced with updates")
		}
		sync.Updates = updates
	}
	patchAnnotations := make(map[string]string)
	if s.Annotations != nil {
		for k, v := range s.Annotations {
			patchAnnotations[k] = v
		}
	}
	au := tlssecret.AnnotationUpdates(cert)
	// add au to patchAnnotations
	for k, v := range au {
		patchAnnotations[k] = v
	}
	if len(errs) > 0 {
		// increment the failed-sync-attempts annotation
		// increment the failed-sync-attempts annotation
		iv := consumedRetries(s) + 1
		patchAnnotations[state.OperatorName+"/failed-sync-attempts"] = strconv.Itoa(iv)
		// set the next-retry annotation to the current time plus the delay
		// the delay is a binary exponential backoff, starting at 1 minute, then 2, 4, 8.. up to 32 hours
		nextRetry := calculateNextRetryTime(s)
		// add the next-retry annotation to the secret
		// this will be evaluated by the readyToRetry function
		// when the next sync attempt is made
		patchAnnotations[state.OperatorName+"/next-retry"] = nextRetry.Format(time.RFC3339)
	} else {
		delete(patchAnnotations, state.OperatorName+"/failed-sync-attempts")
		// remove the next-retry annotation
		delete(patchAnnotations, state.OperatorName+"/next-retry")
		// the sync was a success, add the secret to the cache
		patchAnnotations[state.OperatorName+"/hash"] = state.HashSecret(s)
	}
	l.WithField("patchAnnotations", patchAnnotations).Debug("patchAnnotations")
	// patch the secret with the updated annotations
	patchData := map[string]interface{}{
		"metadata": map[string]interface{}{
			"annotations": patchAnnotations,
		},
	}
	pd, err := json.Marshal(patchData)
	if err != nil {
		l.WithError(err).Errorf("json.Marshal error")
		return err
	}
	l.WithField("patchData", string(pd)).Debug("patchData")
	_, err = state.KubeClient.CoreV1().Secrets(s.Namespace).Patch(context.Background(), s.Name, types.MergePatchType, pd, metav1.PatchOptions{})
	if err != nil {
		l.WithError(err).Errorf("Patch error")
		return err
	}
	if len(errs) > 0 {
		l.WithField("errs", errs).Errorf("errors syncing secret")
		state.EventRecorder.Event(s, corev1.EventTypeWarning, "SyncFailed", fmt.Sprintf("Secret sync failed to %d store%s", len(errs), func() string {
			if len(errs) == 1 {
				return ""
			}
			return "s"
		}()))
		return fmt.Errorf("errors syncing secret %s/%s: %v", s.Namespace, s.Name, errs)
	}
	scf := func() string {
		if len(cert.Syncs) == 1 {
			return ""
		}
		return "s"
	}()
	l.Infof("Secret synced to %d store%s", len(cert.Syncs), scf)
	eventMsg := fmt.Sprintf("Secret synced to %d store%s", len(cert.Syncs), scf)
	state.EventRecorder.Event(s, corev1.EventTypeNormal, "Synced", eventMsg)
	return nil
}
