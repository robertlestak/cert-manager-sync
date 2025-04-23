package slack

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/robertlestak/cert-manager-sync/pkg/state"
	"github.com/robertlestak/cert-manager-sync/pkg/tlssecret"
	log "github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type SlackStore struct {
	WebhookURL      string
	ChannelName     string
	Username        string
	SecretName      string
	SecretNamespace string
}

type SlackMessage struct {
	Channel     string            `json:"channel,omitempty"`
	Username    string            `json:"username,omitempty"`
	Text        string            `json:"text,omitempty"`
	IconEmoji   string            `json:"icon_emoji,omitempty"`
	Attachments []SlackAttachment `json:"attachments,omitempty"`
}

type SlackAttachment struct {
	Fallback   string                 `json:"fallback,omitempty"`
	Color      string                 `json:"color,omitempty"`
	Pretext    string                 `json:"pretext,omitempty"`
	AuthorName string                 `json:"author_name,omitempty"`
	AuthorLink string                 `json:"author_link,omitempty"`
	AuthorIcon string                 `json:"author_icon,omitempty"`
	Title      string                 `json:"title,omitempty"`
	TitleLink  string                 `json:"title_link,omitempty"`
	Text       string                 `json:"text,omitempty"`
	Fields     []SlackAttachmentField `json:"fields,omitempty"`
	ImageURL   string                 `json:"image_url,omitempty"`
	ThumbURL   string                 `json:"thumb_url,omitempty"`
	Footer     string                 `json:"footer,omitempty"`
	FooterIcon string                 `json:"footer_icon,omitempty"`
	Timestamp  int64                  `json:"ts,omitempty"`
}

type SlackAttachmentField struct {
	Title string `json:"title,omitempty"`
	Value string `json:"value,omitempty"`
	Short bool   `json:"short,omitempty"`
}

func (s *SlackStore) GetWebhookURL(ctx context.Context) error {
	if s.WebhookURL != "" {
		return nil
	}
	
	gopt := metav1.GetOptions{}
	sc, err := state.KubeClient.CoreV1().Secrets(s.SecretNamespace).Get(ctx, s.SecretName, gopt)
	if err != nil {
		return err
	}
	if sc.Data["webhook_url"] == nil {
		return fmt.Errorf("webhook_url not found in secret %s/%s", s.SecretNamespace, s.SecretName)
	}
	s.WebhookURL = string(sc.Data["webhook_url"])
	return nil
}

func (s *SlackStore) FromConfig(c tlssecret.GenericSecretSyncConfig) error {
	l := log.WithFields(log.Fields{
		"action": "FromConfig",
	})
	l.Debugf("FromConfig")
	
	if c.Config["webhook-url"] != "" {
		s.WebhookURL = c.Config["webhook-url"]
	}
	if c.Config["secret-name"] != "" {
		s.SecretName = c.Config["secret-name"]
	}
	if c.Config["channel"] != "" {
		s.ChannelName = c.Config["channel"]
	}
	if c.Config["username"] != "" {
		s.Username = c.Config["username"]
	} else {
		s.Username = "cert-manager-sync"
	}
	
	// Handle the namespace/secretname format
	if strings.Contains(s.SecretName, "/") {
		s.SecretNamespace = strings.Split(s.SecretName, "/")[0]
		s.SecretName = strings.Split(s.SecretName, "/")[1]
	}
	
	return nil
}

// SendNotification sends a notification about a sync event
func (s *SlackStore) SendNotification(storeType, secretName, namespace, msg string, isSuccess bool) error {
	l := log.WithFields(log.Fields{
		"action":    "SendNotification",
		"store":     "slack",
		"storeType": storeType,
		"isSuccess": isSuccess,
	})
	l.Debugf("Sending notification to Slack")
	
	ctx := context.Background()
	if err := s.GetWebhookURL(ctx); err != nil {
		l.WithError(err).Errorf("Failed to get webhook URL")
		return err
	}
	
	// Build the message
	color := "#36a64f" // Green for success
	title := fmt.Sprintf("Certificate Sync Success: %s", secretName)
	icon := ":lock:"
	
	if !isSuccess {
		color = "#e01e5a" // Red for failure
		title = fmt.Sprintf("Certificate Sync Failed: %s", secretName)
		icon = ":warning:"
	}
	
	attachment := SlackAttachment{
		Color:     color,
		Title:     title,
		Text:      msg,
		Timestamp: time.Now().Unix(),
		Fields: []SlackAttachmentField{
			{
				Title: "Store Type",
				Value: storeType,
				Short: true,
			},
			{
				Title: "Secret Name",
				Value: secretName,
				Short: true,
			},
			{
				Title: "Namespace",
				Value: namespace,
				Short: true,
			},
		},
		Footer: "cert-manager-sync",
	}
	
	message := SlackMessage{
		Username:    s.Username,
		IconEmoji:   icon,
		Attachments: []SlackAttachment{attachment},
	}
	
	// Use channel from config if specified
	if s.ChannelName != "" {
		message.Channel = s.ChannelName
	}
	
	payload, err := json.Marshal(message)
	if err != nil {
		l.WithError(err).Errorf("Failed to marshal Slack message")
		return err
	}
	
	resp, err := http.Post(s.WebhookURL, "application/json", bytes.NewBuffer(payload))
	if err != nil {
		l.WithError(err).Errorf("Failed to send Slack message")
		return err
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("slack API returned non-200 status code: %d", resp.StatusCode)
	}
	
	l.Info("Slack notification sent successfully")
	return nil
}

// NotifySuccess sends a notification about a successful sync
func (s *SlackStore) NotifySuccess(storeType, secretName, namespace, successMsg string) error {
	return s.SendNotification(storeType, secretName, namespace, successMsg, true)
}

// NotifyFailure sends a notification about a failed sync
func (s *SlackStore) NotifyFailure(storeType, secretName, namespace, errorMsg string) error {
	return s.SendNotification(storeType, secretName, namespace, errorMsg, false)
}

// Sync implements the Store interface but for the Slack store, it just returns success
// It's meant to be used as a notification endpoint, not a certificate store
func (s *SlackStore) Sync(c *tlssecret.Certificate) (map[string]string, error) {
	s.SecretNamespace = c.Namespace
	l := log.WithFields(log.Fields{
		"action":          "Sync",
		"store":           "slack",
		"secretName":      c.SecretName,
		"secretNamespace": c.Namespace,
	})
	l.Debug("Slack notification sync called, but this is typically used via NotifySuccess")
	
	// For the slack store, we don't actually sync a certificate
	// This is just here to satisfy the Store interface
	return nil, nil
}