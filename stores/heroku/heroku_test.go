package heroku

import (
	"context"
	"errors"
	"testing"

	heroku "github.com/heroku/heroku-go/v5"
	"github.com/stretchr/testify/assert"
)

func TestIsHerokuNotFound(t *testing.T) {
	assert.False(t, isHerokuNotFound(nil))
	assert.False(t, isHerokuNotFound(errors.New("plain")))
	notFound := heroku.Error{StatusCode: 404}
	assert.True(t, isHerokuNotFound(notFound))
	other := heroku.Error{StatusCode: 500}
	assert.False(t, isHerokuNotFound(other))
}

func TestHerokuDelete_NoOpWhenCertNameMissing(t *testing.T) {
	// Sync never populated cert-name → no SNI endpoint exists → success.
	s := &HerokuStore{AppName: "a", SecretName: "n"}
	assert.NoError(t, s.Delete(context.Background()))
}

func TestHerokuDelete_RequiresOtherConfigWhenCertNameSet(t *testing.T) {
	cases := []struct {
		name string
		s    *HerokuStore
	}{
		{name: "missing app", s: &HerokuStore{CertName: "c", SecretName: "n"}},
		{name: "missing secret name", s: &HerokuStore{CertName: "c", AppName: "a"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.s.Delete(context.Background())
			assert.Error(t, err)
		})
	}
}
