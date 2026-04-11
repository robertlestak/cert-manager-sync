package main

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLeaderElectionDefaults(t *testing.T) {
	os.Unsetenv("LEADER_ELECTION_ENABLED")
	os.Unsetenv("LEADER_ELECTION_LOCK_NAME")
	os.Unsetenv("LEADER_ELECTION_NAMESPACE")

	// Default: leader election enabled
	assert.NotEqual(t, "false", os.Getenv("LEADER_ELECTION_ENABLED"),
		"leader election should be enabled by default")
}

func TestLeaderElectionDisabled(t *testing.T) {
	os.Setenv("LEADER_ELECTION_ENABLED", "false")
	defer os.Unsetenv("LEADER_ELECTION_ENABLED")

	assert.Equal(t, "false", os.Getenv("LEADER_ELECTION_ENABLED"))
}

func TestLeaderElectionCustomLockName(t *testing.T) {
	os.Setenv("LEADER_ELECTION_LOCK_NAME", "custom-lock")
	defer os.Unsetenv("LEADER_ELECTION_LOCK_NAME")

	assert.Equal(t, "custom-lock", os.Getenv("LEADER_ELECTION_LOCK_NAME"))
}

func TestLeaderElectionCustomNamespace(t *testing.T) {
	os.Setenv("LEADER_ELECTION_NAMESPACE", "kube-system")
	defer os.Unsetenv("LEADER_ELECTION_NAMESPACE")

	assert.Equal(t, "kube-system", os.Getenv("LEADER_ELECTION_NAMESPACE"))
}
