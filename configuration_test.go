package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestConfiguration(t *testing.T) {
	configuration := ParseConfiguration()

	assert.Equal(t, configuration.AuthnContextClassRef, passwordProtectedTransport)
}
