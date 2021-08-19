package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestConfiguration(t *testing.T) {
	configuration := ParseConfiguration()

	assert.Equal(t, configuration.AuthnContextClassRef, "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport")
}
