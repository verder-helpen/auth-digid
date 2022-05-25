package main

import (
	"database/sql"
	"io/ioutil"
	"testing"
	"time"

	"github.com/crewjam/saml"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// To enable database tests, set this at test time with
// -ldflags "-X github.com/verder-helpen/auth-digid.testdb=<postgres url>"
var testdb string

// Prepare clean database for test
func setupDB(t *testing.T) {
	if testdb == "" {
		t.Skip("No database provided for tests")
	}

	commands, err := ioutil.ReadFile("schema.sql")
	require.NoError(t, err)
	db, err := sql.Open("pgx", testdb)
	require.NoError(t, err)
	defer db.Close()
	_, err = db.Exec(string(commands))
	require.NoError(t, err)
}

func TestMapDigiDAuthnContextClasses(t *testing.T) {
	ref, ok := digidAuthnContextClasses["Basis"]
	assert.Equal(t, ref, passwordProtectedTransport)
	assert.True(t, ok)
	ref, ok = digidAuthnContextClasses["Midden"]
	assert.Equal(t, ref, mobileTwoFactorContract)
	assert.True(t, ok)
	ref, ok = digidAuthnContextClasses["Substantieel"]
	assert.Equal(t, ref, smartcard)
	assert.True(t, ok)
	ref, ok = digidAuthnContextClasses["Hoog"]
	assert.Equal(t, ref, smartcardPKI)
	assert.True(t, ok)
	ref, ok = digidAuthnContextClasses["urn:oasis:names:tc:SAML:2.0:ac:classes:NotAnAuthnContextClass"]
	assert.False(t, ok)
	assert.NotEqual(t, ref, passwordProtectedTransport)
	assert.NotEqual(t, ref, mobileTwoFactorContract)
	assert.NotEqual(t, ref, smartcard)
	assert.NotEqual(t, ref, smartcardPKI)
}

func TestCompareAuthnContextClass(t *testing.T) {
	assert.False(t, CompareAuthnContextClass(passwordProtectedTransport, "urn:oasis:names:tc:SAML:2.0:ac:classes:NotAnAuthnContextClass"))
	assert.True(t, CompareAuthnContextClass(passwordProtectedTransport, passwordProtectedTransport))
	assert.True(t, CompareAuthnContextClass(passwordProtectedTransport, mobileTwoFactorContract))
	assert.True(t, CompareAuthnContextClass(passwordProtectedTransport, smartcard))
	assert.True(t, CompareAuthnContextClass(passwordProtectedTransport, smartcardPKI))

	assert.False(t, CompareAuthnContextClass(mobileTwoFactorContract, "urn:oasis:names:tc:SAML:2.0:ac:classes:NotAnAuthnContextClass"))
	assert.False(t, CompareAuthnContextClass(mobileTwoFactorContract, passwordProtectedTransport))
	assert.True(t, CompareAuthnContextClass(mobileTwoFactorContract, mobileTwoFactorContract))
	assert.True(t, CompareAuthnContextClass(mobileTwoFactorContract, smartcard))
	assert.True(t, CompareAuthnContextClass(mobileTwoFactorContract, smartcardPKI))

	assert.False(t, CompareAuthnContextClass(smartcard, "urn:oasis:names:tc:SAML:2.0:ac:classes:NotAnAuthnContextClass"))
	assert.False(t, CompareAuthnContextClass(smartcard, mobileTwoFactorContract))
	assert.False(t, CompareAuthnContextClass(smartcard, passwordProtectedTransport))
	assert.True(t, CompareAuthnContextClass(smartcard, smartcard))
	assert.True(t, CompareAuthnContextClass(smartcard, smartcardPKI))

	assert.False(t, CompareAuthnContextClass(smartcardPKI, "urn:oasis:names:tc:SAML:2.0:ac:classes:NotAnAuthnContextClass"))
	assert.False(t, CompareAuthnContextClass(smartcardPKI, passwordProtectedTransport))
	assert.False(t, CompareAuthnContextClass(smartcardPKI, mobileTwoFactorContract))
	assert.False(t, CompareAuthnContextClass(smartcardPKI, smartcard))
	assert.True(t, CompareAuthnContextClass(smartcardPKI, smartcardPKI))

}

func TestGenerateID(t *testing.T) {
	a := GenerateID()
	b := GenerateID()
	c := GenerateID()
	d := GenerateID()
	assert.NotEqual(t, a, b)
	assert.NotEqual(t, a, c)
	assert.NotEqual(t, a, d)
	assert.NotEqual(t, b, c)
	assert.NotEqual(t, b, d)
	assert.NotEqual(t, c, d)

	abcount := 0
	account := 0
	adcount := 0
	bccount := 0
	bdcount := 0
	cdcount := 0
	for i := range a {
		if a[i] == b[i] {
			abcount++
		}
		if a[i] == c[i] {
			account++
		}
		if a[i] == d[i] {
			adcount++
		}
		if b[i] == c[i] {
			bccount++
		}
		if b[i] == d[i] {
			bdcount++
		}
		if c[i] == d[i] {
			cdcount++
		}
	}

	assert.Greater(t, 10, abcount)
	assert.Greater(t, 10, account)
	assert.Greater(t, 10, adcount)
	assert.Greater(t, 10, bccount)
	assert.Greater(t, 10, bdcount)
	assert.Greater(t, 10, cdcount)
}

func TestSamlSessions(t *testing.T) {
	setupDB(t)
	db, err := sql.Open("pgx", testdb)
	require.NoError(t, err)
	defer db.Close()
	SamlSessionManager := SamlSessionEncoder{
		db:      db,
		timeout: 15,
	}

	testSamlAssertion1 := saml.Assertion{
		Subject: &saml.Subject{
			NameID: &saml.NameID{
				Value: "name",
			},
		},
		AuthnStatements: []saml.AuthnStatement{
			{
				AuthnContext: saml.AuthnContext{
					AuthnContextClassRef: &saml.AuthnContextClassRef{
						Value: "level1",
					},
				},
			},
			{
				AuthnContext: saml.AuthnContext{
					AuthnContextClassRef: &saml.AuthnContextClassRef{
						Value: "level3",
					},
				},
			},
		},
		AttributeStatements: []saml.AttributeStatement{
			{
				Attributes: []saml.Attribute{
					{
						Name: "testAttribute1",
						Values: []saml.AttributeValue{
							{
								Value: "ta1_v1",
							},
							{
								Value: "ta1_v2",
							},
						},
					},
					{
						Name: "testAttribute2",
						Values: []saml.AttributeValue{
							{
								Value: "ta2_v1",
							},
						},
					},
					{
						Name: "testAttribute2",
						Values: []saml.AttributeValue{
							{
								Value: "ta2_v2",
							},
						},
					},
				},
			},
			{
				Attributes: []saml.Attribute{
					{
						Name: "testAttribute1",
						Values: []saml.AttributeValue{
							{
								Value: "ta1_v3",
							},
						},
					},
				},
			},
		},
	}

	testSamlAssertion2 := saml.Assertion{
		Subject: &saml.Subject{
			NameID: &saml.NameID{
				Value: "test",
			},
		},
		AuthnStatements: []saml.AuthnStatement{
			{
				AuthnContext: saml.AuthnContext{
					AuthnContextClassRef: &saml.AuthnContextClassRef{
						Value: "level1",
					},
				},
			},
		},
		AttributeStatements: []saml.AttributeStatement{
			{
				Attributes: []saml.Attribute{
					{
						Name: "A",
						Values: []saml.AttributeValue{
							{
								Value: "B",
							},
						},
					},
					{
						Name: "NameID",
						Values: []saml.AttributeValue{
							{
								Value: "blaat",
							},
						},
					},
				},
			},
		},
	}

	testSession1, err := SamlSessionManager.New(&testSamlAssertion1)
	require.NoError(t, err)
	testSession1t := testSession1.(*SamlSession)
	assert.ElementsMatch(t, []string{"ta1_v1", "ta1_v2", "ta1_v3"}, testSession1t.attributes["testAttribute1"])
	assert.ElementsMatch(t, []string{"ta2_v1", "ta2_v2"}, testSession1t.attributes["testAttribute2"])
	assert.ElementsMatch(t, []string{"name"}, testSession1t.attributes["NameID"])
	assert.ElementsMatch(t, []string{"level1", "level3"}, testSession1t.attributes["AuthnContextClassRef"])
	assert.Equal(t, testSession1t.attributes, testSession1t.GetAttributes())

	id, err := SamlSessionManager.Encode(testSession1)
	assert.NoError(t, err)
	assert.Equal(t, testSession1t.id, id)

	testSession2, err := SamlSessionManager.Decode(testSession1t.id)
	require.NoError(t, err)
	assert.Equal(t, testSession1, testSession2)

	testSession3, err := SamlSessionManager.New(&testSamlAssertion2)
	testSession3t := testSession3.(*SamlSession)
	require.NoError(t, err)
	assert.NotEqual(t, testSession1t.id, testSession3t.id)
	assert.ElementsMatch(t, []string{"B"}, testSession3t.attributes["A"])
	assert.ElementsMatch(t, []string{"blaat", "test"}, testSession3t.attributes["NameID"])
	assert.ElementsMatch(t, []string{"level1"}, testSession3t.attributes["AuthnContextClassRef"])
	assert.Equal(t, testSession3t.attributes, testSession3t.GetAttributes())

	testSession4, err := SamlSessionManager.Decode(testSession3t.id)
	require.NoError(t, err)
	assert.Equal(t, testSession3, testSession4)

	testSession5, err := SamlSessionManager.Decode(testSession1t.id)
	require.NoError(t, err)
	assert.Equal(t, testSession5, testSession1)

	testSession6, err := SamlSessionManager.Decode(testSession3t.id)
	require.NoError(t, err)
	assert.Equal(t, testSession3, testSession6)

	err = SamlSessionManager.Logout(testSession1t.id)
	require.NoError(t, err)

	_, err = SamlSessionManager.Decode(testSession1t.id)
	assert.Error(t, err)

	_, err = SamlSessionManager.Decode("doesnotexist")
	assert.Error(t, err)
}

func TestSamlSessionTimeout(t *testing.T) {
	setupDB(t)
	db, err := sql.Open("pgx", testdb)
	require.NoError(t, err)
	defer db.Close()
	SamlSessionManager := SamlSessionEncoder{
		db:      db,
		timeout: 1,
	}

	testSamlAssertion := saml.Assertion{
		Subject: &saml.Subject{
			NameID: &saml.NameID{
				Value: "test",
			},
		},
		AuthnStatements: []saml.AuthnStatement{
			{
				AuthnContext: saml.AuthnContext{
					AuthnContextClassRef: &saml.AuthnContextClassRef{
						Value: "level1",
					},
				},
			},
		},
		AttributeStatements: []saml.AttributeStatement{
			{
				Attributes: []saml.Attribute{
					{
						Name: "A",
						Values: []saml.AttributeValue{
							{
								Value: "B",
							},
						},
					},
					{
						Name: "NameID",
						Values: []saml.AttributeValue{
							{
								Value: "blaat",
							},
						},
					},
				},
			},
		},
	}

	testSession1, err := SamlSessionManager.New(&testSamlAssertion)
	testSession1t := testSession1.(*SamlSession)
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"B"}, testSession1t.attributes["A"])
	assert.ElementsMatch(t, []string{"blaat", "test"}, testSession1t.attributes["NameID"])
	assert.ElementsMatch(t, []string{"level1"}, testSession1t.attributes["AuthnContextClassRef"])
	assert.Equal(t, testSession1t.attributes, testSession1t.GetAttributes())

	testSession2, err := SamlSessionManager.Decode(testSession1t.id)
	assert.NoError(t, err)
	assert.Equal(t, testSession1, testSession2)

	time.Sleep(time.Second * 30)
	testSession3, err := SamlSessionManager.Decode(testSession1t.id)
	assert.NoError(t, err)
	assert.Equal(t, testSession1, testSession3)

	time.Sleep(time.Second * 30)
	_, err = SamlSessionManager.Decode(testSession1t.id)
	assert.Error(t, err)
}

func TestIDCSessions(t *testing.T) {
	setupDB(t)
	db, err := sql.Open("pgx", testdb)
	require.NoError(t, err)
	defer db.Close()
	SessionManager := VerderHelpenSessionManager{
		db:      db,
		timeout: 15,
	}

	session1, err := SessionManager.NewSession("a", "b", nil)
	require.NoError(t, err)
	assert.Equal(t, "a", session1.attributes)
	assert.Equal(t, "b", session1.continuation)
	assert.Equal(t, (*string)(nil), session1.attributeURL)

	session2string := "f"
	session2, err := SessionManager.NewSession("d", "e", &session2string)
	require.NoError(t, err)
	assert.NotEqual(t, session1.id, session2.id)
	assert.Equal(t, "d", session2.attributes)
	assert.Equal(t, "e", session2.continuation)
	assert.Equal(t, "f", *session2.attributeURL)

	session3, err := SessionManager.GetSession(session1.id)
	require.NoError(t, err)
	assert.Equal(t, session1, session3)

	session4, err := SessionManager.GetSession(session2.id)
	require.NoError(t, err)
	assert.Equal(t, session2, session4)

	_, err = SessionManager.GetSession("doesnotexist")
	assert.Error(t, err)
}

func TestIDCSessionTimeout(t *testing.T) {
	setupDB(t)
	db, err := sql.Open("pgx", testdb)
	require.NoError(t, err)
	defer db.Close()
	SessionManager := VerderHelpenSessionManager{
		db:      db,
		timeout: 1,
	}

	session1, err := SessionManager.NewSession("a", "b", nil)
	require.NoError(t, err)
	assert.Equal(t, "a", session1.attributes)
	assert.Equal(t, "b", session1.continuation)
	assert.Equal(t, (*string)(nil), session1.attributeURL)

	session2, err := SessionManager.GetSession(session1.id)
	assert.NoError(t, err)
	assert.Equal(t, session1, session2)

	time.Sleep(time.Second * 30)

	session3, err := SessionManager.GetSession(session1.id)
	assert.NoError(t, err)
	assert.Equal(t, session1, session3)

	time.Sleep(time.Second * 35)

	_, err = SessionManager.GetSession(session1.id)
	assert.Error(t, err)
}

func TestSamlSessionVerderHelpenMapping(t *testing.T) {
	setupDB(t)
	db, err := sql.Open("pgx", testdb)
	require.NoError(t, err)
	defer db.Close()
	SessionManager := VerderHelpenSessionManager{
		db:      db,
		timeout: 1,
	}
	SamlSessionManager := SamlSessionEncoder{
		db:      db,
		timeout: 1,
	}

	testSamlAssertion := saml.Assertion{
		Subject: &saml.Subject{
			NameID: &saml.NameID{
				Value: "test",
			},
		},
		AuthnStatements: []saml.AuthnStatement{
			{
				AuthnContext: saml.AuthnContext{
					AuthnContextClassRef: &saml.AuthnContextClassRef{
						Value: "level1",
					},
				},
			},
		},
		AttributeStatements: []saml.AttributeStatement{
			{
				Attributes: []saml.Attribute{
					{
						Name: "A",
						Values: []saml.AttributeValue{
							{
								Value: "B",
							},
						},
					},
					{
						Name: "NameID",
						Values: []saml.AttributeValue{
							{
								Value: "blaat",
							},
						},
					},
				},
			},
		},
	}

	testSession1, err := SamlSessionManager.New(&testSamlAssertion)
	testSession1t := testSession1.(*SamlSession)
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"B"}, testSession1t.attributes["A"])
	assert.ElementsMatch(t, []string{"blaat", "test"}, testSession1t.attributes["NameID"])
	assert.ElementsMatch(t, []string{"level1"}, testSession1t.attributes["AuthnContextClassRef"])
	assert.Equal(t, testSession1t.attributes, testSession1t.GetAttributes())

	session1, err := SessionManager.NewSession("a", "b", nil)
	require.NoError(t, err)
	assert.Equal(t, "a", session1.attributes)
	assert.Equal(t, "b", session1.continuation)
	assert.Equal(t, (*string)(nil), session1.attributeURL)

	err = SamlSessionManager.SetVerderHelpenSession(testSession1t, session1.id, "testjwt")
	require.NoError(t, err)
	sessionid, jwt, err := SamlSessionManager.GetVerderHelpenSession(testSession1t)
	require.NoError(t, err)
	assert.Equal(t, session1.id, sessionid)
	assert.Equal(t, "testjwt", jwt)
}
