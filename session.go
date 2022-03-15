package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"

	log "github.com/sirupsen/logrus"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
)

const (
	passwordProtectedTransport = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
	mobileTwoFactorContract    = "urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorContract"
	smartcard                  = "urn:oasis:names:tc:SAML:2.0:ac:classes:Smartcard"
	smartcardPKI               = "urn:oasis:names:tc:SAML:2.0:ac:classes:SmartcardPKI"
)

var digidAuthnContextClasses = map[string]string{
	"Basis":        passwordProtectedTransport,
	"Midden":       mobileTwoFactorContract,
	"Substantieel": smartcard,
	"Hoog":         smartcardPKI,
}

var authnContextClasses = map[string]int{
	passwordProtectedTransport: 1,
	mobileTwoFactorContract:    2,
	smartcard:                  3,
	smartcardPKI:               4,
}

func CompareAuthnContextClass(minimum string, acc string) bool {
	return authnContextClasses[minimum] <= authnContextClasses[acc]
}

var chars = []rune("0123456789abcdefghkmnpqrstuvwxyz")

const ID_LENGTH = 20

func GenerateID() string {
	bytes := make([]byte, ID_LENGTH)
	_, err := rand.Read(bytes)
	if err != nil {
		log.Fatal(err)
	}
	result := make([]rune, ID_LENGTH)
	for i := 0; i < ID_LENGTH; i++ {
		result[i] = chars[int(bytes[i]&0x1f)]
	}
	return string(result)
}

type SamlSessionEncoder struct {
	db      *sql.DB
	timeout int // timeout time in minutes
}

type SamlSession struct {
	id         string
	attributes samlsp.Attributes
}

func (s *SamlSessionEncoder) New(assertion *saml.Assertion) (samlsp.Session, error) {
	// Setup data
	id := GenerateID()
	attributes := make(samlsp.Attributes)
	for _, statement := range assertion.AttributeStatements {
		for _, attribute := range statement.Attributes {
			for _, value := range attribute.Values {
				attributes[attribute.Name] = append(attributes[attribute.Name], value.Value)
			}
		}
	}

	if assertion.Subject != nil {
		if assertion.Subject.NameID != nil {
			attributes["NameID"] = append(attributes["NameID"], assertion.Subject.NameID.Value)
		}
	}

	for _, authnStatement := range assertion.AuthnStatements {
		if authnStatement.AuthnContext.AuthnContextClassRef != nil {
			attributes["AuthnContextClassRef"] = append(attributes["AuthnContextClassRef"], authnStatement.AuthnContext.AuthnContextClassRef.Value)
		}
	}

	encodedAttributes, err := json.Marshal(attributes)
	if err != nil {
		log.Error(err)
		return nil, err
	}

	_, err = s.db.Exec("INSERT INTO saml_session (sessionid, attributes, expiry) VALUES ($1, $2, $3, NOW() + ($4 * Interval '1 minute'))", id, string(encodedAttributes), s.timeout)
	if err != nil {
		log.Error(err)
		return nil, err
	}

	return &SamlSession{
		id:         id,
		attributes: attributes,
	}, nil
}

func (s *SamlSessionEncoder) Encode(session samlsp.Session) (string, error) {
	return session.(*SamlSession).id, nil
}

func (s *SamlSessionEncoder) Decode(id string) (samlsp.Session, error) {
	rows, err := s.db.Query("SELECT attributes FROM saml_session WHERE sessionid = $1 AND expiry > NOW()", id)
	if err != nil {
		log.Error(err)
		return nil, err
	}

	defer rows.Close()
	if !rows.Next() {
		return nil, samlsp.ErrNoSession
	}
	var encodedAttributes string
	err = rows.Scan(&encodedAttributes)
	if err != nil {
		log.Error(err)
		return nil, err
	}

	var attributes samlsp.Attributes
	err = json.Unmarshal([]byte(encodedAttributes), &attributes)
	if err != nil {
		log.Error(err)
		return nil, err
	}

	return &SamlSession{
		id:         id,
		attributes: attributes,
	}, nil
}

func (s *SamlSessionEncoder) SetIDContactSession(session *SamlSession, id_contact_session string, session_attributes string) error {
	result, err := s.db.Exec("UPDATE saml_session SET idcontact_session_id = (SELECT id FROM idcontact_session WHERE sessionid=$2), session_attributes = $3 WHERE sessionid = $1", session.id, id_contact_session, session_attributes)
	if err != nil {
		log.Error(err)
		return err
	}
	aff, err := result.RowsAffected()
	if err != nil {
		log.Error(err)
		return err
	}
	if aff != 1 {
		return samlsp.ErrNoSession
	}
	return nil
}

func (s *SamlSessionEncoder) GetIDContactSession(session *SamlSession) (string, string, error) {
	rows, err := s.db.Query("SELECT idcontact_session.sessionid, session_attributes FROM saml_session INNER JOIN idcontact_session ON saml_session.idcontact_session_id = idcontact_session.id")
	if err != nil {
		log.Error(err)
		return "", "", err
	}

	defer rows.Close()
	if !rows.Next() {
		return "", "", samlsp.ErrNoSession
	}

	var sessionid, session_attributes string
	err = rows.Scan(&sessionid, &session_attributes)
	if err != nil {
		log.Error(err)
		return "", "", err
	}

	return sessionid, session_attributes, nil
}

func (s *SamlSessionEncoder) Logout(sessionid string) error {
	result, err := s.db.Exec("DELETE FROM saml_session WHERE sessionid = $1", sessionid)
	if err != nil {
		log.Error(err)
		return err
	}
	aff, err := result.RowsAffected()
	if err != nil {
		log.Error(err)
		return err
	}
	if aff != 1 {
		return samlsp.ErrNoSession
	}
	return nil
}

func (s *SamlSessionEncoder) Cleanup() error {
	_, err := s.db.Exec("DELETE FROM saml_session WHERE expiry < NOW() - Interval '1 minute'")
	return err
}

func (s *SamlSession) GetAttributes() samlsp.Attributes {
	return s.attributes
}

type IDContactSessionManager struct {
	db      *sql.DB
	timeout int // session timeout in minutes
}

type IDContactSession struct {
	id           string
	attributes   string
	continuation string
	attributeURL *string
}

func (m *IDContactSessionManager) NewSession(attributes, continuation string, attributeURL *string) (*IDContactSession, error) {
	id := GenerateID()
	_, err := m.db.Exec("INSERT INTO idcontact_session (sessionid, attributes, continuation, attr_url, expiry) VALUES ($1, $2, $3, $4, NOW() + ($5 * Interval '1 minute'))", id, attributes, continuation, attributeURL, m.timeout)
	if err != nil {
		return nil, err
	}

	return &IDContactSession{
		id:           id,
		attributes:   attributes,
		continuation: continuation,
		attributeURL: attributeURL,
	}, nil
}

func (m *IDContactSessionManager) GetSession(id string) (*IDContactSession, error) {
	rows, err := m.db.Query("SELECT attributes, continuation, attr_url FROM idcontact_session WHERE sessionid = $1 AND expiry > NOW()", id)
	if err != nil {
		return nil, err
	}

	defer rows.Close()
	if !rows.Next() {
		return nil, errors.New("No Session")
	}
	var attributes string
	var continuation string
	var attributeURL *string
	err = rows.Scan(&attributes, &continuation, &attributeURL)
	if err != nil {
		return nil, err
	}

	return &IDContactSession{
		id:           id,
		attributes:   attributes,
		continuation: continuation,
		attributeURL: attributeURL,
	}, nil
}

func (m *IDContactSessionManager) Cleanup() error {
	_, err := m.db.Exec("DELETE FROM idcontact_session WHERE expiry < NOW() - Interval '1 minute'")
	return err
}
