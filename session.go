package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
)

var chars = []rune("0123456789abcdefghkmnpqrstuvwxyz")

const ID_LENGTH = 20

func GenerateID() string {
	bytes := make([]byte, ID_LENGTH)
	_, err := rand.Read(bytes)
	if err != nil {
		panic(err)
	}
	result := make([]rune, ID_LENGTH)
	for i := 0; i < ID_LENGTH; i++ {
		result[i] = chars[int(bytes[i]&0x1f)]
	}
	return string(result)
}

type SamlSessionEncoder struct {
	db *sql.DB
}

type SamlSession struct {
	attributes samlsp.Attributes
	id         string
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
		fmt.Println(err)
		return nil, err
	}

	_, err = s.db.Exec("INSERT INTO saml_session (sessionid, attributes) VALUES ($1, $2)", id, string(encodedAttributes))
	if err != nil {
		fmt.Println(err)
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
	rows, err := s.db.Query("SELECT attributes FROM saml_session WHERE sessionid = $1", id)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	defer rows.Close()
	if !rows.Next() {
		return nil, samlsp.ErrNoSession
	}
	var encodedAttributes string
	err = rows.Scan(&encodedAttributes)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	var attributes samlsp.Attributes
	err = json.Unmarshal([]byte(encodedAttributes), &attributes)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	return &SamlSession{
		id:         id,
		attributes: attributes,
	}, nil
}

func (s *SamlSession) GetAttributes() samlsp.Attributes {
	return s.attributes
}

type IDContactSessionManager struct {
	db *sql.DB
}

type IDContactSession struct {
	id           string
	attributes   string
	continuation string
	attributeURL *string
}

func (m *IDContactSessionManager) NewSession(attributes, continuation string, attributeURL *string) (*IDContactSession, error) {
	id := GenerateID()
	_, err := m.db.Exec("INSERT INTO idcontact_session (sessionid, attributes, continuation, attr_url) VALUES ($1, $2, $3, $4)", id, attributes, continuation, attributeURL)
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
	rows, err := m.db.Query("SELECT attributes, continuation, attr_url FROM idcontact_session WHERE sessionid = $1", id)
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
