package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
	jwtkeys "github.com/dgrijalva/jwt-go/v4"
	"github.com/go-chi/chi/v5"
	_ "github.com/jackc/pgx/v4/stdlib"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwe"
	"github.com/lestrrat-go/jwx/jwt"
	"github.com/spf13/viper"
)

type Configuration struct {
	SamlKeyPair    tls.Certificate
	IdpMetadataURL *url.URL

	JwtSigningKey    *rsa.PrivateKey
	JwtEncryptionKey *rsa.PublicKey

	ServerURL          *url.URL
	SessionManager     *IDContactSessionManager
	DatabaseConnection string
	AttributeMapping   map[string]string
}

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

	encodedAttributes, err := json.Marshal(attributes)
	if err != nil {
		return nil, err
	}

	_, err = s.db.Exec("INSERT INTO saml_session (sessionid, attributes) VALUES ($0, $1)", id, string(encodedAttributes))
	if err != nil {
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
	rows, err := s.db.Query("SELECT attributes FROM saml_session WHERE session_id = $0", id)
	if err != nil {
		return nil, err
	}

	defer rows.Close()
	if !rows.Next() {
		return nil, samlsp.ErrNoSession
	}
	var encodedAttributes string
	err = rows.Scan(&encodedAttributes)
	if err != nil {
		return nil, err
	}

	var attributes samlsp.Attributes
	err = json.Unmarshal([]byte(encodedAttributes), &attributes)
	if err != nil {
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
	_, err := m.db.Exec("INSERT INTO idcontact_session (sessionid, attributes, continuation, attr_url) VALUES ($0, $1, $2, $3)", id, attributes, continuation, attributeURL)
	if err != nil {
		return nil, err
	}

	return &IDContactSession{
		id:           id,
		continuation: continuation,
		attributeURL: attributeURL,
	}, nil
}

func (m *IDContactSessionManager) GetSession(id string) (*IDContactSession, error) {
	rows, err := m.db.Query("SELECT attributes, continuation, attr_url FROM idcontact_session WHERE sessionid = $0", id)
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

func ParseConfiguration() Configuration {
	// Setup configuration sources
	viper.SetConfigFile("config.json")
	viper.SetConfigType("json")
	viper.AddConfigPath(".")
	viper.SetEnvPrefix("DIGID")
	viper.AutomaticEnv()
	err := viper.ReadInConfig() // Find and read the config file
	if err != nil {             // Handle errors reading the config file
		panic(fmt.Errorf("Fatal error config file: %s \n", err))
	}

	// Load saml configuration
	samlCertificate := viper.GetString("SamlCertificate")
	samlKey := viper.GetString("SamlKey")
	keypair, err := tls.LoadX509KeyPair(samlCertificate, samlKey)
	if err != nil {
		fmt.Println("Failed to read saml keypair")
		panic(err)
	}
	keypair.Leaf, err = x509.ParseCertificate(keypair.Certificate[0])
	if err != nil {
		fmt.Println("Failed to parse leaf certificate")
		panic(err)
	}

	rawIdpURL := viper.GetString("IDPMetadataURL")
	idpMetadataURL, err := url.Parse(rawIdpURL)
	if err != nil {
		fmt.Println("Invalid identity provider metadata url")
		panic(err)
	}

	// Load encryption keys
	jwtSigningKeyFile := viper.GetString("JWTSigningKey")
	jwtSigningKeyPEM, err := ioutil.ReadFile(jwtSigningKeyFile)
	if err != nil {
		fmt.Println("Failed to read jwt siging key")
		panic(err)
	}
	jwtSigningKey, err := jwtkeys.ParseRSAPrivateKeyFromPEM(jwtSigningKeyPEM)
	if err != nil {
		fmt.Println("Failed to parse jwt signing key")
		panic(err)
	}

	jwtEncryptionKeyFile := viper.GetString("JWTEncryptionKey")
	jwtEncryptionKeyPEM, err := ioutil.ReadFile(jwtEncryptionKeyFile)
	if err != nil {
		fmt.Println("Failed to read jwt encryption key")
		panic(err)
	}
	jwtEncryptionKey, err := jwtkeys.ParseRSAPublicKeyFromPEM(jwtEncryptionKeyPEM)

	// General server data
	rawServerURL := viper.GetString("ServerURL")
	serverURL, err := url.Parse(rawServerURL)
	databaseConnection := viper.GetString("DatabaseConnection")
	db, err := sql.Open("pgx", databaseConnection)
	if err != nil {
		fmt.Println("Couldn't open database")
		panic(err)
	}

	return Configuration{
		SamlKeyPair:    keypair,
		IdpMetadataURL: idpMetadataURL,

		JwtSigningKey:    jwtSigningKey,
		JwtEncryptionKey: jwtEncryptionKey,

		ServerURL:          serverURL,
		DatabaseConnection: databaseConnection,
		SessionManager: &IDContactSessionManager{
			db: db,
		},
		AttributeMapping: viper.GetStringMapString("AttributeMapping"),
	}
}

type StartRequest struct {
	Attributes   []string `json:"attributes"`
	Continuation string   `json:"continuation"`
	AttributeURL *string  `json:"attr_url"`
}

type StartResponse struct {
	ClientURL string `json:"client_url"`
}

func (c *Configuration) startSession(w http.ResponseWriter, r *http.Request) {
	// Extract request
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(500)
		fmt.Println(err)
		return
	}
	var request StartRequest
	err = json.Unmarshal(body, &request)
	if err != nil {
		w.WriteHeader(400)
		fmt.Println(err)
		return
	}
	for _, attribute := range request.Attributes {
		_, ok := c.AttributeMapping[attribute]
		if !ok {
			w.WriteHeader(400)
			fmt.Println(err)
			return
		}
	}
	encodedAttributes, err := json.Marshal(request.Attributes)
	if err != nil {
		w.WriteHeader(500)
		fmt.Println(err)
		return
	}

	session, err := c.SessionManager.NewSession(string(encodedAttributes), request.Continuation, request.AttributeURL)
	clientURL := *c.ServerURL
	clientURL.Path = path.Join(clientURL.Path, "session", session.id)
	response, err := json.Marshal(StartResponse{ClientURL: clientURL.String()})
	w.WriteHeader(200)
	w.Write(response)
}

type AuthResult struct {
	status     string
	attributes map[string]string
}

func (c *Configuration) doLogin(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "sessionid")
	session, err := c.SessionManager.GetSession(id)
	if err != nil {
		w.WriteHeader(400)
		fmt.Println(err)
		return
	}

	var attributes []string
	err = json.Unmarshal([]byte(session.attributes), &attributes)
	if err != nil {
		w.WriteHeader(500)
		fmt.Println(err)
		return
	}

	attributeResult := make(map[string]string)

	for _, attribute := range attributes {
		attributeResult[attribute] = samlsp.AttributeFromContext(r.Context(), c.AttributeMapping[attribute])
	}

	token := jwt.New()
	token.Set(jwt.SubjectKey, "id-contact-attributes")
	token.Set(jwt.IssuedAtKey, time.Now())
	token.Set(jwt.ExpirationKey, time.Now().Add(time.Minute*15))
	token.Set("status", "succes")
	token.Set("attibutes", attributeResult)
	signed, err := jwt.Sign(token, jwa.RS256, c.JwtSigningKey)
	if err != nil {
		w.WriteHeader(500)
		fmt.Println(err)
		return
	}
	outer := make(map[string]string)
	outer["njwt"] = string(signed)
	outerJSON, err := json.Marshal(outer)
	if err != nil {
		w.WriteHeader(500)
		fmt.Println(err)
		return
	}
	outerEncoded := make([]byte, base64.URLEncoding.EncodedLen(len(outerJSON)))
	base64.URLEncoding.Encode(outerEncoded, outerJSON)
	authToken, err := jwe.Encrypt(outerEncoded, jwa.RSA1_5, c.JwtEncryptionKey, jwa.A128CBC_HS256, jwa.NoCompress)
	if err != nil {
		w.WriteHeader(500)
		fmt.Println(err)
		return
	}
	if session.attributeURL != nil {
		http.Post(*session.attributeURL, "application/jwt", bytes.NewReader(authToken))
		http.Redirect(w, r, session.continuation, 302)
	} else {
		var redirectURL string
		if strings.Contains(session.continuation, "?") {
			redirectURL = fmt.Sprintf("%s&result=%s", session.continuation, string(authToken))
		} else {
			redirectURL = fmt.Sprintf("%s&result=%s", session.continuation, string(authToken))
		}
		http.Redirect(w, r, redirectURL, 302)
	}
}

func (c *Configuration) BuildHandler() http.Handler {
	r := chi.NewRouter()

	idpMetadata, err := samlsp.FetchMetadata(context.Background(), http.DefaultClient,
		*c.IdpMetadataURL)
	if err != nil {
		fmt.Println("Failed to download IdP metadata.")
		panic(err)
	}

	db, err := sql.Open("pgx", c.DatabaseConnection)
	if err != nil {
		fmt.Println("Couldn't open database")
		panic(err)
	}

	samlSP, err := samlsp.New(samlsp.Options{
		URL:         *c.ServerURL,
		Key:         c.SamlKeyPair.PrivateKey.(*rsa.PrivateKey),
		Certificate: c.SamlKeyPair.Leaf,
		IDPMetadata: idpMetadata,
	})
	samlSP.Session = &samlsp.CookieSessionProvider{
		Name:     "samlsession",
		Domain:   c.ServerURL.Host,
		HTTPOnly: true,
		Secure:   c.ServerURL.Scheme == "https",
		MaxAge:   60 * time.Minute,
		Codec: &SamlSessionEncoder{
			db: db,
		},
	}

	r.Group(func(r chi.Router) {
		r.Use(samlSP.RequireAccount)
		r.Get("/session/{sessionid}", c.doLogin)
	})

	r.Post("/start_authentication", c.startSession)
	r.Mount("/saml/", samlSP)

	return r
}

func main() {
	configuration := ParseConfiguration()
	http.Handle("/", configuration.BuildHandler())
	http.ListenAndServe(":8000", nil)
}
