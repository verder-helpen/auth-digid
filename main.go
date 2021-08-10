package main

import (
	"bytes"
	"context"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"path"
	"time"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
	"github.com/getsentry/sentry-go"
	sentryhttp "github.com/getsentry/sentry-go/http"
	"github.com/go-chi/chi/v5"
	_ "github.com/jackc/pgx/v4/stdlib"
)

type StartRequest struct {
	Attributes   []string `json:"attributes"`
	Continuation string   `json:"continuation"`
	AttributeURL *string  `json:"attr_url"`
}

type StartResponse struct {
	ClientURL string `json:"client_url"`
}

// Start ID Contact authentication session
func (c *Configuration) startSession(w http.ResponseWriter, r *http.Request) {
	fmt.Println("Starting session")
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

	// Validate requested attributes
	for _, attribute := range request.Attributes {
		_, ok := c.AttributeMapping[attribute]
		if !ok {
			w.WriteHeader(400)
			fmt.Println(err)
			return
		}
	}

	// Create a new session in the database
	encodedAttributes, err := json.Marshal(request.Attributes)
	if err != nil {
		w.WriteHeader(500)
		fmt.Println(err)
		return
	}
	session, err := c.SessionManager.NewSession(string(encodedAttributes), request.Continuation, request.AttributeURL)
	if err != nil {
		w.WriteHeader(500)
		fmt.Println(err)
		return
	}

	// And instruct the core appropriately
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

// Handle an actual end-user login
func (c *Configuration) doLogin(w http.ResponseWriter, r *http.Request) {
	// Fetch corresponding ID Contact session
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

	// Extract attributes from BRP:
	samlsession := samlsp.SessionFromContext(r.Context()).(*SamlSession)
	bsn := samlsession.attributes.Get("NameID")
	if bsn[:9] != "s00000000" {
		w.WriteHeader(500)
		fmt.Println("Unexpected sectoral code", bsn[:9])
		return
	}
	altbsn, ok := c.TestBSNMapping[bsn[10:]]
	if ok {
		bsn = "s00000000:" + altbsn
	}
	attributeResult, err := GetBRPAttributes(c.BRPServer, bsn[10:], c.AttributeMapping, c.Client, c.CaCerts)
	if err != nil {
		w.WriteHeader(500)
		fmt.Println(err)
		return
	}

	// Construct authentication result JWT
	logoutUrl := *c.ServerURL
	logoutUrl.Path = path.Join(logoutUrl.Path, "update", samlsession.logoutid)
	authToken, err := buildAttributeJWT(attributeResult, logoutUrl.String(), c.JwtSigningKey, c.JwtEncryptionKey)
	if err != nil {
		w.WriteHeader(500)
		fmt.Println(err)
		return
	}

	// And deliver it appropriately
	if session.attributeURL != nil {
		response, err := http.Post(*session.attributeURL, "application/jwt", bytes.NewReader(authToken))
		if err != nil {
			// Just log
			fmt.Println(err)
		} else {
			defer response.Body.Close()
			if response.StatusCode >= 300 {
				fmt.Printf("attribute url failed (%d)\n", response.StatusCode)
			}
		}
		http.Redirect(w, r, session.continuation, 302)
	} else {
		redirectURL, err := url.Parse(session.continuation)
		if err != nil {
			w.WriteHeader(500)
			fmt.Println(err)
			return
		}
		redirectURL.Query().Set("result", string(authToken))
		http.Redirect(w, r, redirectURL.String(), 302)
	}
}

// Handle update on session from communication plugin.
func (c *Configuration) SessionUpdate(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		fmt.Println(err)
		w.WriteHeader(400)
		return
	}

	updateType := r.FormValue("type")
	if updateType == "logout" {
		// Handle logout request
		err = c.SamlSessionManager.Logout(chi.URLParam(r, "logoutid"))
		if err != nil {
			fmt.Println("Logout failed: ", err)
			// Note, this error shouldn't be propagated to remote
		}
	} else {
		fmt.Println("Unrecognized update type ", updateType)
	}

	w.WriteHeader(204)
}

func (c *Configuration) BuildHandler() http.Handler {
	// Setup SAML plugin
	idpMetadata, err := samlsp.FetchMetadata(context.Background(), http.DefaultClient,
		*c.IdpMetadataURL)
	if err != nil {
		fmt.Println("Failed to download IdP metadata.")
		panic(err)
	}

	samlSP, err := samlsp.New(samlsp.Options{
		EntityID:             c.EntityID,
		URL:                  *c.ServerURL,
		Key:                  c.SamlKeyPair.PrivateKey.(*rsa.PrivateKey),
		Certificate:          c.SamlKeyPair.Leaf,
		TLSClientCertificate: &c.SamlKeyPair,
		IDPMetadata:          idpMetadata,
		SignRequest:          true,
		UseArtifactResponse:  true,
		RequestedAuthnContext: &saml.RequestedAuthnContext{
			Comparison:           "minimum",
			AuthnContextClassRef: "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
		},
	})
	samlSP.Session = &samlsp.CookieSessionProvider{
		Name:     "samlsession",
		Domain:   c.ServerURL.Host,
		HTTPOnly: true,
		Secure:   c.ServerURL.Scheme == "https",
		MaxAge:   60 * time.Minute,
		Codec:    c.SamlSessionManager,
	}

	// Construct router
	r := chi.NewRouter()
	if c.SentryDSN != "" {
		sentryMiddleware := sentryhttp.New(sentryhttp.Options{})
		r.Use(sentryMiddleware.Handle)
	}

	r.Group(func(r chi.Router) {
		r.Use(samlSP.RequireAccount)
		r.Get("/session/{sessionid}", c.doLogin)
	})

	r.Post("/start_authentication", c.startSession)
	r.Post("/update/{logoutid}", c.SessionUpdate)
	r.Mount("/saml/", samlSP)

	return r
}

var release string

func main() {
	configuration := ParseConfiguration()
	if configuration.SentryDSN != "" {
		err := sentry.Init(sentry.ClientOptions{
			Dsn:         configuration.SentryDSN,
			Release:     release,
			Environment: configuration.ServerURL.String(),
		})
		if err != nil {
			fmt.Println("Error starting sentry")
			panic(err)
		}
		defer sentry.Recover()
	}
	http.Handle("/", configuration.BuildHandler())
	http.ListenAndServe(":8000", nil)
}
