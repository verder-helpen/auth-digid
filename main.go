package main

import (
	"bytes"
	"context"
	"crypto/rsa"
	"database/sql"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"path"
	"time"

	"github.com/crewjam/saml/samlsp"
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

	// Extract attributes from SAML Assertions:
	attributeResult := make(map[string]string)

	for _, attribute := range attributes {
		attributeResult[attribute] = samlsp.AttributeFromContext(r.Context(), c.AttributeMapping[attribute])
	}

	// Construct authentication result JWT
	authToken, err := buildAttributeJWT(attributeResult, c.JwtSigningKey, c.JwtEncryptionKey)
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

func (c *Configuration) BuildHandler() http.Handler {
	// Setup SAML plugin
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
		EntityID:            c.EntityID,
		URL:                 *c.ServerURL,
		Key:                 c.SamlKeyPair.PrivateKey.(*rsa.PrivateKey),
		Certificate:         c.SamlKeyPair.Leaf,
		IDPMetadata:         idpMetadata,
		UseArtifactResponse: true,
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

	// Construct router
	r := chi.NewRouter()

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
