//go:build development

package main

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/url"
	"path"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/go-chi/chi/v5"
	"github.com/go-co-op/gocron"
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

// Start Verder Helpen authentication session
func (c *Configuration) startSession(w http.ResponseWriter, r *http.Request) {
	log.Debug("Starting session")
	// Extract request
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(500)
		log.Error(err)
		return
	}
	var request StartRequest
	err = json.Unmarshal(body, &request)
	if err != nil {
		w.WriteHeader(400)
		log.Warn(err)
		return
	}

	// Validate requested attributes
	for _, attribute := range request.Attributes {
		_, ok := c.AttributeMapping[attribute]
		if !ok {
			w.WriteHeader(400)
			log.Warn(err)
			return
		}
	}

	// Create a new session in the database
	encodedAttributes, err := json.Marshal(request.Attributes)
	if err != nil {
		w.WriteHeader(500)
		log.Error(err)
		return
	}
	session, err := c.SessionManager.NewSession(string(encodedAttributes), request.Continuation, request.AttributeURL)
	if err != nil {
		w.WriteHeader(500)
		log.Error(err)
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

// In development, don't create SAML sessions
func (c *Configuration) doLogin(w http.ResponseWriter, r *http.Request) {
	sessionid := chi.URLParam(r, "sessionid")

	confirmURL := *c.ServerURL
	confirmURL.Path = path.Join(confirmURL.Path, "confirm", sessionid)
	http.Redirect(w, r, confirmURL.String(), 302)
}

func (c *Configuration) getConfirm(w http.ResponseWriter, r *http.Request) {
	sessionid := chi.URLParam(r, "sessionid")

	attributes := map[string]string{
		"fullname": "Henk de Vries",
		"city":     "Nijmegen",
	}

	lang := c.Bundle.ParseAcceptLanguage(r.Header.Get("Accept-Language"))

	// translate the attribute keys to the appropriate language
	translatedAttributes := map[string]string{}
	for k, v := range attributes {
		// if the translation for the attribute key is not available, use the key itself
		translation := c.Bundle.Translate(lang, "attributes."+k)
		translatedAttributes[translation] = v
	}

	// And show the user the confirmation screen
	c.Template.ExecuteTemplate(w, "confirm", map[string]interface{}{
		"attributes": translatedAttributes,
		"language":   lang,
		"logoutPath": path.Join("/logout", sessionid),
	})
}

func (c *Configuration) doConfirm(w http.ResponseWriter, r *http.Request) {
	sessionid := chi.URLParam(r, "sessionid")
	attributes := map[string]string{
		"fullname": "Henk de Vries",
		"city":     "Nijmegen",
	}

	session, err := c.SessionManager.GetSession(sessionid)
	if err != nil {
		w.WriteHeader(400)
		log.Warn(err)
		return
	}

	logoutUrl := *c.InternalURL
	logoutUrl.Path = path.Join(logoutUrl.Path, "logout", sessionid)
	authToken, err := buildAttributeJWT(attributes, logoutUrl.String(), c.JwtSigningKey, c.JwtEncryptionKey)
	if err != nil {
		w.WriteHeader(500)
		log.Error(err)
		return
	}

	// And deliver it appropriately
	if session.attributeURL != nil {
		response, err := http.Post(*session.attributeURL, "application/jwt", bytes.NewReader([]byte(authToken)))
		if err != nil {
			// Just log
			log.Error(err)
		} else {
			defer response.Body.Close()
			if response.StatusCode >= 300 {
				log.Errorf("attribute url failed (%d)\n", response.StatusCode)
			}
		}
		http.Redirect(w, r, session.continuation, 302)
	} else {
		redirectURL, err := url.Parse(session.continuation)
		if err != nil {
			w.WriteHeader(500)
			log.Error(err)
			return
		}
		redirectQuery := redirectURL.Query()
		redirectQuery.Set("result", string(authToken))
		redirectURL.RawQuery = redirectQuery.Encode()
		http.Redirect(w, r, redirectURL.String(), 302)
	}
}

func (c *Configuration) doLogout(w http.ResponseWriter, r *http.Request) {
	sessionid := chi.URLParam(r, "sessionid")

	// get Verder Helpen session exists
	session, err := c.SessionManager.GetSession(sessionid)
	if err != nil {
		w.WriteHeader(400)
		log.Warn(err)
		return
	}

	// get continuation URL before actually logging out
	redirectURL, err := url.Parse(session.continuation)
	if err != nil {
		w.WriteHeader(500)
		log.Error(err)
		return
	}

	// redirect to redirect URL without result
	http.Redirect(w, r, redirectURL.String(), 302)
}

func (c *Configuration) BuildHandler() http.Handler {
	// Construct router
	r := chi.NewRouter()

	r.Route("/", func(r chi.Router) {
		r.Get("/session/{sessionid}", c.doLogin)
		r.Get("/confirm/{sessionid}", c.getConfirm)
		r.Post("/confirm/{sessionid}", c.doConfirm)
		r.Post("/logout/{sessionid}", c.doLogout)
	})

	r.Route("/internal", func(r chi.Router) {
		r.Post("/start_authentication", c.startSession)
	})

	return r
}

var release string

func main() {
	configuration := ParseConfiguration()

	s := gocron.NewScheduler(time.UTC)
	s.Every("1m").Do(func() {
		configuration.SessionManager.Cleanup()
	})
	s.StartAsync()

	http.Handle("/", configuration.BuildHandler())
	http.ListenAndServe(":8000", nil)
}
