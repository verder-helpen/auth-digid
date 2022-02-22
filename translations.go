package main

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"strings"

	log "github.com/sirupsen/logrus"
)

type Translations struct {
	data     map[string]map[string]interface{}
	fallback string
}

func NewTranslations() Translations {
	return Translations{
		data: make(map[string]map[string]interface{}),
	}
}

func (t *Translations) Load(language string, filename string) {
	file, err := os.Open(filename)
	if err != nil {
		log.Fatal("Cannot open {}", filename)
	}
	defer file.Close()

	bytes, err := ioutil.ReadAll(file)
	if err != nil {
		log.Fatal("Cannot read {}", filename)
	}

	var lang_map map[string]interface{}
	json.Unmarshal(bytes, &lang_map)

	t.data[language] = lang_map
}

func (t *Translations) SetFallback(language string) {
	t.fallback = language
}

func internalLookupKeyInNestedMap(id string, data interface{}) (string, bool) {
	keys := strings.Split(id, ".")

	// Traverse tree
	for _, key := range keys {
		mdat, ok := data.(map[string]interface{})
		if !ok {
			return "", false
		}
		data, ok = mdat[key]
		if !ok {
			return "", false
		}
	}

	if output, ok := data.(string); ok {
		return output, true
	} else {
		return "", false
	}
}

func (t *Translations) Translate(language string, id string) string {
	// Lookup in current language
	if lang_map, ok := t.data[language]; ok {
		output, ok := internalLookupKeyInNestedMap(id, lang_map)
		if ok {
			return output
		}
	}

	// if not found, lookup in fallback language
	if fallback_map, ok := t.data[t.fallback]; ok {
		output, ok := internalLookupKeyInNestedMap(id, fallback_map)
		if ok {
			return output
		}
	}

	// if not found, return id
	return id
}
