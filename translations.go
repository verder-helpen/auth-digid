package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"regexp"
	"strings"
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

func (t *Translations) Load(language string, filename string) error {
	file, err := os.Open(filename)
	if err != nil {
		return fmt.Errorf("Cannot open %s", filename)
	}
	defer file.Close()

	bytes, err := ioutil.ReadAll(file)
	if err != nil {
		return fmt.Errorf("Cannot read %s", filename)
	}

	var lang_map map[string]interface{}
	json.Unmarshal(bytes, &lang_map)

	t.data[language] = lang_map
	return nil
}

func (t *Translations) SetFallback(language string) error {
	if _, ok := t.data[language]; ok {
		t.fallback = language
		return nil
	}

	// if language not in data, we cannot use it as a fallback
	return fmt.Errorf("Language %s not in loaded languages", language)
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
	}

	return "", false
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

func (t *Translations) ParseAcceptLanguage(acceptLanguageHeader string) string {
	// regexp to match language in accept language ignoring weights
	re := regexp.MustCompile(`([\w-*]+)\s*(?:;\s*q\s*=\s*[0-9.]+)?`)
	match := re.FindAllStringSubmatch(acceptLanguageHeader, -1)

	for _, group := range match {
		if _, ok := t.data[group[1]]; ok {
			// if language in data, return it
			return group[1]
		}
	}

	// if language is not available, use default
	return t.fallback
}
