package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
)

// Walk through the chain of maps reconstructed from the json to fetch the requested attribute
func walkAttributeTree(attribute string, tree interface{}) (string, error) {
	parts := strings.Split(attribute, ".")
	cur := tree
	for _, part := range parts {
		curMap, ok := cur.(map[string]interface{})
		if !ok {
			return "", errors.New(fmt.Sprintf("Attribute %s not found", attribute))
		}
		cur, ok = curMap[part]
		if !ok {
			return "", errors.New(fmt.Sprintf("Attribute %s not found", attribute))
		}
	}

	value, ok := cur.(string)
	if !ok {
		return "", errors.New(fmt.Sprintf("Attribute %s not found", attribute))
	}
	return value, nil
}

// Get the desired attributes from the BRP data associated with a BSN
func GetBRPAttributes(brpserver, bsn string, attributes map[string]string, apiKey string) (map[string]string, error) {
	// Setup client for mTLS
	client := &http.Client{}

	// Do the network request to the BRP server

	// v2.0 of HaalCentraal expects a comma-separated string, in v2.1 this will be an array of strings
	attributesStr := ""
	for _, value := range attributes {
		attributesStr += value + ","
	}
	attributesStr = attributesStr[:len(attributesStr)-1] // chop off the last comma

	body, err := json.Marshal(map[string]interface{}{
		"type":                "RaadpleegMetBurgerservicenummer",
		"burgerservicenummer": [1]string{bsn},
		"fields":              attributesStr,
	})
	if err != nil {
		return nil, err
	}

	request, err := http.NewRequest("POST", brpserver, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}

	// request.Header.Set("Content-Type", "application/json")
	// request.Header.Add("X-API-KEY", apiKey)

	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}

	defer response.Body.Close()
	if response.StatusCode >= 300 {
		return nil, errors.New(fmt.Sprintf("Unexpected response from BRP server %d", response.StatusCode))
	}

	// Extract attributes from response
	body, err = ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}

	var brpData interface{}
	err = json.Unmarshal(body, &brpData)
	if err != nil {
		return nil, err
	}

	result := make(map[string]string)
	for attribute, location := range attributes {
		value, err := walkAttributeTree(location, brpData)
		if err != nil {
			return nil, err
		}
		result[attribute] = value
	}
	return result, nil
}
