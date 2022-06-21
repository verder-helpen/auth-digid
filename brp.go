package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
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
func GetBRPAttributes(brpserver, bsn string, attributes map[string]string, clientCert tls.Certificate, caCerts []byte) (map[string]string, error) {
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCerts)

	// Setup client for mTLS
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:      caCertPool,
				Certificates: []tls.Certificate{clientCert},
			},
		},
	}

	// Do the network request to the BRP server
	request, err := json.Marshal(map[string]string{"bsn": bsn})
	if err != nil {
		return nil, err
	}
	response, err := client.Post(brpserver, "application/json", bytes.NewReader(request))
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode >= 300 {
		return nil, errors.New(fmt.Sprintf("Unexpected response from BRP server %d", response.StatusCode))
	}

	// Extract attributes from response
	body, err := ioutil.ReadAll(response.Body)
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
