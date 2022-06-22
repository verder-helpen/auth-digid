package main

import (
	"io"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestWalkAttributeTree(t *testing.T) {
	testStructure := map[string]interface{}{
		"a": "b",
		"c": map[string]interface{}{
			"d": "e",
		},
	}

	res, err := walkAttributeTree("a", testStructure)
	assert.NoError(t, err)
	assert.Equal(t, "b", res)

	_, err = walkAttributeTree("c", testStructure)
	assert.Error(t, err)

	_, err = walkAttributeTree("a.b", testStructure)
	assert.Error(t, err)

	res, err = walkAttributeTree("c.d", testStructure)
	assert.NoError(t, err)
	assert.Equal(t, "e", res)

	_, err = walkAttributeTree("c.f", testStructure)
	assert.Error(t, err)

	_, err = walkAttributeTree("g", testStructure)
	assert.Error(t, err)
}

func TestFullLookup(t *testing.T) {
	server := http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// TODO verify the X-API-KEY header
			b, err := io.ReadAll(r.Body)
			assert.NoError(t, err)
			assert.Equal(t, []byte(`{"burgerservicenummer":["123456789"],"fields":"a,c.d","type":"RaadpleegMetBurgerservicenummer"}`), b)
			w.Write([]byte(`
{
	"a": "b",
	"c": {
		"d":"e"
	}
}
`))
		}),
		Addr: ":27349",
	}

	go func() {
		server.ListenAndServe()
	}()

	defer server.Close()

	attributes, err := GetBRPAttributes("http://localhost:27349", "123456789", map[string]string{"test1": "a", "test2": "c.d"}, "apikey123")
	assert.NoError(t, err)
	assert.Equal(t, map[string]string{"test1": "b", "test2": "e"}, attributes)
}
