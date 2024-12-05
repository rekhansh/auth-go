package main

import (
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAuthApis(t *testing.T) {
	// 1. Init Server
	router := setupRouter()
	server := httptest.NewServer(router)
	defer server.Close()
	log.Printf("running server: %v", server.URL)

	// 2. Test Ping
	t.Run("Test Ping", func(t *testing.T) {
		resp, err := checkRequest(server.Client(), server.URL+"/ping", "")
		assert.Nil(t, err)
		assert.NotNil(t, resp)
		assert.Equal(t, resp.StatusCode, http.StatusOK)
		data, err := decodeBody(resp)
		assert.Nil(t, err)
		dataMap := data.(map[string]interface{})
		assert.NotNil(t, dataMap)
		assert.Equal(t, dataMap["message"], "ping successful")
	})

	// 3. Test Public Endpoint
	t.Run("Test Public Endpoint", func(t *testing.T) {
		resp, err := checkRequest(server.Client(), server.URL+"/api/v1/public", "")
		assert.Nil(t, err)
		assert.NotNil(t, resp)
		assert.Equal(t, resp.StatusCode, http.StatusOK)
		data, err := decodeBody(resp)
		assert.Nil(t, err)
		dataMap := data.(map[string]interface{})
		assert.NotNil(t, dataMap)
		assert.Equal(t, dataMap["message"], "ping successful")
	})

	// 4. Test Private Endpoint
	urls := map[string]string{
		"With Middleware":    "user-with-middleware",    // Test Private Endpoing using Middleware
		"WithOut Middleware": "user-without-middleware", // Test Private Endpoing without using Middleware
	}
	for name, url := range urls {
		t.Run("Test Private Endpoint "+name, func(t *testing.T) {
			t.Run("Without Token", func(t *testing.T) {
				resp, err := checkRequest(server.Client(), server.URL+"/api/v1/private/"+url, "")
				assert.Nil(t, err)
				assert.NotNil(t, resp)
				assert.Equal(t, resp.StatusCode, http.StatusUnauthorized)
				data, err := decodeBody(resp)
				assert.Nil(t, err)
				dataMap := data.(map[string]interface{})
				assert.NotNil(t, dataMap)
				assert.Equal(t, dataMap["message"], "missing token")
			})

			t.Run("With wrong Token", func(t *testing.T) {
				resp, err := checkRequest(server.Client(), server.URL+"/api/v1/private/user-with-middleware", "TOKEN")
				assert.Nil(t, err)
				assert.NotNil(t, resp)
				assert.Equal(t, resp.StatusCode, http.StatusUnauthorized)
				data, err := decodeBody(resp)
				assert.Nil(t, err)
				dataMap := data.(map[string]interface{})
				assert.NotNil(t, dataMap)
				assert.Equal(t, dataMap["message"], "invalid token")
			})
		})
	}
	// 5. Test Auth Provider Endpoints
}

func checkRequest(client *http.Client, url, token string) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodPost, url, nil)
	if err != nil {
		log.Printf("error: %v", err)
		return nil, err
	}
	if token != "" {
		req.Header.Add("Authorization", "Bearer "+token)
	}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("error: %v", err)
		return nil, err
	}

	return resp, nil
}

func decodeBody(response *http.Response) (interface{}, error) {
	defer response.Body.Close()
	var data interface{}
	err := json.NewDecoder(response.Body).Decode(&data)
	if err != nil {
		log.Printf("error: %v", err)
	}
	log.Printf("response: %v", data)
	return data, nil
}
