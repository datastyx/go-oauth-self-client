package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/jinzhu/configor"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"
	"github.com/lestrrat-go/jwx/jwt/openid"

	"github.com/google/uuid"
)

type ProxyConfig struct {
	SelfIssuingOidcClient struct {
		KeyId           string `default:"selfissuingoidcclient"` // keyId for the public key in the JWKS
		OauthClientId   string `default:"selfissuingoidcclient"` // OAuth 2.0 client_id as registered in the idp, required for the subject in the assertion token
		JwksUrlPort     int    `default:"80"`                    // port for the URL for exposing the JWKS with the public key to validate the self issued token of the client
		JwksUrlPath     string `default:"/jwks"`                 // 'path' part of the URL for exposing the JWKS with the public key to validate the self issued token of the client
		PrivKeyFileName string `default:"key.pem"`               // name for the private key PEM (PKCS#1) store in the current dir
	}
	RemoteIdp struct {
		TokenEndpoint   string // token endpoint of the authorization server
		IdpJWKSendpoint string // keys of the idp to validate the received access token (validation typically done at the RS but for this demonstrator its done here)
	}
}

func main() {

	var config ProxyConfig
	// get user configuration
	err := configor.Load(&config, "config/config.yml")
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("config: %#v", config)

	// try to retrieve public key from current dir
	privkeyPKCS1, err := getLocalPrivKeyPKCS1(config.SelfIssuingOidcClient.PrivKeyFileName)
	if errors.Is(err, os.ErrNotExist) {
		log.Println("No local private key found, creating a new one")
		privkeyPKCS1, err = createNewPrivKey(config.SelfIssuingOidcClient.PrivKeyFileName)
	} else if err != nil {
		log.Fatalf("Failed reading the existing privKey : %s\n", err)
	}
	// Create a JWK pub key from the private key
	pubJWK, err := createJWKPubKey(config.SelfIssuingOidcClient.KeyId, privkeyPKCS1)
	if err != nil {
		log.Fatalf("Failed generating the public JWK : %s\n", err)
	}
	// create a JWKS with the JWK pub key as single key in the set
	jwks, err := createJWKS(config.SelfIssuingOidcClient.KeyId, pubJWK)
	if err != nil {
		log.Fatalf("Failed producing the JWKS : %s\n", err)
	}
	// create a self signed token using the private key
	token, err := createAssertionToken(config.SelfIssuingOidcClient.KeyId, config.SelfIssuingOidcClient.OauthClientId, config.RemoteIdp.TokenEndpoint, privkeyPKCS1)
	if err != nil {
		log.Fatalf("Failed generating the JWT assertion token : %s\n", err)
	}
	log.Println("Created self issued token :")
	fmt.Println(string(token))
	// expose the a JWKS URL
	server := makeHTTPServer(config.SelfIssuingOidcClient.JwksUrlPort, config.SelfIssuingOidcClient.JwksUrlPath, jwks)
	defer server.Close()

	log.Printf("Starting JWKS server at 0.0.0.0:%s%s\n", strconv.Itoa(config.SelfIssuingOidcClient.JwksUrlPort), config.SelfIssuingOidcClient.JwksUrlPath)
	go serveJWKS(server)
	fmt.Println("[Tap ENTER to finish]")
	fmt.Scanln()

	// get a new access token using the JWT authorization grant (rfc7523)
	accessToken, err := getAccessTokenWithAssertionGrant(config.RemoteIdp.TokenEndpoint, config.SelfIssuingOidcClient.OauthClientId, token)
	if err != nil {
		log.Fatalf("Failed generating the JWT assertion token : %s\n", err)
	}
	fmt.Println("[Tap ENTER to finish]")
	fmt.Scanln()

	// retrieve the jwks from the idp
	log.Println("Retrieving IDP's JWKS")
	idpJWKS, err := getIdpJWKeySet(config.RemoteIdp.IdpJWKSendpoint)

	{
		goIdpJwks, err := jwk.Parse(idpJWKS)
		if err != nil {
			log.Fatalf("The JWKS bytes could not be unmarshalled to a JWKS, got error : %s\n", err)
		}
		// Actual verification:
		// FINALLY. This is how you Parse and verify the payload.
		// Key IDs are automatically matched.

		token, err := jwt.Parse(
			accessToken,
			// Tell the parser that you want to use this keyset
			jwt.WithKeySet(goIdpJwks),
			// Uncomment the following option if you know your key does not have an "alg"
			// field (which is apparently the case for Azure tokens)
			// jwt.InferAlgorithmFromKey(true),
		)
		if err != nil {
			fmt.Printf("failed to parse payload: %s\n", err)
		}
		_ = token
		log.Println("Access token validated")
	}

}
func getLocalPrivKeyPKCS1(privKeyFileName string) ([]byte, error) {

	file, err := os.OpenFile(privKeyFileName, os.O_RDONLY, 0600)
	if err != nil {
		return nil, err
	}
	b, err := io.ReadAll(file)
	if err != nil {
		log.Fatal(err)
	}
	privKey, _ := pem.Decode(b)
	return privKey.Bytes, nil
}

func createNewPrivKey(privKeyFileName string) ([]byte, error) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %s\n", err)
	}

	keyOut, err := os.OpenFile(privKeyFileName, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return nil, fmt.Errorf("Failed to open key.pem for writing: %v", err)
	}
	privBytes := x509.MarshalPKCS1PrivateKey(privKey)
	if err := pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes}); err != nil {
		return nil, fmt.Errorf("Failed to write data to key.pem: %v", err)
	}
	if err := keyOut.Close(); err != nil {
		return nil, fmt.Errorf("Error closing key.pem: %v", err)
	}
	log.Printf("Create new private key in '%s'\n", privKeyFileName)
	return privBytes, nil
}

func createJWKPubKey(keyId string, privKeyPKCS8 []byte) ([]byte, error) {
	privKey, err := x509.ParsePKCS1PrivateKey(privKeyPKCS8)
	if err != nil {
		return nil, fmt.Errorf("failed to parse pem private key: %s\n", err)
	}
	// Now create a key set that users will use to verity the signed payload against
	// Normally these keys are available somewhere like https://www.googleapis.com/oauth2/v3/certs

	pubKey, err := jwk.New(privKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create JWK: %s\n", err)
	}

	// Remember, the key must have the proper "kid", and "alg"
	// If your key does not have "alg", see jwt.InferAlgorithmFromKey()
	pubKey.Set(jwk.AlgorithmKey, jwa.RS256)
	pubKey.Set(jwk.KeyIDKey, keyId)
	pubKey.Set(jwk.KeyUsageKey, "sig")
	pem, err := jwk.Pem(pubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize pubKey to PEM: %s\n", err)
	}
	ioutil.WriteFile("pubkey.pem", pem, 0600)
	buf, err := json.MarshalIndent(pubKey, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal key into JSON: %s\n", err)
	}
	ioutil.WriteFile("pubkey.jwk", buf, 0600)
	log.Printf("Created new JWK with the public key having a 'kid' of %s", keyId)
	return buf, nil
}
func createJWKS(keyId string, pubJWK []byte) ([]byte, error) {

	pubKey, err := jwk.ParseKey(pubJWK)
	if err != nil {
		return nil, fmt.Errorf("Couldn't parse the given public JWK: %s\n", err)
	}
	// This key set contains two keys, the first one is the correct one
	keyset := jwk.NewSet()
	keyset.Add(pubKey)

	buf, err := json.MarshalIndent(keyset, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal key into JSON: %s\n", err)
	}
	ioutil.WriteFile("keyset.jwks", buf, 0600)
	log.Printf("Created new JWKS with the public key having a 'kid' of %s", keyId)
	return buf, nil
}

func createAssertionToken(keyid string, oauthClientId string, tokenEndpoint string, privKeyPKCS8 []byte) ([]byte, error) {
	privKey, err := x509.ParsePKCS1PrivateKey(privKeyPKCS8)
	if err != nil {
		return nil, fmt.Errorf("failed to parse pem private key: %s\n", err)
	}
	// Now create a key set that users will use to verity the signed payload against
	// Normally these keys are available somewhere like https://www.googleapis.com/oauth2/v3/certs

	privJwk, err := jwk.New(privKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create private JWK: %s\n", err)
	}
	privJwk.Set(jwk.KeyIDKey, keyid)
	var payload []byte
	// Preparation:
	// For demonstration purposes, we need to do some preparation
	// Create a JWK key to sign the token (and also give a KeyID)

	// Create the token
	token := openid.New()
	now := time.Now().Unix()
	token.Set(jwt.SubjectKey, oauthClientId)
	token.Set(jwt.AudienceKey, tokenEndpoint)
	token.Set(jwt.IssuedAtKey, now)
	token.Set(jwt.ExpirationKey, now+120)
	token.Set(jwt.NotBeforeKey, now-120)
	token.Set(openid.JwtIDKey, uuid.New().String())
	token.Set(openid.IssuerKey, oauthClientId)
	token.Set("auth_time", now)
	token.Set("amr", "swk")
	token.Set("aciClr", "<sclr:ConfidentialityClearance xmlns:sclr='urn:nato:stanag:4774:confidentialityclearance:1:0' xmlns:slab='urn:nato:stanag:4774:confidentialitymetadatalabel:1:0'><slab:PolicyIdentifier>MOCK</slab:PolicyIdentifier><sclr:ClassificationList><slab:Classification>UNCLASSIFIED</slab:Classification></sclr:ClassificationList></sclr:ConfidentialityClearance>")
	token.Set("org", "datastyx")
	token.Set("email", "someone@home.org")
	token.Set("aciCOI", "MARIX")
	// Sign the token and generate a payload
	signed, err := jwt.Sign(token, jwa.RS256, privJwk)
	if err != nil {
		return nil, fmt.Errorf("failed to generate signed payload: %s\n", err)
	}

	// This is what you typically get as a signed JWT from a server
	payload = signed
	return payload, nil
}
func makeHTTPServer(port int, path string, jwks []byte) *http.Server {
	//Create the default mux
	mux := http.NewServeMux()
	mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Content-Type", "application/jwk-set+json")
		fmt.Fprint(w, string(jwks))
	})

	// set timeouts so that a slow or malicious client doesn't
	// hold resources forever
	return &http.Server{
		Addr:         ":" + strconv.Itoa(port),
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
		IdleTimeout:  120 * time.Second,
		Handler:      mux,
	}
}

func serveJWKS(server *http.Server) {
	log.Fatal(server.ListenAndServe())
}

func getAccessTokenWithAssertionGrant(tokenEndpoint string, oauthClientId string, assertionToken []byte) ([]byte, error) {
	client := &http.Client{Timeout: time.Second * 5}
	data := url.Values{}
	// data.Set("client_id", oauthClientId)
	data.Set("grant_type", "client_credentials")
	// data.Set("client_secret", "5aff93c4-fe17-4371-b3cb-f93e32b013ec")
	data.Set("client_assertion", string(assertionToken))
	data.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
	data.Set("audience", "some.custom.backend")

	req, err := http.NewRequest("POST", tokenEndpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("Creating the request for the token endpoint '%s' got error : %s\n", tokenEndpoint, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	requestDump, err := httputil.DumpRequest(req, true)
	if err != nil {
		return nil, fmt.Errorf("Dumping the request for the token endpoint '%s' got error : %s\n", tokenEndpoint, err)
	} else {
		log.Printf("\nRequest being sent :\n")
		log.Printf("\n%s\n\n", string(requestDump))
	}
	log.Println("Calling token endpoint")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("call the token endpoint '%s' got error : %s\n", tokenEndpoint, err)
	}
	defer resp.Body.Close()
	result, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("Extracting the body from the response to the call to the token endpoint '%s' got error : %s\n", tokenEndpoint, err)
	}
	log.Println(string(result))
	var jsonBody map[string]interface{}
	err = json.Unmarshal(result, &jsonBody)
	if err != nil {
		return nil, fmt.Errorf("Marshalling the response body from the call to the token endpoint '%s' got error : %s\n", tokenEndpoint, err)
	}
	return []byte(jsonBody["access_token"].(string)), nil
}

func getIdpJWKeySet(idpJWKSendpoint string) ([]byte, error) {
	resp, err := http.Get(idpJWKSendpoint)
	if err != nil {
		return nil, fmt.Errorf("Retrieving the IDP's JWKS from the endpoint '%s' got error : %s\n", idpJWKSendpoint, err)
	}
	defer resp.Body.Close()
	resultJWKS, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("Extracting the body from the response to the call to the jwks endpoint '%s' got error : %s\n", idpJWKSendpoint, err)
	}
	//validate it is a jwk or jwks
	_, err = jwk.Parse(resultJWKS)
	if err != nil {
		return nil, fmt.Errorf("the result from the jwk endpoint '%s' could not be unmarshalled to a JWKS, got error : %s\n", idpJWKSendpoint, err)
	}
	return resultJWKS, nil
}
