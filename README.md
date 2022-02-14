go-oauth-self-client
====================

This is an example demonstration of an Oauth 2.0 Client code that retrieves an access token at an Authorization Server Token Enpoint using the JWT Authorization Grant (rfc7523).

Following steps are executed : 
1. Try to retrieve public key from current dir
2. Create a JWK pub key from the private key
3. Create a JWKS with the JWK pub key as single key in the set
4. Create a self signed token using the private key
5. Expose the a JWKS URL (for validation of the assertion by the authorization server)
6. Get a new access token using the JWT authorization grant (rfc7523)
7. Retrieve the jwks from the idp
8. Validate the access token


Prerequisits 
------------
- This script requires a Go (golang) installation v1.13+
- This script requires an OAuth 2.0 Authorization Server with a registered client. An example authorization server client configuration cna be found for Keycloak in the 'keycloak-client-export' directory. The client Script needs to be configured in './config/config.yml'

Running
-------
go run ./go-oauth-self-client.go