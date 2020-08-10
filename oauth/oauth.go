package oauth

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/mercadolibre/golang-restclient/rest"
	"github.com/studingprojects/bookstore_utils-go/rest_errors"
)

const (
	headerXPublic   = "X-Public"
	headerXCallerId = "X-Caller-Id"
	headerXClientId = "X-Client-Id"
)

var (
	oauthClient = rest.RequestBuilder{
		BaseURL: "http://localhost:8089",
		Timeout: 500 * time.Millisecond,
	}
)

type AccessToken struct {
	Id       string `json:"Id"`
	ClientId int64  `json:"clientId"`
	CallerId int64  `json:"callerId"`
}

func IsPublic(request *http.Request) bool {
	if request == nil {
		return true
	}
	return request.Header.Get(headerXPublic) == "true"
}

func GetClientId(request *http.Request) int64 {
	return parseHeaderInt(request, headerXClientId)
}

func GetCallerId(request *http.Request) int64 {
	return parseHeaderInt(request, headerXCallerId)
}

func AuthenticateRequest(request *http.Request) rest_errors.RestErr {
	if request == nil {
		return nil
	}
	cleanRequest(request)

	accessTokenId := strings.TrimSpace(request.URL.Query().Get("access_token"))
	if accessTokenId == "" {
		return rest_errors.NewBadRequestError("access_token is required")
	}
	at, err := getAccessToken(accessTokenId)
	if err != nil {
		if err.Status() == http.StatusNotFound {
			return nil
		}
		return err
	}
	request.Header.Add(headerXCallerId, fmt.Sprintf("%v", at.CallerId))
	request.Header.Add(headerXClientId, fmt.Sprintf("%v", at.ClientId))

	return nil
}

func cleanRequest(request *http.Request) {
	if request == nil {
		return
	}
	request.Header.Del(headerXClientId)
	request.Header.Del(headerXCallerId)
}

func getAccessToken(accessToken string) (*AccessToken, rest_errors.RestErr) {
	response := oauthClient.Get(fmt.Sprintf("/oauth/access_token/%s", accessToken))
	if response == nil || response.Response == nil {
		return nil, rest_errors.NewBadRequestError("oauth service: invalid parameters")
	}
	if response.StatusCode > 299 {
		var restErr rest_errors.RestErr
		if err := json.Unmarshal(response.Bytes(), &restErr); err != nil {
			return nil, rest_errors.NewInternalServerError("oauth service: could not parse oauth response", err)
		}
		return nil, rest_errors.NewExternalServiceError(
			fmt.Sprintf("user service: %s", restErr.Message()),
			errors.New("external_service_error"),
		)
	}
	var at AccessToken
	if err := json.Unmarshal(response.Bytes(), &at); err != nil {
		return nil, rest_errors.NewInternalServerError("oauth service: could not parse oauth response", err)
	}

	return &at, nil
}

func parseHeaderInt(request *http.Request, key string) int64 {
	if request == nil {
		return 0
	}
	value, err := strconv.ParseInt(request.Header.Get(key), 10, 64)
	if err != nil {
		return 0
	}
	return value
}
