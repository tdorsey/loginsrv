package oauth2

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"regexp"
	"strings"

	"github.com/tarent/loginsrv/model"
)

// for info see https://developers.google.com/identity/protocols/OpenIDConnect#obtaininguserprofileinformation
func init() {
	RegisterProvider(providerGoogle)
}

//DiscoverOAuthURLs Retrieve the OAuth Discovery Document and set endpoints from there instead of hardcoding.
func DiscoverOAuthURLs() (openID GoogleOpenID) {
	openID = GoogleOpenID{
		DiscoveryURL: "https://accounts.google.com/.well-known/openid-configuration",
		GetDiscoveryDocument: func(openID GoogleOpenID) (doc model.DiscoveryDocument, rawDocJson string, err error) {
			doc = model.DiscoveryDocument{}
			resp, err := http.Get(openID.DiscoveryURL)
			if err != nil {
				return model.DiscoveryDocument{}, "", err
			}

			b, err := ioutil.ReadAll(resp.Body)

			err = json.Unmarshal(b, &doc)
			if err != nil {
				return model.DiscoveryDocument{}, "", fmt.Errorf("error parsing google discovery document: %v", err)
			}
			return doc, string(b), nil
		},
	}
	return openID
}

//GoogleOpenID Holds OAuth Endpoint information retrieved from the Discovery Document
type GoogleOpenID struct {
	DiscoveryURL         string
	GetDiscoveryDocument func(openID GoogleOpenID) (doc model.DiscoveryDocument, rawDocJson string, err error)
	AuthURL              string
	TokenURL             string
	UserInfoURL          string
}

type GoogleUser struct {
	DisplayName string
	Emails      []struct {
		Value string
	}
	Image struct {
		Url string
	}
	Domain string
}

var openID = DiscoverOAuthURLs()

var providerGoogle = Provider{
	Name:     "google",
	AuthURL:  openID.AuthURL,
	TokenURL: openID.TokenURL,
	GetUserInfo: func(token TokenInfo) (model.UserInfo, string, error) {

		gu := GoogleUser{}
		url := fmt.Sprintf("%v?alt=json&access_token=%v", openID.UserInfoURL, token.AccessToken)
		resp, err := http.Get(url)

		if err != nil {
			return model.UserInfo{}, "", err
		}

		if !strings.Contains(resp.Header.Get("Content-Type"), "application/json") {
			return model.UserInfo{}, "", fmt.Errorf("wrong content-type on google get user info: %v", resp.Header.Get("Content-Type"))
		}

		if resp.StatusCode != 200 {
			return model.UserInfo{}, "", fmt.Errorf("got http status %v on google get user info", resp.StatusCode)
		}

		b, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return model.UserInfo{}, "", fmt.Errorf("error reading google get user info: %v", err)
		}

		err = json.Unmarshal(b, &gu)
		if err != nil {
			return model.UserInfo{}, "", fmt.Errorf("error parsing google get user info: %v", err)
		}

		if len(gu.Emails) == 0 {
			return model.UserInfo{}, "", fmt.Errorf("invalid google response: no email address returned.")
		}

		reg := regexp.MustCompile(`\?.*$`)

		return model.UserInfo{
			Sub:     gu.Emails[0].Value,
			Picture: reg.ReplaceAllString(gu.Image.Url, "${1}"),
			Name:    gu.DisplayName,
			Email:   gu.Emails[0].Value,
			Origin:  "google",
			Domain:  gu.Domain,
		}, string(b), nil
	},
}
