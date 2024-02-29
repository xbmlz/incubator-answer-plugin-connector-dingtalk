package dingtalk

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/apache/incubator-answer/plugin"
	"github.com/xbmlz/incubator-answer-plugin-connector-dingtalk/i18n"
)

const (
	DINGTALK_LOGO_SVG      = "PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSIyNCIgaGVpZ2h0PSIyNCIgdmlld0JveD0iMCAwIDI0IDI0Ij48cGF0aCBkPSJNMTIgMGMtNi42MjYgMC0xMiA1LjM3My0xMiAxMiAwIDUuMzAyIDMuNDM4IDkuOCA4LjIwNyAxMS4zODcuNTk5LjExMS43OTMtLjI2MS43OTMtLjU3N3YtMi4yMzRjLTMuMzM4LjcyNi00LjAzMy0xLjQxNi00LjAzMy0xLjQxNi0uNTQ2LTEuMzg3LTEuMzMzLTEuNzU2LTEuMzMzLTEuNzU2LTEuMDg5LS43NDUuMDgzLS43MjkuMDgzLS43MjkgMS4yMDUuMDg0IDEuODM5IDEuMjM3IDEuODM5IDEuMjM3IDEuMDcgMS44MzQgMi44MDcgMS4zMDQgMy40OTIuOTk3LjEwNy0uNzc1LjQxOC0xLjMwNS43NjItMS42MDQtMi42NjUtLjMwNS01LjQ2Ny0xLjMzNC01LjQ2Ny01LjkzMSAwLTEuMzExLjQ2OS0yLjM4MSAxLjIzNi0zLjIyMS0uMTI0LS4zMDMtLjUzNS0xLjUyNC4xMTctMy4xNzYgMCAwIDEuMDA4LS4zMjIgMy4zMDEgMS4yMy45NTctLjI2NiAxLjk4My0uMzk5IDMuMDAzLS40MDQgMS4wMi4wMDUgMi4wNDcuMTM4IDMuMDA2LjQwNCAyLjI5MS0xLjU1MiAzLjI5Ny0xLjIzIDMuMjk3LTEuMjMuNjUzIDEuNjUzLjI0MiAyLjg3NC4xMTggMy4xNzYuNzcuODQgMS4yMzUgMS45MTEgMS4yMzUgMy4yMjEgMCA0LjYwOS0yLjgwNyA1LjYyNC01LjQ3OSA1LjkyMS40My4zNzIuODIzIDEuMTAyLjgyMyAyLjIyMnYzLjI5M2MwIC4zMTkuMTkyLjY5NC44MDEuNTc2IDQuNzY1LTEuNTg5IDguMTk5LTYuMDg2IDguMTk5LTExLjM4NiAwLTYuNjI3LTUuMzczLTEyLTEyLTEyeiIvPjwvc3ZnPg=="
	DINGTALK_AUTHORIZE_URL = "https://login.dingtalk.com/oauth2/auth"
	DINGTALK_TOKEN_URL     = "https://api.dingtalk.com/v1.0/oauth2/userAccessToken"
	DINGTALK_USER_JSON_URL = "https://api.dingtalk.com/v1.0/contact/users/me"
)

type Connector struct {
	Config *ConnectorConfig
}

type ConnectorConfig struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

type TokenResponse struct {
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
	ExpiresIn    int    `json:"expiresIn"`
	CorpID       string `json:"corpId"`
}

type UserInfoResponse struct {
	Nick      string `json:"nick"`
	AvatarUrl string `json:"avatarUrl"`
	Mobile    string `json:"mobile"`
	OpenID    string `json:"openId"`
	UnionId   string `json:"unionId"`
	Email     string `json:"email"`
	StateCode string `json:"stateCode"`
}

func init() {
	plugin.Register(&Connector{
		Config: &ConnectorConfig{},
	})
}

func (g *Connector) Info() plugin.Info {
	return plugin.Info{
		Name:        plugin.MakeTranslator(i18n.InfoName),
		SlugName:    "dingtalk_connector",
		Description: plugin.MakeTranslator(i18n.InfoDescription),
		Author:      "xbmlz",
		Version:     "1.0.0",
		Link:        "https://github.com/xbmlz/incubator-answer-plugin-connector-dingtalk/tree/main",
	}
}

func (g *Connector) ConnectorLogoSVG() string {
	return DINGTALK_LOGO_SVG
}

func (g *Connector) ConnectorName() plugin.Translator {
	return plugin.MakeTranslator(i18n.ConnectorName)
}

func (g *Connector) ConnectorSlugName() string {
	return "dingtalk"
}

func (g *Connector) ConnectorSender(ctx *plugin.GinContext, receiverURL string) (redirectURL string) {
	// https://login.dingtalk.com/oauth2/auth?
	// redirect_uri=xxxx
	// &response_type=code
	// &client_id=dingxxxxxxx
	// &scope=openid
	// &state=dddd
	// &prompt=consent
	return fmt.Sprintf("%s?redirect_uri=%s&response_type=code&client_id=%s&scope=Contact.User.Read&state=state&prompt=consent",
		DINGTALK_AUTHORIZE_URL, receiverURL, g.Config.ClientID)
}

func (g *Connector) ConnectorReceiver(ctx *plugin.GinContext, receiverURL string) (userInfo plugin.ExternalLoginUserInfo, err error) {

	// 1. get code
	code := ctx.Query("code")
	fmt.Println("code:", code)

	// 2. get token
	tokenReq := map[string]string{
		"clientId":     g.Config.ClientID,
		"clientSecret": g.Config.ClientSecret,
		"code":         code,
		"grantType":    "authorization_code",
	}
	token, err := getToken(DINGTALK_TOKEN_URL, tokenReq)
	if err != nil {
		return plugin.ExternalLoginUserInfo{}, err
	}
	fmt.Println("token:", token)

	// 3. get user info
	user, err := getUserInfo(DINGTALK_USER_JSON_URL, token)
	if err != nil {
		return plugin.ExternalLoginUserInfo{}, err
	}
	fmt.Println("user:", user)
	return user, nil
}

func getToken(url string, body map[string]string) (token string, err error) {
	jsonBody, _ := json.Marshal(body)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonBody))
	if err != nil {
		return "", err
	}

	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{}
	response, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("get token failed, status code: %d", response.StatusCode)
	}

	var resp TokenResponse
	err = json.NewDecoder(response.Body).Decode(&resp)
	if err != nil {
		return "", err
	}

	return resp.AccessToken, nil
}

func getUserInfo(url string, token string) (userInfo plugin.ExternalLoginUserInfo, err error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return plugin.ExternalLoginUserInfo{}, err
	}

	req.Header.Set("x-acs-dingtalk-access-token", token)
	client := &http.Client{}
	response, err := client.Do(req)
	if err != nil {
		return plugin.ExternalLoginUserInfo{}, err
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return plugin.ExternalLoginUserInfo{}, fmt.Errorf("get user info failed, status code: %d", response.StatusCode)
	}

	var resp UserInfoResponse
	err = json.NewDecoder(response.Body).Decode(&resp)
	if err != nil {
		return plugin.ExternalLoginUserInfo{}, err
	}

	userInfo = plugin.ExternalLoginUserInfo{
		ExternalID:  resp.OpenID,
		DisplayName: resp.Nick,
		Username:    resp.Nick,
		Email:       resp.Email,
		Avatar:      resp.AvatarUrl,
		MetaInfo:    "",
	}

	return userInfo, nil
}

func (g *Connector) ConfigFields() []plugin.ConfigField {
	return []plugin.ConfigField{
		{
			Name:        "client_id",
			Type:        plugin.ConfigTypeInput,
			Title:       plugin.MakeTranslator(i18n.ConfigClientIDTitle),
			Description: plugin.MakeTranslator(i18n.ConfigClientIDDescription),
			Required:    true,
			UIOptions: plugin.ConfigFieldUIOptions{
				InputType: plugin.InputTypeText,
			},
			Value: g.Config.ClientID,
		},
		{
			Name:        "client_secret",
			Type:        plugin.ConfigTypeInput,
			Title:       plugin.MakeTranslator(i18n.ConfigClientSecretTitle),
			Description: plugin.MakeTranslator(i18n.ConfigClientSecretDescription),
			Required:    true,
			UIOptions: plugin.ConfigFieldUIOptions{
				InputType: plugin.InputTypeText,
			},
			Value: g.Config.ClientSecret,
		},
	}
}

func (g *Connector) ConfigReceiver(config []byte) error {
	c := &ConnectorConfig{}
	_ = json.Unmarshal(config, c)
	g.Config = c
	return nil
}
