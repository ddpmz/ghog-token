package gftoken

import (
	"strings"

	"github.com/gogf/gf/v2/net/ghttp"
)

const FailedAuthCode = 401

type AuthFailed struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// token可以是两种传递方式
// 1. Header 中 {Authorization:Bearer xxx}
// 2. 请求参数中 {token:xxx}
func (m *GfToken) GetRequestToken(r *ghttp.Request) (token string) {
	authHeader := r.Header.Get("Authorization")
	if authHeader != "" {
		parts := strings.SplitN(authHeader, " ", 2)
		if !(len(parts) == 2 && parts[0] == "Bearer") {
			return
		} else if parts[1] == "" {
			return
		}
		token = parts[1]
	} else {
		authHeader = r.Get("token").String()
		if authHeader == "" {
			return
		}
		token = authHeader
	}
	return
}

func (m *GfToken) GetToken(r *ghttp.Request) (tData *tokenData, err error) {
	token := m.GetRequestToken(r)
	tData, _, err = m.getTokenData(r.GetCtx(), token)
	return
}

// 验证token是否生效
func (m *GfToken) IsLogin(r *ghttp.Request) (ok bool, failed *AuthFailed) {
	ok = true
	urlPath := r.URL.Path
	if !m.AuthPath(urlPath) {
		// 如果不需要认证，继续
		return
	}
	token := m.GetRequestToken(r)
	// 检查缓存的token是否有效且自动刷新缓存token
	if !m.IsEffective(r.GetCtx(), token) {
		ok = false
		failed = &AuthFailed{
			Code:    FailedAuthCode,
			Message: "token已失效",
		}
	}
	return
}
