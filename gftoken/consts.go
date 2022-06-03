package gftoken

const (
	DefaultTimeout    = 60 * 60 * 24 * 10
	DefaultMaxRefresh = 60 * 60 * 24 * 5
	DefaultCacheKey   = "GfToken_"
	DefaultEncryptKey = "1234567890m1234567890z1234567890"
)

// Token 错误信息
const (
	ErrorsParseTokenFail string = "Token 解析失败"
	ErrorsTokenInvalid   string = "Token 无效"
	ErrTokenNotValidYet  string = "Token 未激活"
	ErrorsTokenMalFormed string = "Token 格式不正确"
)

const (
	JwtTokenOK          = 1     // token有效
	JwtTokenInvalid int = -iota // token无效
	JwtTokenExpired             // token过期
)
