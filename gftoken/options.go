package gftoken

import (
	"github.com/gogf/gf/v2/database/gredis"
	"github.com/gogf/gf/v2/frame/g"
	"github.com/gogf/gf/v2/os/gcache"
)

var (
	defaultGfToken = GfToken{
		CacheKey:   DefaultCacheKey,
		Timeout:    DefaultTimeout,
		MaxRefresh: DefaultMaxRefresh,
		cache:      gcache.New(),
		userJwt:    CreateMyJWT("defaultGfToken"),
		MultiLogin: false,
		EncryptKey: []byte(DefaultEncryptKey),
	}
)

type OptionFunc func(*GfToken)

func NewGfToken(opts ...OptionFunc) *GfToken {
	g := defaultGfToken
	for _, o := range opts {
		o(&g)
	}
	return &g
}

func WithExcludePaths(value g.SliceStr) OptionFunc {
	return func(g *GfToken) {
		g.ExcludePaths = value
	}
}

func WithEncryptKey(value []byte) OptionFunc {
	return func(g *GfToken) {
		g.EncryptKey = value
	}
}

func WithCacheKey(value string) OptionFunc {
	return func(g *GfToken) {
		g.CacheKey = value
	}
}

func WithTimeoutAndMaxRefresh(timeout, maxRefresh int64) OptionFunc {
	return func(g *GfToken) {
		g.Timeout = timeout
		g.MaxRefresh = maxRefresh
	}
}

func WithTimeout(value int64) OptionFunc {
	return func(g *GfToken) {
		g.Timeout = value
	}
}

func WithMaxRefresh(value int64) OptionFunc {
	return func(g *GfToken) {
		g.MaxRefresh = value
	}
}

func WithUserJwt(key string) OptionFunc {
	return func(g *GfToken) {
		g.userJwt = CreateMyJWT(key)
	}
}

func WithGCache() OptionFunc {
	return func(g *GfToken) {
		g.cache = gcache.New()
	}
}

func WithGRedis(redis ...*gredis.Redis) OptionFunc {
	return func(gf *GfToken) {
		gf.cache = gcache.New()
		if len(redis) > 0 {
			gf.cache.SetAdapter(gcache.NewAdapterRedis(redis[0]))
		} else {
			gf.cache.SetAdapter(gcache.NewAdapterRedis(g.Redis()))
		}
	}
}

func WithGRedisConfig(redisConfig ...*gredis.Config) OptionFunc {
	return func(g *GfToken) {
		g.cache = gcache.New()
		redis, err := gredis.New(redisConfig...)
		if err != nil {
			panic(err)
		}
		g.cache.SetAdapter(gcache.NewAdapterRedis(redis))
	}
}

func WithMultiLogin(b bool) OptionFunc {
	return func(g *GfToken) {
		g.MultiLogin = b
	}
}
