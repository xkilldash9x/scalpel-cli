// internal/discovery/types.go
package discovery

import (
	"time"
)

// Config holds the configuration for the Discovery engine.
type Config struct {
	MaxDepth    int           `mapstructure:"maxDepth"`
	Concurrency int           `mapstructure:"concurrency"`
	Timeout     time.Duration `mapstructure:"timeout"`
	// use pointer to distinguish between 'false' (explicitly disabled) and 'unset' (default behavior).
	PassiveEnabled *bool `mapstructure:"passiveEnabled"`
	// requests per second for crt.sh
	CrtShRateLimit float64 `mapstructure:"crtShRateLimit"`
	CacheDir       string  `mapstructure:"cacheDir"`
	// Concurrency for passive HTTP requests (e.g., sitemap parsing)
	PassiveConcurrency int `mapstructure:"passiveConcurrency"`
}

// SetDefaults applies default values if they aren't set in the config file.
func (c *Config) SetDefaults() {
	// using <= 0 ensures we catch negative values too
	if c.MaxDepth <= 0 {
		c.MaxDepth = 3 // sensible default depth
	}
	if c.Concurrency <= 0 {
		c.Concurrency = 5 // default browser instances
	}
	if c.Timeout <= 0 {
		c.Timeout = 45 * time.Second // timeout per page load
	}
	// resilience: crt.sh requires gentle rate limiting. 0.5 req/s is safe.
	if c.CrtShRateLimit <= 0 {
		c.CrtShRateLimit = 0.5
	}
	if c.CacheDir == "" {
		c.CacheDir = ".scalpel_cache" // default local cache directory
	}
	// passive discovery is enabled by default if the field is unset (nil).
	if c.PassiveEnabled == nil {
		defaultVal := true
		c.PassiveEnabled = &defaultVal
	}
}

// crawlTask represents an item in the crawler queue.
type crawlTask struct {
	URL   string
	Depth int
}