package proxy

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"golang.org/x/net/proxy"
)

// ProxyType 代理类型
type ProxyType string

const (
	ProxyTypeNone   ProxyType = "none"
	ProxyTypeHTTP   ProxyType = "http"
	ProxyTypeSOCKS5 ProxyType = "socks5"
)

// ProxyConfig 代理配置
type ProxyConfig struct {
	Type     ProxyType `json:"type"`
	Host     string    `json:"host"`
	Port     string    `json:"port"`
	Username string    `json:"username,omitempty"`
	Password string    `json:"password,omitempty"`
}

// ProxySettings 全局代理设置
type ProxySettings struct {
	RegisterProxy ProxyConfig `json:"register_proxy"` // 注册代理
	ChatProxy     ProxyConfig `json:"chat_proxy"`     // 对话代理
}

// Manager 代理管理器
type Manager struct {
	mu       sync.RWMutex
	settings ProxySettings
}

var (
	globalManager *Manager
	once          sync.Once
)

// GetManager 获取全局代理管理器
func GetManager() *Manager {
	once.Do(func() {
		globalManager = &Manager{
			settings: ProxySettings{
				RegisterProxy: ProxyConfig{Type: ProxyTypeNone},
				ChatProxy:     ProxyConfig{Type: ProxyTypeNone},
			},
		}
	})
	return globalManager
}

// GetSettings 获取当前代理设置
func (m *Manager) GetSettings() ProxySettings {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.settings
}

// SetSettings 设置代理配置
func (m *Manager) SetSettings(settings ProxySettings) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.settings = settings
}

// SetRegisterProxy 设置注册代理
func (m *Manager) SetRegisterProxy(cfg ProxyConfig) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.settings.RegisterProxy = cfg
}

// SetChatProxy 设置对话代理
func (m *Manager) SetChatProxy(cfg ProxyConfig) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.settings.ChatProxy = cfg
}

// GetRegisterProxy 获取注册代理配置
func (m *Manager) GetRegisterProxy() ProxyConfig {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.settings.RegisterProxy
}

// GetChatProxy 获取对话代理配置
func (m *Manager) GetChatProxy() ProxyConfig {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.settings.ChatProxy
}

// GetProxyURL 获取代理 URL 字符串
func (cfg *ProxyConfig) GetProxyURL() string {
	if cfg.Type == ProxyTypeNone || cfg.Host == "" {
		return ""
	}

	scheme := "http"
	if cfg.Type == ProxyTypeSOCKS5 {
		scheme = "socks5"
	}

	if cfg.Username != "" && cfg.Password != "" {
		return fmt.Sprintf("%s://%s:%s@%s:%s", scheme, cfg.Username, cfg.Password, cfg.Host, cfg.Port)
	}
	return fmt.Sprintf("%s://%s:%s", scheme, cfg.Host, cfg.Port)
}

// CreateHTTPClient 创建带代理的 HTTP 客户端
func (cfg *ProxyConfig) CreateHTTPClient(timeout time.Duration) *http.Client {
	if cfg.Type == ProxyTypeNone || cfg.Host == "" {
		return &http.Client{Timeout: timeout}
	}

	transport := &http.Transport{}

	switch cfg.Type {
	case ProxyTypeHTTP:
		proxyURL, err := url.Parse(cfg.GetProxyURL())
		if err == nil {
			transport.Proxy = http.ProxyURL(proxyURL)
		}

	case ProxyTypeSOCKS5:
		var auth *proxy.Auth
		if cfg.Username != "" && cfg.Password != "" {
			auth = &proxy.Auth{
				User:     cfg.Username,
				Password: cfg.Password,
			}
		}

		dialer, err := proxy.SOCKS5("tcp", fmt.Sprintf("%s:%s", cfg.Host, cfg.Port), auth, proxy.Direct)
		if err == nil {
			transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
				return dialer.Dial(network, addr)
			}
		}
	}

	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
	}
}

// CreateChatHTTPClient 创建对话代理 HTTP 客户端
func CreateChatHTTPClient(timeout time.Duration) *http.Client {
	cfg := GetManager().GetChatProxy()
	return cfg.CreateHTTPClient(timeout)
}

// CreateRegisterHTTPClient 创建注册代理 HTTP 客户端
func CreateRegisterHTTPClient(timeout time.Duration) *http.Client {
	cfg := GetManager().GetRegisterProxy()
	return cfg.CreateHTTPClient(timeout)
}

// GetRegisterProxyURL 获取注册代理 URL（用于 chromedp）
func GetRegisterProxyURL() string {
	cfg := GetManager().GetRegisterProxy()
	return cfg.GetProxyURL()
}

// GetChatProxyURL 获取对话代理 URL
func GetChatProxyURL() string {
	cfg := GetManager().GetChatProxy()
	return cfg.GetProxyURL()
}

// InitFromEnv 从环境变量初始化代理配置
func InitFromEnv(registerProxy, chatProxy string) {
	m := GetManager()

	if registerProxy != "" {
		if cfg, err := ParseProxyURL(registerProxy); err == nil {
			m.SetRegisterProxy(cfg)
		}
	}

	if chatProxy != "" {
		if cfg, err := ParseProxyURL(chatProxy); err == nil {
			m.SetChatProxy(cfg)
		}
	}
}

// ParseProxyURL 解析代理 URL
func ParseProxyURL(proxyURL string) (ProxyConfig, error) {
	if proxyURL == "" {
		return ProxyConfig{Type: ProxyTypeNone}, nil
	}

	u, err := url.Parse(proxyURL)
	if err != nil {
		return ProxyConfig{}, fmt.Errorf("无效的代理 URL: %w", err)
	}

	cfg := ProxyConfig{
		Host: u.Hostname(),
		Port: u.Port(),
	}

	switch u.Scheme {
	case "http", "https":
		cfg.Type = ProxyTypeHTTP
	case "socks5", "socks5h":
		cfg.Type = ProxyTypeSOCKS5
	default:
		return ProxyConfig{}, fmt.Errorf("不支持的代理类型: %s", u.Scheme)
	}

	if u.User != nil {
		cfg.Username = u.User.Username()
		cfg.Password, _ = u.User.Password()
	}

	return cfg, nil
}
