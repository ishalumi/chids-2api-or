package tempmail

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"orchids-api/internal/proxy"
)

// TempMailService 临时邮箱服务接口
type TempMailService interface {
	GenerateEmail() (string, error)
	WaitForVerificationCode(email string, timeout time.Duration) (string, error)
	Name() string
}

// ProviderType 邮箱提供商类型
type ProviderType int

const (
	ProviderGPTMail ProviderType = iota
	ProviderMailTM
	Provider1SecMail
	ProviderGuerrilla
	ProviderDispostable
	ProviderDropmail
	ProviderMailnesia
)

const (
	defaultTempMailProvider = "gpt-mail"
	envTempMailProvider     = "TEMP_MAIL_PROVIDER"
)

var providerNames = []string{"gpt-mail", "mail.tm", "1secmail", "guerrillamail", "dispostable", "dropmail", "mailnesia"}

// ===================== 多提供商工厂 =====================

// MultiProvider 多提供商轮询
type MultiProvider struct {
	mu      sync.Mutex
	counter int
}

var globalProvider = &MultiProvider{}

// AllProviders 返回所有可用的提供商类型
func AllProviders() []ProviderType {
	return []ProviderType{
		ProviderGPTMail,
		ProviderMailTM,
		Provider1SecMail,
		ProviderGuerrilla,
		ProviderDispostable,
		ProviderDropmail,
		ProviderMailnesia,
	}
}

// NewTempMail 创建临时邮箱服务（基于环境变量默认值）
func NewTempMail() TempMailService {
	service, err := NewTempMailByName("")
	if err != nil {
		log.Printf("[tempmail] 选择默认提供商失败: %v，回退到 gpt-mail", err)
		return NewGPTMail()
	}
	return service
}

// Next 获取下一个提供商（基于环境变量默认值）
func (mp *MultiProvider) Next() TempMailService {
	return NewTempMail()
}

// NewTempMailByProvider 根据指定提供商创建
func NewTempMailByProvider(p ProviderType) TempMailService {
	switch p {
	case ProviderGPTMail:
		return NewGPTMail()
	case ProviderMailTM:
		return NewMailTM()
	case Provider1SecMail:
		return New1SecMailProvider()
	case ProviderGuerrilla:
		return NewGuerrillaMail()
	case ProviderDispostable:
		return NewDispostable()
	case ProviderDropmail:
		return NewDropmail()
	case ProviderMailnesia:
		return NewMailnesia()
	default:
		return NewGPTMail()
	}
}

// NewTempMailByName 根据提供商名称创建
func NewTempMailByName(name string) (TempMailService, error) {
	selected := strings.TrimSpace(name)
	if selected == "" {
		selected = DefaultProviderName()
	}
	normalized := normalizeProviderName(selected)
	switch normalized {
	case "gpt-mail", "gptmail", "gptmail.com", "gpt-mail.com":
		return NewGPTMail(), nil
	case "mail.tm", "mailtm", "mail-tm":
		return NewMailTM(), nil
	case "1secmail", "1sec", "1sec-mail":
		return New1SecMailProvider(), nil
	case "guerrillamail", "guerrilla", "guerrilla-mail":
		return NewGuerrillaMail(), nil
	case "dispostable":
		return NewDispostable(), nil
	case "dropmail", "dropmail.me":
		return NewDropmail(), nil
	case "mailnesia":
		return NewMailnesia(), nil
	default:
		return nil, fmt.Errorf("未知邮箱提供商: %s，可选: %s", selected, strings.Join(providerNames, ", "))
	}
}

// DefaultProviderName 获取默认提供商名称（可通过环境变量覆盖）
func DefaultProviderName() string {
	if value := strings.TrimSpace(os.Getenv(envTempMailProvider)); value != "" {
		return value
	}
	return defaultTempMailProvider
}

func normalizeProviderName(name string) string {
	value := strings.ToLower(strings.TrimSpace(name))
	value = strings.ReplaceAll(value, "_", "-")
	value = strings.ReplaceAll(value, " ", "")
	return value
}

// ===================== GPTMail 提供商 =====================

const (
	defaultGPTMailBaseURL = "https://mail.chatgpt.org.uk"
	defaultGPTMailAPIKey  = "gpt-test"
	defaultGPTMailKeyFile = "gpt-mail/gpt-key.txt"
)

type GPTMail struct {
	client  *http.Client
	baseURL string
	apiKey  string
}

type gptMailListData struct {
	Emails []gptMailEmail `json:"emails"`
	Count  int            `json:"count"`
}

type gptMailEmail struct {
	ID          string `json:"id"`
	Subject     string `json:"subject"`
	Content     string `json:"content"`
	HTMLContent string `json:"html_content"`
	HasHTML     bool   `json:"has_html"`
}

type gptMailEmailDetail struct {
	ID          string            `json:"id"`
	Subject     string            `json:"subject"`
	Content     string            `json:"content"`
	HTMLContent string            `json:"html_content"`
	HasHTML     bool              `json:"has_html"`
	RawContent  string            `json:"raw_content"`
	Headers     map[string]string `json:"headers"`
}

func NewGPTMail() *GPTMail {
	return &GPTMail{
		client:  proxy.CreateRegisterHTTPClient(30 * time.Second),
		baseURL: loadGPTMailBaseURL(),
		apiKey:  loadGPTMailAPIKey(),
	}
}

func (g *GPTMail) Name() string {
	return "gpt-mail"
}

func (g *GPTMail) GenerateEmail() (string, error) {
	var data struct {
		Email string `json:"email"`
	}
	if err := g.doJSON(http.MethodGet, "/api/generate-email", nil, &data); err != nil {
		return "", err
	}
	if data.Email == "" {
		return "", fmt.Errorf("[gpt-mail] 生成邮箱失败：返回为空")
	}
	log.Printf("[gpt-mail] 创建成功: %s", data.Email)
	return data.Email, nil
}

func (g *GPTMail) WaitForVerificationCode(email string, timeout time.Duration) (string, error) {
	startTime := time.Now()
	pollInterval := 3 * time.Second
	checkCount := 0

	for {
		if time.Since(startTime) > timeout {
			return "", fmt.Errorf("[gpt-mail] 超时等待验证码邮件")
		}

		checkCount++
		log.Printf("[gpt-mail 检查 #%d] 正在检查邮箱...", checkCount)

		listData, err := g.listEmails(email)
		if err != nil {
			time.Sleep(pollInterval)
			continue
		}

		for _, msg := range listData.Emails {
			code := extractVerificationCode(msg.Content)
			if code == "" {
				code = extractVerificationCode(msg.HTMLContent)
			}
			if code == "" {
				code = extractVerificationCode(msg.Subject)
			}
			if code != "" {
				log.Printf("[gpt-mail] 找到验证码: %s", code)
				return code, nil
			}

			detail, err := g.getEmailDetail(msg.ID)
			if err != nil {
				continue
			}

			code = extractVerificationCode(detail.Content)
			if code == "" {
				code = extractVerificationCode(detail.HTMLContent)
			}
			if code == "" {
				code = extractVerificationCode(detail.Subject)
			}
			if code == "" {
				code = extractVerificationCode(detail.RawContent)
			}
			if code != "" {
				log.Printf("[gpt-mail] 找到验证码: %s", code)
				return code, nil
			}
		}

		time.Sleep(pollInterval)
	}
}

func (g *GPTMail) listEmails(email string) (*gptMailListData, error) {
	path := "/api/emails?email=" + url.QueryEscape(email)
	var data gptMailListData
	if err := g.doJSON(http.MethodGet, path, nil, &data); err != nil {
		return nil, err
	}
	return &data, nil
}

func (g *GPTMail) getEmailDetail(id string) (*gptMailEmailDetail, error) {
	if id == "" {
		return nil, fmt.Errorf("[gpt-mail] 邮件 ID 为空")
	}
	path := "/api/email/" + url.PathEscape(id)
	var data gptMailEmailDetail
	if err := g.doJSON(http.MethodGet, path, nil, &data); err != nil {
		return nil, err
	}
	return &data, nil
}

func (g *GPTMail) doJSON(method, path string, body any, out any) error {
	if err := g.ensureConfig(); err != nil {
		return err
	}

	urlStr := strings.TrimRight(g.baseURL, "/") + path
	var bodyReader io.Reader
	if body != nil {
		jsonData, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("[gpt-mail] 序列化请求失败: %w", err)
		}
		bodyReader = bytes.NewReader(jsonData)
	}

	req, err := http.NewRequest(method, urlStr, bodyReader)
	if err != nil {
		return fmt.Errorf("[gpt-mail] 创建请求失败: %w", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("X-API-Key", g.apiKey)

	resp, err := g.client.Do(req)
	if err != nil {
		return fmt.Errorf("[gpt-mail] 请求失败: %w", err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("[gpt-mail] 读取响应失败: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("[gpt-mail] 请求失败 (%d): %s", resp.StatusCode, string(raw))
	}

	var wrapper struct {
		Success bool            `json:"success"`
		Data    json.RawMessage `json:"data"`
		Error   string          `json:"error"`
	}
	if err := json.Unmarshal(raw, &wrapper); err != nil {
		return fmt.Errorf("[gpt-mail] 解析响应失败: %w", err)
	}
	if !wrapper.Success {
		if wrapper.Error == "" {
			wrapper.Error = "unknown error"
		}
		return fmt.Errorf("[gpt-mail] %s", wrapper.Error)
	}
	if out != nil && len(wrapper.Data) > 0 {
		if err := json.Unmarshal(wrapper.Data, out); err != nil {
			return fmt.Errorf("[gpt-mail] 解析数据失败: %w", err)
		}
	}

	return nil
}

func (g *GPTMail) ensureConfig() error {
	if strings.TrimSpace(g.baseURL) == "" {
		g.baseURL = defaultGPTMailBaseURL
	}
	if strings.TrimSpace(g.apiKey) == "" {
		return fmt.Errorf("[gpt-mail] 缺少 API Key，请设置 GPT_MAIL_API_KEY 或 gpt-mail/gpt-key.txt")
	}
	return nil
}

func loadGPTMailBaseURL() string {
	if value := strings.TrimSpace(os.Getenv("GPT_MAIL_BASE_URL")); value != "" {
		return strings.TrimRight(value, "/")
	}
	return defaultGPTMailBaseURL
}

func loadGPTMailAPIKey() string {
	if value := strings.TrimSpace(os.Getenv("GPT_MAIL_API_KEY")); value != "" {
		return value
	}
	keyPath := filepath.FromSlash(defaultGPTMailKeyFile)
	if value := readGPTMailKeyFile(keyPath); value != "" {
		return value
	}
	return defaultGPTMailAPIKey
}

func readGPTMailKeyFile(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "key:") {
			return strings.TrimSpace(strings.TrimPrefix(line, "key:"))
		}
		if strings.HasPrefix(line, "key=") {
			return strings.TrimSpace(strings.TrimPrefix(line, "key="))
		}
		return line
	}
	return ""
}

// ===================== Mail.tm 提供商 =====================

type MailTM struct {
	client   *http.Client
	email    string
	password string
	token    string
}

type mailTMDomain struct {
	Domain string `json:"domain"`
}

type mailTMDomainsResponse struct {
	Members []mailTMDomain `json:"hydra:member"`
}

type mailTMAccount struct {
	ID      string `json:"id"`
	Address string `json:"address"`
}

type mailTMToken struct {
	Token string `json:"token"`
}

type mailTMMessage struct {
	ID      string        `json:"id"`
	From    mailTMAddress `json:"from"`
	Subject string        `json:"subject"`
}

type mailTMAddress struct {
	Address string `json:"address"`
	Name    string `json:"name"`
}

type mailTMMessagesResponse struct {
	Members []mailTMMessage `json:"hydra:member"`
}

type mailTMMessageDetail struct {
	ID      string   `json:"id"`
	Subject string   `json:"subject"`
	Text    string   `json:"text"`
	Html    []string `json:"html"`
}

func NewMailTM() *MailTM {
	return &MailTM{
		client:   proxy.CreateRegisterHTTPClient(30 * time.Second),
		password: "TempPass" + generateRandomString(8) + "!",
	}
}

func (m *MailTM) Name() string {
	return "mail.tm"
}

func (m *MailTM) GenerateEmail() (string, error) {
	maxRetries := 5

	for retry := 0; retry < maxRetries; retry++ {
		if retry > 0 {
			// 重试前等待，指数退避避免 429
			waitTime := time.Duration(3+retry*3) * time.Second
			log.Printf("[mail.tm] 重试 #%d，等待 %v...", retry, waitTime)
			time.Sleep(waitTime)
		}

		email, err := m.tryGenerateEmail()
		if err == nil {
			return email, nil
		}

		// 如果是 429 错误，继续重试
		if strings.Contains(err.Error(), "429") {
			log.Printf("[mail.tm] 遇到 429 限制，将重试...")
			continue
		}

		// 其他错误直接返回
		return "", err
	}

	return "", fmt.Errorf("[mail.tm] 重试 %d 次后仍然失败", maxRetries)
}

func (m *MailTM) tryGenerateEmail() (string, error) {
	resp, err := m.client.Get("https://api.mail.tm/domains")
	if err != nil {
		return "", fmt.Errorf("[mail.tm] 获取域名失败: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("[mail.tm] 读取域名响应失败: %w", err)
	}

	if resp.StatusCode == 429 {
		return "", fmt.Errorf("[mail.tm] 请求过于频繁 (429)")
	}

	var domainsResp mailTMDomainsResponse
	if err := json.Unmarshal(body, &domainsResp); err != nil {
		return "", fmt.Errorf("[mail.tm] 解析域名响应失败: %w", err)
	}

	if len(domainsResp.Members) == 0 {
		return "", fmt.Errorf("[mail.tm] 没有可用域名")
	}

	domain := domainsResp.Members[0].Domain
	username := generateRandomString(10)
	email := fmt.Sprintf("%s@%s", username, domain)

	accountData := map[string]string{
		"address":  email,
		"password": m.password,
	}
	jsonData, _ := json.Marshal(accountData)

	req, _ := http.NewRequest("POST", "https://api.mail.tm/accounts", bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")

	resp, err = m.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("[mail.tm] 创建账户失败: %w", err)
	}
	defer resp.Body.Close()

	body, _ = io.ReadAll(resp.Body)
	if resp.StatusCode == 429 {
		return "", fmt.Errorf("[mail.tm] 请求过于频繁 (429)")
	}
	if resp.StatusCode != 201 {
		return "", fmt.Errorf("[mail.tm] 创建账户失败 (%d): %s", resp.StatusCode, string(body))
	}

	var account mailTMAccount
	if err := json.Unmarshal(body, &account); err != nil {
		return "", fmt.Errorf("[mail.tm] 解析账户响应失败: %w", err)
	}

	m.email = email
	log.Printf("[mail.tm] 创建成功: %s", email)

	if err := m.login(); err != nil {
		return "", fmt.Errorf("[mail.tm] 登录失败: %w", err)
	}

	return email, nil
}

func (m *MailTM) login() error {
	loginData := map[string]string{
		"address":  m.email,
		"password": m.password,
	}
	jsonData, _ := json.Marshal(loginData)

	req, _ := http.NewRequest("POST", "https://api.mail.tm/token", bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")

	resp, err := m.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return fmt.Errorf("登录失败 (%d): %s", resp.StatusCode, string(body))
	}

	var token mailTMToken
	if err := json.Unmarshal(body, &token); err != nil {
		return err
	}

	m.token = token.Token
	return nil
}

func (m *MailTM) WaitForVerificationCode(email string, timeout time.Duration) (string, error) {
	startTime := time.Now()
	pollInterval := 3 * time.Second
	checkCount := 0

	for {
		if time.Since(startTime) > timeout {
			return "", fmt.Errorf("[mail.tm] 超时等待验证码邮件")
		}

		checkCount++
		log.Printf("[mail.tm 检查 #%d] 正在检查邮箱...", checkCount)

		req, _ := http.NewRequest("GET", "https://api.mail.tm/messages", nil)
		req.Header.Set("Authorization", "Bearer "+m.token)

		resp, err := m.client.Do(req)
		if err != nil {
			time.Sleep(pollInterval)
			continue
		}

		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode != 200 {
			time.Sleep(pollInterval)
			continue
		}

		var messagesResp mailTMMessagesResponse
		if err := json.Unmarshal(body, &messagesResp); err != nil {
			time.Sleep(pollInterval)
			continue
		}

		for _, msg := range messagesResp.Members {
			detailReq, _ := http.NewRequest("GET", "https://api.mail.tm/messages/"+msg.ID, nil)
			detailReq.Header.Set("Authorization", "Bearer "+m.token)

			detailResp, err := m.client.Do(detailReq)
			if err != nil {
				continue
			}

			detailBody, _ := io.ReadAll(detailResp.Body)
			detailResp.Body.Close()

			var detail mailTMMessageDetail
			if err := json.Unmarshal(detailBody, &detail); err != nil {
				continue
			}

			code := extractVerificationCode(detail.Text)
			if code == "" && len(detail.Html) > 0 {
				for _, html := range detail.Html {
					code = extractVerificationCode(html)
					if code != "" {
						break
					}
				}
			}

			if code != "" {
				log.Printf("[mail.tm] 找到验证码: %s", code)
				return code, nil
			}
		}

		time.Sleep(pollInterval)
	}
}

// ===================== 1secmail 提供商 =====================

type SecMail struct {
	client   *http.Client
	email    string
	login    string
	domain   string
}

var secMailDomains = []string{"1secmail.com", "1secmail.org", "1secmail.net"}

func New1SecMailProvider() *SecMail {
	return &SecMail{
		client: proxy.CreateRegisterHTTPClient(30 * time.Second),
	}
}

func (s *SecMail) Name() string {
	return "1secmail"
}

func (s *SecMail) GenerateEmail() (string, error) {
	s.login = generateRandomString(10)
	s.domain = secMailDomains[rand.Intn(len(secMailDomains))]
	s.email = fmt.Sprintf("%s@%s", s.login, s.domain)

	log.Printf("[1secmail] 创建成功: %s", s.email)
	return s.email, nil
}

func (s *SecMail) WaitForVerificationCode(email string, timeout time.Duration) (string, error) {
	startTime := time.Now()
	pollInterval := 3 * time.Second
	checkCount := 0

	for {
		if time.Since(startTime) > timeout {
			return "", fmt.Errorf("[1secmail] 超时等待验证码邮件")
		}

		checkCount++
		log.Printf("[1secmail 检查 #%d] 正在检查邮箱...", checkCount)

		url := fmt.Sprintf("https://www.1secmail.com/api/v1/?action=getMessages&login=%s&domain=%s", s.login, s.domain)
		resp, err := s.client.Get(url)
		if err != nil {
			time.Sleep(pollInterval)
			continue
		}

		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode == 429 {
			log.Printf("[1secmail] 请求过于频繁，等待...")
			time.Sleep(pollInterval * 2)
			continue
		}

		var messages []struct {
			ID      int    `json:"id"`
			From    string `json:"from"`
			Subject string `json:"subject"`
		}
		if err := json.Unmarshal(body, &messages); err != nil {
			time.Sleep(pollInterval)
			continue
		}

		for _, msg := range messages {
			detailURL := fmt.Sprintf("https://www.1secmail.com/api/v1/?action=readMessage&login=%s&domain=%s&id=%d", s.login, s.domain, msg.ID)
			detailResp, err := s.client.Get(detailURL)
			if err != nil {
				continue
			}

			detailBody, _ := io.ReadAll(detailResp.Body)
			detailResp.Body.Close()

			var detail struct {
				Body     string `json:"body"`
				TextBody string `json:"textBody"`
				HtmlBody string `json:"htmlBody"`
			}
			if err := json.Unmarshal(detailBody, &detail); err != nil {
				continue
			}

			code := extractVerificationCode(detail.TextBody)
			if code == "" {
				code = extractVerificationCode(detail.Body)
			}
			if code == "" {
				code = extractVerificationCode(detail.HtmlBody)
			}

			if code != "" {
				log.Printf("[1secmail] 找到验证码: %s", code)
				return code, nil
			}
		}

		time.Sleep(pollInterval)
	}
}

// ===================== Guerrilla Mail 提供商 =====================

type GuerrillaMail struct {
	client   *http.Client
	email    string
	sidToken string
}

func NewGuerrillaMail() *GuerrillaMail {
	return &GuerrillaMail{
		client: proxy.CreateRegisterHTTPClient(30 * time.Second),
	}
}

func (g *GuerrillaMail) Name() string {
	return "guerrillamail"
}

func (g *GuerrillaMail) GenerateEmail() (string, error) {
	resp, err := g.client.Get("https://api.guerrillamail.com/ajax.php?f=get_email_address")
	if err != nil {
		return "", fmt.Errorf("[guerrillamail] 获取邮箱失败: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == 429 {
		return "", fmt.Errorf("[guerrillamail] 请求过于频繁 (429)")
	}
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("[guerrillamail] 获取邮箱失败 (%d): %s", resp.StatusCode, string(body))
	}

	var result struct {
		EmailAddr string `json:"email_addr"`
		SidToken  string `json:"sid_token"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", fmt.Errorf("[guerrillamail] 解析响应失败: %w", err)
	}

	g.email = result.EmailAddr
	g.sidToken = result.SidToken

	log.Printf("[guerrillamail] 创建成功: %s", g.email)
	return g.email, nil
}

func (g *GuerrillaMail) WaitForVerificationCode(email string, timeout time.Duration) (string, error) {
	startTime := time.Now()
	pollInterval := 3 * time.Second
	checkCount := 0
	seq := 0

	for {
		if time.Since(startTime) > timeout {
			return "", fmt.Errorf("[guerrillamail] 超时等待验证码邮件")
		}

		checkCount++
		log.Printf("[guerrillamail 检查 #%d] 正在检查邮箱...", checkCount)

		url := fmt.Sprintf("https://api.guerrillamail.com/ajax.php?f=check_email&sid_token=%s&seq=%d", g.sidToken, seq)
		resp, err := g.client.Get(url)
		if err != nil {
			time.Sleep(pollInterval)
			continue
		}

		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode == 429 {
			log.Printf("[guerrillamail] 请求过于频繁，等待...")
			time.Sleep(pollInterval * 2)
			continue
		}

		var result struct {
			List []struct {
				MailID      string `json:"mail_id"`
				MailFrom    string `json:"mail_from"`
				MailSubject string `json:"mail_subject"`
				MailExcerpt string `json:"mail_excerpt"`
				MailBody    string `json:"mail_body"`
			} `json:"list"`
		}
		if err := json.Unmarshal(body, &result); err != nil {
			time.Sleep(pollInterval)
			continue
		}

		for _, mail := range result.List {
			// 尝试从摘要中提取验证码
			code := extractVerificationCode(mail.MailExcerpt)
			if code == "" {
				code = extractVerificationCode(mail.MailSubject)
			}

			// 如果摘要中没有，获取完整邮件内容
			if code == "" && mail.MailID != "" {
				detailURL := fmt.Sprintf("https://api.guerrillamail.com/ajax.php?f=fetch_email&sid_token=%s&email_id=%s", g.sidToken, mail.MailID)
				detailResp, err := g.client.Get(detailURL)
				if err == nil {
					detailBody, _ := io.ReadAll(detailResp.Body)
					detailResp.Body.Close()

					var detail struct {
						MailBody string `json:"mail_body"`
					}
					if json.Unmarshal(detailBody, &detail) == nil {
						code = extractVerificationCode(detail.MailBody)
					}
				}
			}

			if code != "" {
				log.Printf("[guerrillamail] 找到验证码: %s", code)
				return code, nil
			}
		}

		time.Sleep(pollInterval)
	}
}

// ===================== Dropmail.me 提供商 =====================

type Dropmail struct {
	client *http.Client
	email  string
	token  string
}

func NewDropmail() *Dropmail {
	return &Dropmail{
		client: proxy.CreateRegisterHTTPClient(30 * time.Second),
	}
}

func (d *Dropmail) Name() string {
	return "dropmail"
}

func (d *Dropmail) GenerateEmail() (string, error) {
	// Dropmail 使用 GraphQL API
	query := `{"query":"mutation{introduceSession{id,expiresAt,addresses{address}}}"}`

	req, _ := http.NewRequest("POST", "https://dropmail.me/api/graphql/web-test-wgq1o", strings.NewReader(query))
	req.Header.Set("Content-Type", "application/json")

	resp, err := d.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("[dropmail] 获取邮箱失败: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == 429 {
		return "", fmt.Errorf("[dropmail] 请求过于频繁 (429)")
	}
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("[dropmail] 获取邮箱失败 (%d): %s", resp.StatusCode, string(body))
	}

	var result struct {
		Data struct {
			IntroduceSession struct {
				ID        string `json:"id"`
				Addresses []struct {
					Address string `json:"address"`
				} `json:"addresses"`
			} `json:"introduceSession"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", fmt.Errorf("[dropmail] 解析响应失败: %w", err)
	}

	if len(result.Data.IntroduceSession.Addresses) == 0 {
		return "", fmt.Errorf("[dropmail] 没有获取到邮箱地址")
	}

	d.email = result.Data.IntroduceSession.Addresses[0].Address
	d.token = result.Data.IntroduceSession.ID

	log.Printf("[dropmail] 创建成功: %s", d.email)
	return d.email, nil
}

func (d *Dropmail) WaitForVerificationCode(email string, timeout time.Duration) (string, error) {
	startTime := time.Now()
	pollInterval := 3 * time.Second
	checkCount := 0

	for {
		if time.Since(startTime) > timeout {
			return "", fmt.Errorf("[dropmail] 超时等待验证码邮件")
		}

		checkCount++
		log.Printf("[dropmail 检查 #%d] 正在检查邮箱...", checkCount)

		query := fmt.Sprintf(`{"query":"query{session(id:\"%s\"){mails{rawSize,fromAddr,toAddr,downloadUrl,text,headerSubject}}}"}`, d.token)
		req, _ := http.NewRequest("POST", "https://dropmail.me/api/graphql/web-test-wgq1o", strings.NewReader(query))
		req.Header.Set("Content-Type", "application/json")

		resp, err := d.client.Do(req)
		if err != nil {
			time.Sleep(pollInterval)
			continue
		}

		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode != 200 {
			time.Sleep(pollInterval)
			continue
		}

		var result struct {
			Data struct {
				Session struct {
					Mails []struct {
						FromAddr      string `json:"fromAddr"`
						HeaderSubject string `json:"headerSubject"`
						Text          string `json:"text"`
					} `json:"mails"`
				} `json:"session"`
			} `json:"data"`
		}
		if err := json.Unmarshal(body, &result); err != nil {
			time.Sleep(pollInterval)
			continue
		}

		for _, mail := range result.Data.Session.Mails {
			code := extractVerificationCode(mail.Text)
			if code == "" {
				code = extractVerificationCode(mail.HeaderSubject)
			}

			if code != "" {
				log.Printf("[dropmail] 找到验证码: %s", code)
				return code, nil
			}
		}

		time.Sleep(pollInterval)
	}
}

// ===================== Mailnesia 提供商 =====================

type Mailnesia struct {
	client *http.Client
	email  string
	name   string
}

func NewMailnesia() *Mailnesia {
	return &Mailnesia{
		client: proxy.CreateRegisterHTTPClient(30 * time.Second),
	}
}

func (m *Mailnesia) Name() string {
	return "mailnesia"
}

func (m *Mailnesia) GenerateEmail() (string, error) {
	m.name = generateRandomString(10)
	m.email = fmt.Sprintf("%s@mailnesia.com", m.name)

	log.Printf("[mailnesia] 创建成功: %s", m.email)
	return m.email, nil
}

func (m *Mailnesia) WaitForVerificationCode(email string, timeout time.Duration) (string, error) {
	startTime := time.Now()
	pollInterval := 3 * time.Second
	checkCount := 0

	for {
		if time.Since(startTime) > timeout {
			return "", fmt.Errorf("[mailnesia] 超时等待验证码邮件")
		}

		checkCount++
		log.Printf("[mailnesia 检查 #%d] 正在检查邮箱...", checkCount)

		url := fmt.Sprintf("https://mailnesia.com/mailbox/%s", m.name)
		resp, err := m.client.Get(url)
		if err != nil {
			time.Sleep(pollInterval)
			continue
		}

		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode != 200 {
			time.Sleep(pollInterval)
			continue
		}

		// Extract verification code from HTML response
		code := extractVerificationCode(string(body))
		if code != "" {
			log.Printf("[mailnesia] 找到验证码: %s", code)
			return code, nil
		}

		time.Sleep(pollInterval)
	}
}

// ===================== Dispostable 提供商 =====================

type Dispostable struct {
	client *http.Client
	email  string
	name   string
}

var dispostableDomains = []string{"dispostable.com"}

func NewDispostable() *Dispostable {
	return &Dispostable{
		client: proxy.CreateRegisterHTTPClient(30 * time.Second),
	}
}

func (d *Dispostable) Name() string {
	return "dispostable"
}

func (d *Dispostable) GenerateEmail() (string, error) {
	d.name = generateRandomString(10)
	d.email = fmt.Sprintf("%s@dispostable.com", d.name)

	log.Printf("[dispostable] 创建成功: %s", d.email)
	return d.email, nil
}

func (d *Dispostable) WaitForVerificationCode(email string, timeout time.Duration) (string, error) {
	startTime := time.Now()
	pollInterval := 3 * time.Second
	checkCount := 0

	for {
		if time.Since(startTime) > timeout {
			return "", fmt.Errorf("[dispostable] 超时等待验证码邮件")
		}

		checkCount++
		log.Printf("[dispostable 检查 #%d] 正在检查邮箱...", checkCount)

		url := fmt.Sprintf("https://www.dispostable.com/api/inbox/%s", d.name)
		resp, err := d.client.Get(url)
		if err != nil {
			time.Sleep(pollInterval)
			continue
		}

		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode != 200 {
			time.Sleep(pollInterval)
			continue
		}

		var result []struct {
			ID      string `json:"id"`
			From    string `json:"sender"`
			Subject string `json:"subject"`
			Body    string `json:"body"`
		}
		if err := json.Unmarshal(body, &result); err != nil {
			time.Sleep(pollInterval)
			continue
		}

		for _, mail := range result {
			code := extractVerificationCode(mail.Body)
			if code == "" {
				code = extractVerificationCode(mail.Subject)
			}

			if code != "" {
				log.Printf("[dispostable] 找到验证码: %s", code)
				return code, nil
			}
		}

		time.Sleep(pollInterval)
	}
}

// ===================== 公共工具函数 =====================

func extractVerificationCode(content string) string {
	patterns := []string{
		`\b(\d{6})\b`,
		`code[:\s]+(\d{6})`,
		`verification[:\s]+(\d{6})`,
		`verify[:\s]+(\d{6})`,
		`<strong>(\d{6})</strong>`,
		`<span[^>]*>(\d{6})</span>`,
		`Your verification code is[:\s]+(\d{6})`,
	}

	for _, pattern := range patterns {
		re := regexp.MustCompile(`(?i)` + pattern)
		matches := re.FindStringSubmatch(content)
		if len(matches) > 1 {
			return matches[1]
		}
	}

	return ""
}

func generateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	result := make([]byte, length)
	for i := range result {
		result[i] = charset[rand.Intn(len(charset))]
	}
	return string(result)
}
