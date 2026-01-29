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
	Provider1SecMail
	ProviderGuerrilla
	ProviderDispostable
	ProviderDropmail
	ProviderMailnesia
)

var providerNames = []string{"gpt-mail", "1secmail", "guerrillamail", "dispostable", "dropmail", "mailnesia"}

// ===================== 多提供商工厂 =====================

// MultiProvider 多提供商轮询
type MultiProvider struct {
	mu      sync.Mutex
	counter int
}

var globalProvider = &MultiProvider{}

// AllProviders 返回所有可用的提供商类型（目前仅启用 gpt-mail）
func AllProviders() []ProviderType {
	return []ProviderType{
		ProviderGPTMail,
	}
}

// NewTempMail 创建临时邮箱服务（默认使用 gpt-mail）
func NewTempMail() TempMailService {
	return NewGPTMail()
}

// Next 获取下一个提供商（默认使用 gpt-mail）
func (mp *MultiProvider) Next() TempMailService {
	return NewGPTMail()
}

// NewTempMailByProvider 根据指定提供商创建
func NewTempMailByProvider(p ProviderType) TempMailService {
	switch p {
	case ProviderGPTMail:
		return NewGPTMail()
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
