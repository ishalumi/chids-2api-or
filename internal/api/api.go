package api

import (
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"orchids-api/internal/clerk"
	"orchids-api/internal/register"
	"orchids-api/internal/store"
)

type API struct {
	store    *store.Store
	register *register.RegisterService
}

type ExportData struct {
	Version   int              `json:"version"`
	ExportAt  time.Time        `json:"export_at"`
	Accounts  []store.Account  `json:"accounts"`
}

type ImportResult struct {
	Total    int `json:"total"`
	Imported int `json:"imported"`
	Skipped  int `json:"skipped"`
}

func New(s *store.Store) *API {
	return &API{
		store:    s,
		register: register.New(),
	}
}

func (a *API) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/accounts", a.HandleAccounts)
	mux.HandleFunc("/api/accounts/", a.HandleAccountByID)
	mux.HandleFunc("/api/register", a.HandleRegister)
	mux.HandleFunc("/api/register/verify", a.HandleRegisterVerify)
	mux.HandleFunc("/api/register/batch", a.HandleBatchRegister)
}

func (a *API) HandleAccounts(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case http.MethodGet:
		accounts, err := a.store.ListAccounts()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(accounts)

	case http.MethodPost:
		var acc store.Account
		if err := json.NewDecoder(r.Body).Decode(&acc); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		if acc.ClientCookie != "" && acc.SessionID == "" {
			info, err := clerk.FetchAccountInfo(acc.ClientCookie)
			if err != nil {
				log.Printf("Failed to fetch account info: %v", err)
				http.Error(w, "Failed to fetch account info: "+err.Error(), http.StatusBadRequest)
				return
			}
			acc.SessionID = info.SessionID
			acc.ClientUat = info.ClientUat
			acc.ProjectID = info.ProjectID
			acc.UserID = info.UserID
			acc.Email = info.Email
		}

		if err := a.store.CreateAccount(&acc); err != nil {
			log.Printf("Failed to create account: %v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(acc)

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (a *API) HandleAccountByID(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	idStr := strings.TrimPrefix(r.URL.Path, "/api/accounts/")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		http.Error(w, "Invalid ID", http.StatusBadRequest)
		return
	}

	switch r.Method {
	case http.MethodGet:
		acc, err := a.store.GetAccount(id)
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		json.NewEncoder(w).Encode(acc)

	case http.MethodPut:
		existing, err := a.store.GetAccount(id)
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}

		var acc store.Account
		if err := json.NewDecoder(r.Body).Decode(&acc); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		acc.ID = id

		if acc.SessionID == "" {
			acc.SessionID = existing.SessionID
		}
		if acc.ClientUat == "" {
			acc.ClientUat = existing.ClientUat
		}
		if acc.ProjectID == "" {
			acc.ProjectID = existing.ProjectID
		}
		if acc.UserID == "" {
			acc.UserID = existing.UserID
		}
		if acc.Email == "" {
			acc.Email = existing.Email
		}

		if err := a.store.UpdateAccount(&acc); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(acc)

	case http.MethodDelete:
		if err := a.store.DeleteAccount(id); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (a *API) HandleExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	accounts, err := a.store.ListAccounts()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	exportData := ExportData{
		Version:  1,
		ExportAt: time.Now(),
		Accounts: make([]store.Account, len(accounts)),
	}
	for i, acc := range accounts {
		exportData.Accounts[i] = *acc
		exportData.Accounts[i].ID = 0
		exportData.Accounts[i].RequestCount = 0
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", "attachment; filename=accounts_export.json")
	json.NewEncoder(w).Encode(exportData)
}

func (a *API) HandleImport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var exportData ExportData
	if err := json.NewDecoder(r.Body).Decode(&exportData); err != nil {
		http.Error(w, "Invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}

	result := ImportResult{Total: len(exportData.Accounts)}

	for _, acc := range exportData.Accounts {
		acc.ID = 0
		acc.RequestCount = 0
		if err := a.store.CreateAccount(&acc); err != nil {
			log.Printf("Failed to import account %s: %v", acc.Name, err)
			result.Skipped++
		} else {
			result.Imported++
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

// HandleRegister 处理自动注册请求
func (a *API) HandleRegister(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req register.RegisterJSON
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		// 如果没有请求体，使用自动模式
		req = register.RegisterJSON{}
	}

	// 如果提供了邮箱，使用自定义邮箱模式（需要手动验证）
	if req.Email != "" {
		password := req.Password
		if password == "" {
			password = "OrchidsAuto@2024!"
		}

		result, signUpID, err := a.register.RegisterWithCustomEmail(req.Email, password)
		if err != nil {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": false,
				"error":   err.Error(),
			})
			return
		}

		json.NewEncoder(w).Encode(map[string]interface{}{
			"success":    true,
			"sign_up_id": signUpID,
			"email":      result.Email,
			"message":    "验证码已发送，请调用 /api/register/verify 完成验证",
		})
		return
	}

	// 自动模式：使用临时邮箱
	result, err := a.register.RegisterWithOptions(req.Headless)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   err.Error(),
		})
		return
	}

	// 从 clerk 获取完整账号信息
	info, err := clerk.FetchAccountInfo(result.ClientCookie)
	if err != nil {
		log.Printf("[注册] 获取账号信息失败: %v", err)
		// 即使获取失败也保存基本信息
		info = &clerk.AccountInfo{
			ClientCookie: result.ClientCookie,
			Email:        result.Email,
			ProjectID:    "280b7bae-cd29-41e4-a0a6-7f603c43b607",
		}
	} else {
		log.Printf("[注册] 获取账号信息成功: SessionID=%s, UserID=%s", info.SessionID, info.UserID)
	}

	// 自动创建账号
	acc := &store.Account{
		Name:         "Auto-" + result.Email[:strings.Index(result.Email, "@")],
		Email:        info.Email,
		ClientCookie: info.ClientCookie,
		ClientUat:    info.ClientUat,
		SessionID:    info.SessionID,
		UserID:       info.UserID,
		ProjectID:    info.ProjectID,
		AgentMode:    "claude-opus-4.5",
		Weight:       1,
		Enabled:      true,
	}

	if err := a.store.CreateAccount(acc); err != nil {
		log.Printf("Failed to save registered account: %v", err)
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":       true,
		"email":         info.Email,
		"password":      result.Password,
		"client_cookie": info.ClientCookie,
		"client_uat":    info.ClientUat,
		"session_id":    info.SessionID,
		"user_id":       info.UserID,
		"account_id":    acc.ID,
	})
}

// HandleRegisterVerify 处理手动验证码验证
func (a *API) HandleRegisterVerify(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req register.RegisterJSON
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}

	if req.SignUpID == "" || req.Code == "" {
		http.Error(w, "sign_up_id and code are required", http.StatusBadRequest)
		return
	}

	result, err := a.register.CompleteRegistration(req.SignUpID, req.Code)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   err.Error(),
		})
		return
	}

	// 自动创建账号
	acc := &store.Account{
		Name:         "Auto-" + result.Email[:strings.Index(result.Email, "@")],
		Email:        result.Email,
		ClientCookie: result.ClientCookie,
		SessionID:    result.SessionID,
		UserID:       result.UserID,
		ProjectID:    "280b7bae-cd29-41e4-a0a6-7f603c43b607",
		AgentMode:    "claude-opus-4.5",
		Weight:       1,
		Enabled:      true,
	}

	if err := a.store.CreateAccount(acc); err != nil {
		log.Printf("Failed to save registered account: %v", err)
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":       true,
		"email":         result.Email,
		"client_cookie": result.ClientCookie,
		"session_id":    result.SessionID,
		"user_id":       result.UserID,
		"account_id":    acc.ID,
	})
}

// HandleBatchRegister 处理批量注册请求
func (a *API) HandleBatchRegister(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method != http.MethodPost {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "Method not allowed",
		})
		return
	}

	var req register.RegisterJSON
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		req = register.RegisterJSON{Count: 1, Workers: 5}
	}

	// 默认值
	count := req.Count
	if count <= 0 {
		count = 1
	}
	// 不限制最大数量，由用户自行决定

	workers := req.Workers
	if workers <= 0 {
		workers = 5
	}
	if workers > 8 {
		workers = 8
	}

	log.Printf("[批量注册API] 收到请求: count=%d, workers=%d", count, workers)

	// 执行批量注册
	batchResult := a.register.BatchRegister(count, workers)

	if batchResult == nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "批量注册返回空结果",
		})
		return
	}

	// 保存成功的账号到数据库
	savedCount := 0
	for i, result := range batchResult.Results {
		if result == nil {
			log.Printf("[批量注册] 结果 #%d 为 nil，跳过", i+1)
			continue
		}

		log.Printf("[批量注册] 处理结果 #%d: email=%s, success=%v, cookie长度=%d, error=%s",
			i+1, result.Email, result.Success, len(result.ClientCookie), result.Error)

		if !result.Success {
			log.Printf("[批量注册] 结果 #%d 注册失败，跳过: %s", i+1, result.Error)
			continue
		}
		if result.ClientCookie == "" {
			log.Printf("[批量注册] 结果 #%d Cookie为空，跳过", i+1)
			continue
		}

		// 获取完整账号信息
		info, err := clerk.FetchAccountInfo(result.ClientCookie)
		if err != nil {
			log.Printf("[批量注册] 获取账号信息失败 (%s): %v", result.Email, err)
			info = &clerk.AccountInfo{
				ClientCookie: result.ClientCookie,
				Email:        result.Email,
				ProjectID:    "280b7bae-cd29-41e4-a0a6-7f603c43b607",
			}
		}

		// 创建账号
		emailParts := strings.Split(result.Email, "@")
		accName := "Auto-" + emailParts[0]

		acc := &store.Account{
			Name:         accName,
			Email:        info.Email,
			ClientCookie: info.ClientCookie,
			ClientUat:    info.ClientUat,
			SessionID:    info.SessionID,
			UserID:       info.UserID,
			ProjectID:    info.ProjectID,
			AgentMode:    "claude-opus-4.5",
			Weight:       1,
			Enabled:      true,
		}

		if err := a.store.CreateAccount(acc); err != nil {
			log.Printf("[批量注册] 保存账号失败 (%s): %v", result.Email, err)
		} else {
			savedCount++
			log.Printf("[批量注册] 保存账号成功 (%s), ID=%d, 已保存%d个", result.Email, acc.ID, savedCount)
		}
	}

	// 构建简化的结果（避免 JSON 编码问题）
	simpleResults := make([]map[string]interface{}, 0)
	for _, r := range batchResult.Results {
		if r == nil {
			continue
		}
		simpleResults = append(simpleResults, map[string]interface{}{
			"email":   r.Email,
			"success": r.Success,
			"error":   r.Error,
		})
	}

	response := map[string]interface{}{
		"success":    true,
		"total":      batchResult.Total,
		"registered": batchResult.Success,
		"failed":     batchResult.Failed,
		"saved":      savedCount,
		"duration":   batchResult.Duration,
		"results":    simpleResults,
	}

	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("[批量注册API] JSON编码失败: %v", err)
	}
}
