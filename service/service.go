package service

import (
	"bytes"
	"context"
	"crypto/sha1"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/smtp"
	"strconv"
	"time"

	datastore "cloud.google.com/go/datastore"
	"github.com/afex/hystrix-go/hystrix"
	"github.com/dchest/passwordreset"
	"github.com/go-kit/kit/metrics"
	"github.com/johnantonusmaximus/accounts/service/types"
	"github.com/johnantonusmaximus/go-common/src/errors"
	opentracing "github.com/opentracing/opentracing-go"
	"github.com/spf13/viper"
	"golang.org/x/crypto/bcrypt"
)

// AccountService wraps the login service with latency and circuit metrics
type accountService struct {
	requestCount   metrics.Counter
	requestLatency metrics.Histogram
	circuitStatus  metrics.Gauge
	config         viper.Viper
}

var auth smtp.Auth

var password string = "Jrojazz12"
var secret []byte = []byte("JimbobTheGreat123!")

// AccountService instantiates the Account service with counters, latency, metrics, and circuit status
func AccountService(requestCount metrics.Counter, requestLatency metrics.Histogram, circuitStatus metrics.Gauge) Service {
	config := InitConfig("./conf")
	return &accountService{requestCount, requestLatency, circuitStatus, *config}
}

// Service defines an Accounts service interface for Go-Kit
type Service interface {
	LoginUserService(ctx context.Context, req types.LoginRequest) (types.AccountResponse, error)
	CreateUserService(ctx context.Context, req types.CreateUserRequest) (types.AccountResponse, error)
	ResetPasswordRequestService(ctx context.Context, req types.ResetPasswordRequest) (types.ResetPasswordRequestResponse, error)
	GetConfig() *viper.Viper
}

func (a accountService) GetConfig() *viper.Viper {
	return &a.config
}

// LoginUser logs in a user
func (a accountService) LoginUserService(ctx context.Context, req types.LoginRequest) (types.AccountResponse, error) {
	if req.Auth.Username == "" || req.Auth.Password == "" {
		return types.AccountResponse{}, errors.ErrMissingParametersReason.New("Username or password is missing")
	}

	LoginResponse, err := a.Login(ctx, req)

	return LoginResponse, err
}

// CreateUser creates a new user
func (a accountService) CreateUserService(ctx context.Context, req types.CreateUserRequest) (types.AccountResponse, error) {
	if req.Account.AccountNumber == "" || req.Account.Company == "" || req.Account.FirstName == "" || req.Account.LastName == "" || req.Account.PhoneNumber == "" || req.Account.Username == "" {
		return types.AccountResponse{}, errors.ErrMissingParametersReason.New("Missing parameters for account creation")
	}

	CreateUserResponse, err := a.CreateUser(ctx, req)
	return CreateUserResponse, err
}

// CreateUser creates a new user
func (a accountService) ResetPasswordRequestService(ctx context.Context, req types.ResetPasswordRequest) (types.ResetPasswordRequestResponse, error) {
	if req.Username == "" {
		return types.ResetPasswordRequestResponse{}, errors.ErrMissingParametersReason.New("Missing parameters for password reset request")
	}

	ResetPasswordRequestResponse, err := a.ResetPasswordRequest(ctx, req)
	return ResetPasswordRequestResponse, err
}

// Login logs in a user
func (a accountService) Login(ctx context.Context, req types.LoginRequest) (types.AccountResponse, error) {
	output := make(chan bool, 1)
	var err error
	var loginResponse types.AccountResponse
	errs := hystrix.Go("LoginUser", func() error {
		loginResponse, err = a.GetUserDataFromDB(ctx, req)
		if err != nil {
			if sErr, ok := err.(*errors.Err); ok {
				if sErr.GetCode() != 404 {
					return sErr
				}
			} else {
				return err
			}
		}
		output <- true
		return nil
	}, nil)

	select {
	case out := <-output:
		if out {
			return loginResponse, err
		}
	case err := <-errs:
		return loginResponse, err
	}

	return loginResponse, err

}

// Login logs in a user
func (a accountService) CreateUser(ctx context.Context, req types.CreateUserRequest) (types.AccountResponse, error) {
	output := make(chan bool, 1)
	var err error
	var createUserResponse types.AccountResponse
	errs := hystrix.Go("CreateUser", func() error {
		err = a.CheckForUserInDB(ctx, req)
		if err != nil {
			if sErr, ok := err.(*errors.Err); ok {
				if sErr.GetCode() != 404 {
					return sErr
				}
			} else {
				return err
			}
		}
		createUserResponse, err = a.CreateUserInDB(ctx, req)
		if err != nil {
			if sErr, ok := err.(*errors.Err); ok {
				if sErr.GetCode() != 404 {
					return sErr
				}
			} else {
				return err
			}
		}
		output <- true
		return nil
	}, nil)

	select {
	case out := <-output:
		if out {
			return createUserResponse, err
		}
	case err := <-errs:
		return createUserResponse, err
	}

	return createUserResponse, err

}

// Login logs in a user
func (a accountService) ResetPasswordRequest(ctx context.Context, req types.ResetPasswordRequest) (types.ResetPasswordRequestResponse, error) {
	output := make(chan bool, 1)
	var err error
	var accountResponse types.AccountResponse
	var resetPasswordRequestResponse types.ResetPasswordRequestResponse
	errs := hystrix.Go("ResetPasswordRequest", func() error {
		accountResponse, err = a.GetUserInDBForPasswordReset(ctx, req)
		if err != nil {
			err = nil
			time.Sleep(3 * time.Second)
			// This exits out of the resetpassword flow without sending an email to anyone
			output <- true
			return err
		}

		resetToken := generateResetToken(accountResponse)
		accountResponse.ResetToken = resetToken
		_, err := a.UpdateUserRecord(ctx, accountResponse)
		if err != nil {
			return err
		}

		err = a.sendPasswordResetEmail(ctx, accountResponse, resetToken)
		if err != nil {
			if sErr, ok := err.(*errors.Err); ok {
				if sErr.GetCode() != 404 {
					return sErr
				}
			} else {
				return err
			}
		}
		output <- true
		return nil
	}, nil)

	select {
	case out := <-output:
		if out {
			return resetPasswordRequestResponse, err
		}
	case err := <-errs:
		return resetPasswordRequestResponse, err
	}

	return resetPasswordRequestResponse, err

}

// GetUserDataFromDB gets the user from the database
func (a accountService) GetUserDataFromDB(ctx context.Context, req types.LoginRequest) (types.AccountResponse, error) {
	span, ctx := opentracing.StartSpanFromContext(ctx, "login_user")
	defer span.Finish()
	var err error
	var resp types.AccountResponse
	defer func(begin time.Time) {
		var code string
		if err != nil {
			code = strconv.Itoa(CodeFrom(err))
		} else {
			code = "200"
		}

		a.requestCount.With("method", "LoginUser", "code", code, "granularity", "login_user").Add(1)
		a.requestLatency.With("method", "LoginUser", "granularity", "login_user").Observe(time.Since(begin).Seconds())
		a.circuitStatus.With("circuit_name", "LoginUser").Set(getCircuitStatus("LoginUser"))
	}(time.Now())

	client, err := datastore.NewClient(ctx, a.config.GetString("PROJECT_ID"))
	if err != nil {
		log.Fatal("Error creating datastore client: ", err)
	}

	key := datastore.NameKey("Account", req.Auth.Username, nil)
	acc := new(types.Account)
	if err = client.Get(ctx, key, acc); err != nil {
		return resp, err
	}

	err = comparePassword(acc.Password, req.Auth.Password)
	if err != nil {
		return resp, err
	}

	resp = types.AccountResponse{
		FirstName:     acc.FirstName,
		LastName:      acc.LastName,
		PhoneNumber:   acc.PhoneNumber,
		Company:       acc.Company,
		Username:      acc.Username,
		AccountNumber: acc.AccountNumber,
	}

	return resp, err
}

// GetUserDataFromDB gets the user from the database
func (a accountService) UpdateUserRecord(ctx context.Context, req types.AccountResponse) (types.AccountResponse, error) {
	span, ctx := opentracing.StartSpanFromContext(ctx, "update_user_record")
	defer span.Finish()
	var err error
	defer func(begin time.Time) {
		var code string
		if err != nil {
			code = strconv.Itoa(CodeFrom(err))
		} else {
			code = "200"
		}

		a.requestCount.With("method", "UpdateUser", "code", code, "granularity", "update_user_record").Add(1)
		a.requestLatency.With("method", "UpdateUser", "granularity", "update_user_record").Observe(time.Since(begin).Seconds())
		a.circuitStatus.With("circuit_name", "UpdateUser").Set(getCircuitStatus("UpdateUser"))
	}(time.Now())

	client, err := datastore.NewClient(ctx, a.config.GetString("PROJECT_ID"))
	if err != nil {
		log.Fatal("Error creating datastore client: ", err)
	}

	accPtr := &req

	newKey := datastore.NameKey("Account", req.Username, nil)
	_, err = client.Put(ctx, newKey, accPtr)
	if err != nil {
		return types.AccountResponse{}, err
	}

	return req, err
}

// GetUserDataFromDB gets the user from the database
func (a accountService) CheckForUserInDB(ctx context.Context, req types.CreateUserRequest) error {
	span, ctx := opentracing.StartSpanFromContext(ctx, "check_for_user")
	defer span.Finish()
	var err error
	defer func(begin time.Time) {
		var code string
		if err != nil {
			code = strconv.Itoa(CodeFrom(err))
		} else {
			code = "200"
		}

		a.requestCount.With("method", "CheckForUserInDB", "code", code, "granularity", "check_for_user").Add(1)
		a.requestLatency.With("method", "CheckForUserInDB", "granularity", "check_for_user").Observe(time.Since(begin).Seconds())
		a.circuitStatus.With("circuit_name", "CheckForUserInDB").Set(getCircuitStatus("CheckForUserInDB"))
	}(time.Now())

	client, err := datastore.NewClient(ctx, a.config.GetString("PROJECT_ID"))
	if err != nil {
		log.Fatal("Error creating datastore client: ", err)
	}
	// Datastore query here
	key := datastore.NameKey("Account", req.Account.Username, nil)
	acc := new(types.Account)
	if err = client.Get(ctx, key, acc); err == nil {
		return errors.ErrDuplicate
	}
	return nil
}

// GetUserInDBForPasswordReset gets the user from the database for password reset
func (a accountService) GetUserInDBForPasswordReset(ctx context.Context, req types.ResetPasswordRequest) (types.AccountResponse, error) {
	span, ctx := opentracing.StartSpanFromContext(ctx, "get_user_for_password_reset")
	defer span.Finish()
	var err error
	var resp types.AccountResponse
	defer func(begin time.Time) {
		var code string
		if err != nil {
			code = strconv.Itoa(CodeFrom(err))
		} else {
			code = "200"
		}

		a.requestCount.With("method", "ResetPasswordRequest", "code", code, "granularity", "get_user_for_password_reset").Add(1)
		a.requestLatency.With("method", "ResetPasswordRequest", "granularity", "get_user_for_password_reset").Observe(time.Since(begin).Seconds())
		a.circuitStatus.With("circuit_name", "ResetPasswordRequest").Set(getCircuitStatus("ResetPasswordRequest"))
	}(time.Now())

	client, err := datastore.NewClient(ctx, a.config.GetString("PROJECT_ID"))
	if err != nil {
		log.Fatal("Error creating datastore client: ", err)
	}
	// Datastore query here
	key := datastore.NameKey("Account", req.Username, nil)
	acc := new(types.Account)
	if err = client.Get(ctx, key, acc); err != nil {
		return resp, err
	}

	resp = types.AccountResponse{
		FirstName:     acc.FirstName,
		LastName:      acc.LastName,
		PhoneNumber:   acc.PhoneNumber,
		Company:       acc.Company,
		Username:      acc.Username,
		AccountNumber: acc.AccountNumber,
		Password:      acc.Password,
		Team:          acc.Team,
		IsAdmin:       acc.IsAdmin,
	}

	return resp, err
}

// GetUserInDBForPasswordReset gets the user from the database for password reset
func (a accountService) sendPasswordResetEmail(ctx context.Context, req types.AccountResponse, resetToken string) error {
	span, ctx := opentracing.StartSpanFromContext(ctx, "send_password_reset_email")
	defer span.Finish()
	var err error
	defer func(begin time.Time) {
		var code string
		if err != nil {
			code = strconv.Itoa(CodeFrom(err))
		} else {
			code = "200"
		}

		a.requestCount.With("method", "SendPasswordResetEmail", "code", code, "granularity", "send_password_reset_email").Add(1)
		a.requestLatency.With("method", "SendPasswordResetEmail", "granularity", "send_password_reset_email").Observe(time.Since(begin).Seconds())
		a.circuitStatus.With("circuit_name", "SendPasswordResetEmail").Set(getCircuitStatus("send_password_reset_email"))
	}(time.Now())

	templateData := EmailTemplateData{
		ResetLink: "https://app.ethos.cloud/#/create-new-password?reset=" + resetToken,
	}

	auth = smtp.PlainAuth("", "zen@kaizentek.io", password, "smtp.gmail.com")
	r := newRequest([]string{req.Username}, "Password Reset Request - ETHOS", "")
	err = r.parseTemplate("./templates/forgot-password-email.html", templateData)
	if err := r.parseTemplate("./templates/forgot-password-email.html", templateData); err == nil {
		_, err := r.sendEmail()
		return err
	}

	return err
}

// CreateUser creates a new user
func (a accountService) CreateUserInDB(ctx context.Context, req types.CreateUserRequest) (types.AccountResponse, error) {
	span, ctx := opentracing.StartSpanFromContext(ctx, "login_user")
	defer span.Finish()
	var err error
	var resp types.AccountResponse
	defer func(begin time.Time) {
		var code string
		if err != nil {
			code = strconv.Itoa(CodeFrom(err))
		} else {
			code = "200"
		}

		a.requestCount.With("method", "CreateUser", "code", code, "granularity", "create_user").Add(1)
		a.requestLatency.With("method", "CreateUser", "granularity", "create_user").Observe(time.Since(begin).Seconds())
		a.circuitStatus.With("circuit_name", "CreateUser").Set(getCircuitStatus("CreateUser"))
	}(time.Now())

	errString := checkForDataErrors(req.Account)
	if len(errString) > 0 {
		return resp, err
	}

	hashedPassword, err := hashAndSaltPassword([]byte(req.Account.Password))
	if err != nil {
		return resp, err
	}
	req.Account.Password = hashedPassword
	accPtr := &req.Account

	client, err := datastore.NewClient(ctx, a.config.GetString("PROJECT_ID"))
	if err != nil {
		log.Fatal("Error creating datastore client: ", err)
	}

	newKey := datastore.NameKey("Account", req.Account.Username, nil)
	_, err = client.Put(ctx, newKey, accPtr)
	if err != nil {
		return resp, err
	}

	resp = types.AccountResponse{
		FirstName:     req.Account.FirstName,
		LastName:      req.Account.LastName,
		PhoneNumber:   req.Account.PhoneNumber,
		Company:       req.Account.Company,
		Username:      req.Account.Username,
		AccountNumber: req.Account.AccountNumber,
		Team:          req.Account.Team,
		IsAdmin:       req.Account.IsAdmin,
	}
	return resp, err
}

func hashAndSaltPassword(p []byte) (string, error) {
	hash, err := bcrypt.GenerateFromPassword(p, bcrypt.MinCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

func comparePassword(hashedPassword string, plainPwd string) error {
	hashBytes := []byte(hashedPassword)
	hashAttempt := []byte(plainPwd)

	err := bcrypt.CompareHashAndPassword(hashBytes, hashAttempt)
	if err != nil {
		return err
	}

	return nil
}

func checkForDataErrors(acc types.Account) string {
	if len(acc.Password) < 5 {
		return "Password not long enough"
	}

	if len(acc.Username) < 1 {
		return "No username provided"
	}

	if len(acc.FirstName) < 1 {
		return "No first name provided"
	}

	if len(acc.LastName) < 1 {
		return "No last name provided"
	}

	if len(acc.PhoneNumber) < 1 {
		return "No phone number provided"
	}

	if len(acc.AccountNumber) < 1 {
		return "No account number provided"
	}

	return ""
}

func newRequest(to []string, subject, body string) *EmailRequest {
	return &EmailRequest{
		From:    "zen@kaizentek.io",
		To:      to,
		Subject: subject,
		Body:    body,
	}
}

func generateResetToken(account types.AccountResponse) string {

	h := sha1.New()
	h.Write([]byte(account.Username + account.AccountNumber))
	bs := h.Sum(nil)
	e := fmt.Sprintf("%x", bs)
	b := []byte(e)

	return passwordreset.NewToken(account.Username, 1*time.Hour, b, secret)
}

func (r *EmailRequest) parseTemplate(templateFileName string, data interface{}) error {
	t, err := template.ParseFiles(templateFileName)
	if err != nil {
		return err
	}
	buf := new(bytes.Buffer)
	if err = t.Execute(buf, data); err != nil {
		return err
	}
	r.Body = buf.String()
	return nil
}

func (r *EmailRequest) sendEmail() (bool, error) {
	mime := "MIME-version: 1.0;\nContent-Type: text/html; charset=\"UTF-8\";\n\n"
	subject := "Subject: " + r.Subject + "!\n"
	msg := []byte(subject + mime + "\n" + r.Body)
	addr := "smtp.gmail.com:587"
	if err := smtp.SendMail(addr, auth, r.From, r.To, msg); err != nil {
		return false, err
	}
	return true, nil
}

func errorResponse(w http.ResponseWriter, code int, err error, response []byte) {
	log.Println("SERVER ERROR:", err)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if len(response) > 0 {
		w.Write(response)
	}
}

func successResponse(w http.ResponseWriter, code int, response []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	w.Write(response)
}

// EmailRequest struct
type EmailRequest struct {
	From    string
	To      []string
	Subject string
	Body    string
}

// EmailTemplateData struct
type EmailTemplateData struct {
	ResetLink string
}
