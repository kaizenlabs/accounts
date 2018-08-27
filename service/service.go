package service

import (
	"context"
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/afex/hystrix-go/hystrix"
	"github.com/asdine/storm"
	"github.com/go-kit/kit/metrics"

	"github.com/johnantonusmaximus/Accounts/service/types"
	"github.com/johnantonusmaximus/go-common/src/errors"
	"github.com/spf13/viper"
	"golang.org/x/crypto/bcrypt"
)

// LoginService wraps the login service with latency and circuit metrics
type LoginService struct {
	requestCount   metrics.Counter
	requestLatency metrics.Histogram
	circuitStatus  metrics.Gauge
	config         viper.Viper
}

// Service defines an Accounts service interface for Go-Kit
type Service interface {
	LoginUser(ctx context.Context, req types.LoginRequest)
	CreateUser(w http.ResponseWriter, r *http.Request)
	GetConfig() *viper.Viper
}

// LoginUser logs in a user
func (l LoginService) LoginUser(ctx context.Context, req types.LoginRequest) (r types.LoginResponse, err error) {
	if req.Auth.Username == "" || req.Auth.Password == "" {
		return types.LoginResponse{}, errors.ErrMissingParametersReason.New("Username or password is missing")
	}

	LoginResponse, err := l.Login(ctx, req)

	return LoginResponse, err
}

// Login logs in a user
func (l LoginService) Login(ctx context.Context, req types.LoginRequest) (r types.LoginResponse, err error) {
	output := make(chan bool, 1)
	var loginResponse types.LoginResponse
	errs := hystrix.Go("LoginUser", func() error {
		loginResponse, err = l.GetUserDataFromDB(ctx, req)
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

func (l LoginService) GetUserDataFromDB(ctx context.Context, req types.LoginRequest) (types.LoginResponse, error) {
	span, ctx := opentracing.StartSpanFromContext(ctx, "login_user")
	defer span.Finish()
	var err error 
	var resp types.LoginResponse

	defer func(begin time.Time) {
		var code string 
		if err != nil {
			code = strconv.Itoa(CodeFrom(err))
		} else {
			code = "200"
		}

		p.requestCount.With("method", "LoginUser", "code", code, "granularity", "login_user").Add(1)
		p.requestLatency.With("method", "LoginUser", "granularity", "login_user").Observe(time.Since(begin).Seconds())
		p.circuitStatus.With("circuit_name", "LoginUser").Set(getCircuitStatus("LoginUser"))
	}(time.Now())
	
	db, err := storm.Open("account.db")
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, err, []byte{})
		return
	}
	defer db.Close()
	err = db.One("Username", req.Auth.Username, &resp)
	if err != nil {
		if err == storm.ErrNotFound {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		errorResponse(w, http.StatusInternalServerError, err, []byte{})
		return
	}

	err = comparePassword(user.Password, auth.Password)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	response := types.LoginResponse{
		FirstName:     user.FirstName,
		LastName:      user.LastName,
		PhoneNumber:   user.PhoneNumber,
		Company:       user.Company,
		Username:      user.Username,
		AccountNumber: user.AccountNumber,
	}

	json, err := json.Marshal(response)
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, err, []byte{})
		return
	}
	successResponse(w, http.StatusOK, json)
}
}

// CreateUser creates a new user
func CreateUser(w http.ResponseWriter, r *http.Request) {
	var accToAdd types.Account
	db, err := storm.Open("account.db")
	if err != nil {
		response := struct {
			Error string
		}{err.Error()}
		json, err2 := json.Marshal(response)
		if err2 != nil {
			errorResponse(w, http.StatusInternalServerError, err2, []byte{})
			return
		}
		errorResponse(w, http.StatusInternalServerError, err, json)
		return
	}
	defer db.Close()
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		response := struct {
			Error string
		}{err.Error()}
		json, err2 := json.Marshal(response)
		if err2 != nil {
			errorResponse(w, http.StatusInternalServerError, err2, json)
			return
		}
		errorResponse(w, http.StatusInternalServerError, err, json)
		return
	}

	err = json.Unmarshal(body, &accToAdd)
	if err != nil {
		response := struct {
			Error string
		}{err.Error()}
		json, err2 := json.Marshal(response)
		if err2 != nil {
			errorResponse(w, http.StatusInternalServerError, err2, []byte{})
			return
		}
		errorResponse(w, http.StatusBadRequest, err, json)
		return
	}

	errString := checkForDataErrors(accToAdd)
	if len(errString) > 0 {
		response := struct {
			Error string
		}{errString}
		json, err2 := json.Marshal(response)
		if err2 != nil {
			errorResponse(w, http.StatusInternalServerError, err2, []byte{})
			return
		}
		log.Println("BAD REQUEST: ", errString)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		w.Write(json)
		return
	}

	hashedPassword, err := hashAndSaltPassword([]byte(accToAdd.Password))
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, err, []byte{})
		return
	}
	accToAdd.Password = hashedPassword
	accToAdd.ID = 0

	err = db.Save(&accToAdd)
	if err != nil {
		response := struct {
			Error string
		}{err.Error()}
		json, err2 := json.Marshal(response)
		if err2 != nil {
			errorResponse(w, http.StatusInternalServerError, err2, []byte{})
			return
		}
		errorResponse(w, http.StatusInternalServerError, err, json)
		return
	}

	json, err := json.Marshal(accToAdd)
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, err, []byte{})
		return
	}
	successResponse(w, http.StatusOK, json)
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
