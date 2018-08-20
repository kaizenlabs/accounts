package service

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/asdine/storm"
	"github.com/johnantonusmaximus/Accounts/service/types"
	"github.com/spf13/viper"
	"golang.org/x/crypto/bcrypt"
)

// Service defines an Accounts service interface for Go-Kit
type Service interface {
	Login(ctx context.Context, req types.LoginEndpointRequest)
	CreateUser(w http.ResponseWriter, r *http.Request)
	GetConfig() *viper.Viper
}

// Login logs in a user
func Login(w http.ResponseWriter, r *http.Request) {
	var user types.Account
	var auth types.Auth
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		errorResponse(w, http.StatusBadRequest, err, []byte{})
		return
	}
	err = json.Unmarshal(body, &auth)
	if err != nil {
		fmt.Println("Yoooo")
		errorResponse(w, http.StatusBadRequest, err, []byte{})
		return
	}
	db, err := storm.Open("account.db")
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, err, []byte{})
		return
	}
	defer db.Close()
	err = db.One("Username", auth.Username, &user)
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
