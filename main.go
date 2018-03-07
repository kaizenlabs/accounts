package main

import (
	"bytes"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/asdine/storm"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"golang.org/x/crypto/bcrypt"
)

// Account defines a user account
type Account struct {
	ID            int    `storm:"id,increment=100"`
	FirstName     string `json:"firstName"`
	LastName      string `json:"lastName"`
	PhoneNumber   string `json:"phoneNumber"`
	Company       string `json:"company" storm:"index"`
	Username      string `json:"username" storm:"unique"`
	Password      string `json:"password"`
	AccountNumber string `json:"accountNumber" storm:"index"`
}

// Auth represent an authentication request
type Auth struct {
	Username string
	Password string
}

// PORT is the port for the server
const PORT string = "3002"

func main() {
	r := mux.NewRouter()
	r.HandleFunc("/login", login).Methods("POST") // GET will be handles by React app
	r.HandleFunc("/create-user", createUser).Methods("POST")
	originsOK := handlers.AllowedOrigins([]string{"*"})
	fmt.Printf("Listening on port %s", PORT)
	log.Fatal(http.ListenAndServe(":"+PORT, handlers.CORS(originsOK)(r)))
}

func login(w http.ResponseWriter, r *http.Request) {
	var user Account
	var auth Auth
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Println("SERVER ERROR:", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	err = json.Unmarshal(body, &auth)
	if err != nil {
		log.Println("SERVER ERROR:", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	db, err := storm.Open("account.db")
	if err != nil {
		log.Println("SERVER ERROR:", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	defer db.Close()
	err = db.One("Username", auth.Username, &user)
	if err != nil {
		if err == storm.ErrNotFound {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		log.Println("SERVER ERROR:", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	err = comparePassword(user.Password, auth.Password)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	response := struct {
		FirstName     string
		LastName      string
		PhoneNumber   string
		Company       string
		Username      string
		AccountNumber string
	}{
		user.FirstName,
		user.LastName,
		user.PhoneNumber,
		user.Company,
		user.Username,
		user.AccountNumber,
	}

	json, err := json.Marshal(response)
	if err != nil {
		log.Println("SERVER ERROR:", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(json)
}

func createUser(w http.ResponseWriter, r *http.Request) {
	var accToAdd Account
	db, err := storm.Open("account.db")
	if err != nil {
		response := struct {
			Error string
		}{err.Error()}
		json, err2 := json.Marshal(response)
		if err2 != nil {
			log.Printf("SERVER ERROR: %v\n", err2)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			w.Write(json)
			return
		}
		log.Println("SERVER ERROR:", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		w.Write(json)
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
			log.Printf("SERVER ERROR: %v\n", err2)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			w.Write(json)
			return
		}
		log.Printf("SERVER ERROR: %s\n", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		w.Write(json)
		return
	}

	err = json.Unmarshal(body, &accToAdd)
	if err != nil {
		response := struct {
			Error string
		}{err.Error()}
		json, err2 := json.Marshal(response)
		if err2 != nil {
			log.Printf("SERVER ERROR: %v\n", err2)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			w.Write(json)
			return
		}
		log.Printf("SERVER ERROR: %s\n", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		w.Write(json)
		return
	}

	errString := checkForDataErrors(accToAdd)
	if len(errString) > 0 {
		response := struct {
			Error string
		}{errString}
		json, err2 := json.Marshal(response)
		if err2 != nil {
			log.Printf("SERVER ERROR: %v\n", err2)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
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
		log.Printf("SERVER ERROR: %s\n", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
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
			log.Printf("SERVER ERROR: %v\n", err2)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			w.Write(json)
			return
		}
		log.Printf("SERVER ERROR: %v\n", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		w.Write(json)
		return
	}

	json, err := json.Marshal(accToAdd)
	if err != nil {
		log.Printf("SERVER ERROR: %s\n", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		w.Write(json)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(json)
}

// Serialize serializes an account for storage
func (acc Account) Serialize() []byte {
	var buffer bytes.Buffer

	encoder := gob.NewEncoder(&buffer)
	err := encoder.Encode(acc)
	if err != nil {
		log.Fatal(err)
	}
	return buffer.Bytes()
}

// DeserializeAccount deserializes an account
func DeserializeAccount(d []byte) Account {
	var acc Account

	decoder := gob.NewDecoder(bytes.NewReader(d))
	err := decoder.Decode(&acc)
	if err != nil {
		log.Fatal(err)
	}
	return acc
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

func checkForDataErrors(acc Account) string {
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
