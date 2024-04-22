package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cucumber/godog"
)

type UserRegistration struct {
	errorMessage string
}

type User struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

type CustomError struct {
	Error        string `json:"error"`
	ErrorMessage string `json:"errormessage"`
	Status       int    `json:"status"`
}

// var server = handler.NewServer()

func (u *UserRegistration) aUserWithTheUsernameIsAlreadyRegistered(username string) error {
	router, _, _ := setupRouter()

	us := &User{
		Username: "testuser",
		Email:    "abc123@gmail.com",
		Password: "12ABcd%^",
	}

	req, err := json.Marshal(us)
	if err != nil {
		return err
	}

	request := httptest.NewRequest(http.MethodPost, "/api/register", strings.NewReader(string(req)))
	request.Header.Add("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, request)
	responseBytes := w.Body.Bytes()
	var customError CustomError

	err = json.Unmarshal(responseBytes, &customError)
	if err != nil {
		return err
	}
	u.errorMessage = customError.ErrorMessage

	return nil
}

func (u *UserRegistration) iAttemptToRegisterWithTheSameUsername() error {
	if u.errorMessage == "user already exists" {
		return nil
	}
	return errors.New("username does not exist")
}

func (u *UserRegistration) theSystemShouldReturnAnErrorMessageIndicatingThatThe() error {
	if u.errorMessage != "user already exists" {
		return errors.New("username doesn't exist")
	}
	return nil
}

func (u *UserRegistration) iAmRegisteringWithAnInvalidEmailFormat() error {
	user := map[string]string{
		"username": "testuser",
		"email":    "abc123gmail.com",
		"password": "12ABcd%^",
	}

	req, err := json.Marshal(user)

	if err != nil {
		return err
	}

	res, err := http.Post("http://localhost:8000/api/register", "application/json", strings.NewReader(string(req)))
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if res.StatusCode == http.StatusBadRequest {
		u.errorMessage = "invalid email format"
		return nil
	}

	return errors.New("valid email")
}

func (u *UserRegistration) iSubmitTheRegistrationForm() error {
	return nil
}

func (u *UserRegistration) theSystemShouldReturnAnErrorMessageIndicatingThatTheEmailFormatIsInvalid() error {
	if u.errorMessage == "invalid email format" {
		return nil
	}
	return errors.New("email format is valid")
}

func (u *UserRegistration) iAmRegisteringWithAWeakPassword() error {
	user := map[string]string{
		"username": "testuser",
		"email":    "abc123@gmail.com",
		"password": "12345678",
	}
	req, err := json.Marshal(user)
	if err != nil {
		return err
	}

	res, err := http.Post("http://localhost:8000/api/register", "application/json", strings.NewReader(string(req)))
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if res.StatusCode == http.StatusBadRequest {
		u.errorMessage = "the password is not strong enough"
		return nil
	}
	return errors.New("strong password")
}

func (u *UserRegistration) theSystemShouldReturnAnErrorMessageIndicatingThatThePasswordIsNotStrongEnough() error {
	if u.errorMessage == "the password is not strong enough" {
		return nil
	}
	return errors.New("password is strong enough")
}

func (u *UserRegistration) iAmRegisteringWithAUsernameLessThanCharactersLong(arg1 int) error {
	user := map[string]string{
		"username": "test",
		"email":    "abc123@gmail.com",
		"password": "12345678",
	}
	req, err := json.Marshal(user)
	if err != nil {
		return err
	}

	res, err := http.Post("http://localhost:8000/api/register", "application/json", strings.NewReader(string(req)))
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if res.StatusCode == http.StatusBadRequest {
		u.errorMessage = "the username must be at least characters long"
		return nil
	}
	return errors.New("valid username")
}

func (u *UserRegistration) theSystemShouldReturnAnErrorMessageIndicatingThatTheUsernameMustBeAtLeastCharactersLong(minLength int) error {
	if u.errorMessage == "the username must be at least characters long" {
		return nil
	}
	return errors.New("username has more than 5 characters long")
}

func (u *UserRegistration) iAmRegisteringWithAPasswordThatDoesNotMeetTheStrengthRequirements() error {
	user := map[string]string{
		"username": "testuser",
		"email":    "abc123@gmail.com",
		"password": "12345tghik",
	}
	req, err := json.Marshal(user)
	if err != nil {
		return err
	}

	res, err := http.Post("http://localhost:8000/api/register", "application/json", strings.NewReader(string(req)))
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if res.StatusCode == http.StatusBadRequest {
		u.errorMessage = "at least 8 characters long, with at least one uppercase letter, one lowercase letter, one digit, and one special character"
		return nil
	}

	return errors.New("valid password")
}

func (u *UserRegistration) theSystemShouldReturnAnErrorMessageIndicatingThePasswordRequirementsEgAtLeastCharactersLongWithAtLeastOneUppercaseLetterOneLowercaseLetterOneDigitAndOneSpecialCharacter(length int) error {
	if u.errorMessage == "at least 8 characters long, with at least one uppercase letter, one lowercase letter, one digit, and one special character" {
		return nil
	}
	return errors.New("strong password")
}

func (u *UserRegistration) iAmARegisteredUserWithValidCredentials() error {
	user := map[string]string{
		"username": "nebil12",
		"email":    "nebil@gmail.com",
		"password": "1234ABcd%^",
	}
	req, err := json.Marshal(user)
	if err != nil {
		return err
	}

	res, err := http.Post("http://localhost:8000/api/register", "application/json", strings.NewReader(string(req)))
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if res.StatusCode == http.StatusCreated {
		u.errorMessage = "user registered"
		return nil
	}
	return errors.New("unable to register user")
}

func (u *UserRegistration) iLogInWithMyUsernameAndPassword() error {
	if u.errorMessage == "user registered" {
		user := map[string]string{
			"username": "nebil12",
			"password": "1234ABcd%^",
		}
		req, err := json.Marshal(user)
		if err != nil {
			return err
		}

		res, err := http.Post("http://localhost:8000/api/login", "application/json", strings.NewReader(string(req)))
		if err != nil {
			return err
		}
		defer res.Body.Close()

		if res.StatusCode == http.StatusOK {
			u.errorMessage = "access token and refresh token generated"
			return nil
		}
	}
	return errors.New("unable to login user")
}

func (u *UserRegistration) theSystemShouldGenerateAJWTTokenForAuthenticationAndIssueARefreshToken() error {
	if u.errorMessage == "access token and refresh token generated" {
		return nil
	}
	return errors.New("unable to generate refresh token")
}

func (u *UserRegistration) iAmAttemptingToLogInWithAnInvalidUsername() error {
	user := map[string]string{
		"username": "nebil10",
		"password": "1234ABcd%^",
	}
	req, err := json.Marshal(user)
	if err != nil {
		return err
	}

	res, err := http.Post("http://localhost:8000/api/login", "application/json", strings.NewReader(string(req)))
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode == http.StatusNotFound {
		u.errorMessage = "the username is not registered"
		return nil
	}
	return errors.New("username registered")
}

func (u *UserRegistration) iSubmitTheLoginForm() error {
	return nil
}

func (u *UserRegistration) theSystemShouldReturnAnErrorMessageIndicatingThatTheUsernameIsNotRegistered() error {
	if u.errorMessage == "the username is not registered" {
		return nil
	}
	return errors.New("user already reigtered")
}

func (u *UserRegistration) iAmAttemptingToLogInWithAnInvalidPassword() error {
	user := map[string]string{
		"username": "nebil12",
		"password": "1234ABcd$%",
	}
	req, err := json.Marshal(user)
	if err != nil {
		return err
	}

	res, err := http.Post("http://localhost:8000/api/login", "application/json", strings.NewReader(string(req)))
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if res.StatusCode == http.StatusBadRequest {
		u.errorMessage = "the password is incorrect"
		return nil
	}
	return errors.New("password is correct")
}

func (u *UserRegistration) theSystemShouldReturnAnErrorMessageIndicatingThatThePasswordIsIncorrect() error {
	if u.errorMessage == "the password is incorrect" {
		return nil
	}
	return errors.New("password is correct")
}

func InitializeScenario(ctx *godog.ScenarioContext) {
	user := &UserRegistration{}

	ctx.Step(`^a user with the username "([^"]*)" is already registered,$`,
		user.aUserWithTheUsernameIsAlreadyRegistered)
	ctx.Step(`^I attempt to register with the same username,$`,
		user.iAttemptToRegisterWithTheSameUsername)
	ctx.Step(`^the system should return an error message indicating that the username already exists.$`,
		user.theSystemShouldReturnAnErrorMessageIndicatingThatThe)

	// ctx.Step(`^I am registering with an invalid email format,$`,
	// 	user.iAmRegisteringWithAnInvalidEmailFormat)
	// ctx.Step(`^I submit the registration form,$`,
	// 	user.iSubmitTheRegistrationForm)
	// ctx.Step(`^the system should return an error message indicating that the email format is invalid\.$`,
	// 	user.theSystemShouldReturnAnErrorMessageIndicatingThatTheEmailFormatIsInvalid)

	// ctx.Step(`^I am registering with a weak password,$`,
	// 	user.iAmRegisteringWithAWeakPassword)
	// ctx.Step(`^the system should return an error message indicating that the password is not strong enough\.$`,
	// 	user.theSystemShouldReturnAnErrorMessageIndicatingThatThePasswordIsNotStrongEnough)

	// ctx.Step(`^I am registering with a username less than (\d+) characters long,$`,
	// 	user.iAmRegisteringWithAUsernameLessThanCharactersLong)
	// ctx.Step(`^the system should return an error message indicating that the username must be at least (\d+) characters long\.$`,
	// 	user.theSystemShouldReturnAnErrorMessageIndicatingThatTheUsernameMustBeAtLeastCharactersLong)

	// ctx.Step(`^I am registering with a password that does not meet the strength requirements,$`,
	// 	user.iAmRegisteringWithAPasswordThatDoesNotMeetTheStrengthRequirements)
	// ctx.Step(`^the system should return an error message indicating the password requirements \(e\.g\., at least (\d+) characters long, with at least one uppercase letter, one lowercase letter, one digit, and one special character\)\.$`,
	// 	user.theSystemShouldReturnAnErrorMessageIndicatingThePasswordRequirementsEgAtLeastCharactersLongWithAtLeastOneUppercaseLetterOneLowercaseLetterOneDigitAndOneSpecialCharacter)

	// ctx.Step(`^I am a registered user with valid credentials,$`,
	// 	user.iAmARegisteredUserWithValidCredentials)
	// ctx.Step(`^I log in with my username and password,$`,
	// 	user.iLogInWithMyUsernameAndPassword)
	// ctx.Step(`^the system should generate a JWT token for authentication and issue a refresh token$`,
	// 	user.theSystemShouldGenerateAJWTTokenForAuthenticationAndIssueARefreshToken)

	// ctx.Step(`^I am attempting to log in with an invalid username,$`,
	// 	user.iAmAttemptingToLogInWithAnInvalidUsername)
	// ctx.Step(`^I submit the login form,$`,
	// 	user.iSubmitTheLoginForm)
	// ctx.Step(`^the system should return an error message indicating that the username is not registered\.$`,
	// 	user.theSystemShouldReturnAnErrorMessageIndicatingThatTheUsernameIsNotRegistered)

	// ctx.Step(`^I am attempting to log in with an invalid password,$`,
	// 	user.iAmAttemptingToLogInWithAnInvalidPassword)
	// ctx.Step(`^the system should return an error message indicating that the password is incorrect\.$`,
	// 	user.theSystemShouldReturnAnErrorMessageIndicatingThatThePasswordIsIncorrect)

}

func TestFeatures(t *testing.T) {
	suite := godog.TestSuite{
		ScenarioInitializer: InitializeScenario,
		Options: &godog.Options{
			Format:   "pretty",
			Paths:    []string{"features/godogs.feature"},
			TestingT: t, // Testing instance that will run subtests.
		},
	}

	if suite.Run() != 0 {
		t.Fatal("non-zero status returned, failed to run feature tests")
	}
}
