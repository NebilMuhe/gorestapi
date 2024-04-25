package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cucumber/godog"
	"gitlab.com/Nebil/helpers"
)

func (u *UserRegistration) theSystemSholudReturnAnError(err string) error {
	if u.errorMessage == err {
		return nil
	}
	return errors.New("invalid input")
}

func (u *UserRegistration) userEnterAnd(username, password string) error {
	logger := helpers.NewLogger()
	router, _, _ := setupRouter(logger)
	us := &User{
		Username: username,
		Password: password,
	}

	req, err := json.Marshal(us)
	if err != nil {
		return err
	}
	request := httptest.NewRequest(http.MethodPost, "/api/login", strings.NewReader(string(req)))
	request.Header.Add("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, request)

	responseBytes := w.Body.Bytes()
	var customError CustomError

	err = json.Unmarshal(responseBytes, &customError)
	if err != nil {
		return err
	}

	errr := strings.Split(customError.ErrorMessage, ": ")
	u.errorMessage = errr[1]
	return nil
}

func (u *UserRegistration) userIsOnLoginPage() error {
	return nil
}

func (u *UserRegistration) theResponseCodeShouldBeAndError(code int, err string) error {
	fmt.Println("correct", err == u.errorMessage)
	fmt.Println(err)
	fmt.Println(u.errorMessage)
	if code == u.status && err == u.errorMessage {
		return nil
	}
	return errors.New("invalid response")
}

func (u *UserRegistration) iSendRequestToUrlWithPayload(method, url string, payload *godog.DocString) error {
	logger := helpers.NewLogger()
	router, _, _ := setupRouter(logger)
	request := httptest.NewRequest(method, url, strings.NewReader(string(payload.Content)))
	request.Header.Add("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, request)
	u.status = w.Code
	responseBytes := w.Body.Bytes()
	var customError CustomError

	err := json.Unmarshal(responseBytes, &customError)
	if err != nil {
		return err
	}

	u.errorMessage = customError.ErrorMessage

	return nil
}

func (u *UserRegistration) theResponseCodeShouldBeAndIssueJWT(code int) error {
	if u.status == code {
		return nil
	}
	return errors.New("token already issued")
}

func InitializeLoginScenario(ctx *godog.ScenarioContext) {
	user := &UserRegistration{}
	ctx.Step(`^User is on login page$`, user.userIsOnLoginPage)
	ctx.Step(`^User enters "([^"]*)" and "([^"]*)"$`, user.userEnterAnd)
	ctx.Step(`^The system sholud return an error "([^"]*)"$`, user.theSystemSholudReturnAnError)

	ctx.Step(`^I send "([^"]*)" request to url "([^"]*)" with payload:$`, user.iSendRequestToUrlWithPayload)
	ctx.Step(`^the response code should be (\d+) and error "([^"]*)"$`, user.theResponseCodeShouldBeAndError)

	ctx.Step(`^the response code should be (\d+) and issue JWT$`, user.theResponseCodeShouldBeAndIssueJWT)
}

func TestLogin(t *testing.T) {
	suite := godog.TestSuite{
		ScenarioInitializer: InitializeLoginScenario,
		Options: &godog.Options{
			Format:   "pretty",
			Paths:    []string{"features/login.feature"},
			TestingT: t, // Testing instance that will run subtests.
		},
	}

	if suite.Run() != 0 {
		t.Fatal("non-zero status returned, failed to run feature tests")
	}
}
