package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/cucumber/godog"
)

func (u *UserRegistration) userIsOnRegistrePage() error {
	return nil
}

func (u *UserRegistration) userEntersAnd(username, email, password string) error {
	router, _, _ := setupRouter()

	us := &User{
		Username: username,
		Email:    email,
		Password: password,
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

	fmt.Println("custom ", customError.ErrorMessage)
	u.errorMessage = customError.ErrorMessage

	// defer db.Exec("DELETE FROM users;")
	return nil
}

func (u *UserRegistration) theSystemSholudReturn(err string) error {
	if u.errorMessage == err {
		return nil
	}
	return godog.ErrPending
}

func (u *UserRegistration) iSendRequestToWithPayload(method, url string, payload *godog.DocString) error {
	router, db, _ := setupRouter()
	defer db.Exec("DELETE FROM users;")
	request := httptest.NewRequest(method, url, strings.NewReader(string(payload.Content)))
	request.Header.Add("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, request)
	u.status = w.Code
	u.response = w.Body.String()

	fmt.Println("code ", w.Code)
	return nil
}

func (u *UserRegistration) theResponseCodeShouldBe(code int) error {
	if u.status == code {
		return nil
	}
	return godog.ErrPending
}

func (u *UserRegistration) theResponsePayloadShouldMatchJson(payload *godog.DocString) error {
	var userdata User
	if err := json.Unmarshal([]byte(u.response), &userdata); err != nil {
		return err
	}

	var expectedData User
	if err := json.Unmarshal([]byte(payload.Content), &expectedData); err != nil {
		return err
	}

	equal := reflect.DeepEqual(userdata, expectedData)

	if equal {
		return nil
	}

	return godog.ErrPending
}

func InitializeRegisterScenario(ctx *godog.ScenarioContext) {
	user := &UserRegistration{}
	ctx.Step(`^User is on registre page$`, user.userIsOnRegistrePage)
	ctx.Step(`^User enters "([^"]*)",""([^"]*)"", and "([^"]*)"$`, user.userEntersAnd)
	ctx.Step(`^The system sholud return "([^"]*)"$`, user.theSystemSholudReturn)

	ctx.Step(`^I send "([^"]*)" request to "([^"]*)" with payload:$`, user.iSendRequestToWithPayload)
	ctx.Step(`^the response code should be (\d+)$`, user.theResponseCodeShouldBe)
	ctx.Step(`^the response payload should match json:$`, user.theResponsePayloadShouldMatchJson)
}

func TestRegister(t *testing.T) {
	suite := godog.TestSuite{
		ScenarioInitializer: InitializeRegisterScenario,
		Options: &godog.Options{
			Format:   "pretty",
			Paths:    []string{"features/register.feature"},
			TestingT: t, // Testing instance that will run subtests.
		},
	}

	if suite.Run() != 0 {
		t.Fatal("non-zero status returned, failed to run feature tests")
	}
}
