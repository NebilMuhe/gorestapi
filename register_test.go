package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/cucumber/godog"
)

func (u *UserRegistration) theSystemSholudReturn(arg1 string) error {
	if u.errorMessage == arg1 {
		return nil
	}
	return errors.New(arg1)
}

func (u *UserRegistration) userEntersAnd(arg1, arg2, arg3 string) error {
	router, _, _ := setupRouter()
	us := &User{
		Username: arg1,
		Email:    arg2,
		Password: arg3,
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

	errr := strings.Split(customError.ErrorMessage, ": ")
	u.errorMessage = errr[1]
	return nil
}

func (u *UserRegistration) userIsOnRegistrePage() error {
	return nil
}

func (u *UserRegistration) iSendRequestToWithPayload(arg1, arg2 string, arg3 *godog.DocString) error {
	router, _, _ := setupRouter()
	request := httptest.NewRequest(arg1, arg2, strings.NewReader(string(arg3.Content)))
	request.Header.Add("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, request)
	u.status = w.Code
	u.response = w.Body.String()
	return nil
}

func (u *UserRegistration) theResponseCodeShouldBe(arg1 int) error {
	if u.status == arg1 {
		return nil
	}
	return errors.New("unable to register user")
}

func (u *UserRegistration) theResponsePayloadShouldMatchJson(arg1 *godog.DocString) error {
	var userdata User
	if err := json.Unmarshal([]byte(u.response), &userdata); err != nil {
		return err
	}

	var expectedData User
	if err := json.Unmarshal([]byte(arg1.Content), &expectedData); err != nil {
		return err
	}

	equal := reflect.DeepEqual(userdata, expectedData)

	if equal {
		return nil
	}
	return errors.New("invalid response")
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
