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
)

func (u *UserRegistration) theSystemSholudReturn(arg1 string) error {
	fmt.Println(u.errorMessage)
	fmt.Println(arg1)
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

	// fmt.Println(customError.ErrorMessage)
	// u.errorMessage = customError.ErrorMessage
	errr := strings.Split(customError.ErrorMessage, ": ")
	u.errorMessage = errr[1]
	fmt.Println(errr[1])
	return nil
}

func (u *UserRegistration) userIsOnRegistrePage() error {
	return nil
}

func InitializeRegisterScenario(ctx *godog.ScenarioContext) {
	user := &UserRegistration{}
	ctx.Step(`^User is on registre page$`, user.userIsOnRegistrePage)
	ctx.Step(`^User enters "([^"]*)",""([^"]*)"", and "([^"]*)"$`, user.userEntersAnd)
	ctx.Step(`^The system sholud return "([^"]*)"$`, user.theSystemSholudReturn)
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
