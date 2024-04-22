package models

import (
	"fmt"
	"regexp"

	validation "github.com/go-ozzo/ozzo-validation"
	"github.com/go-ozzo/ozzo-validation/is"
	"gitlab.com/Nebil/errors"
	"go.uber.org/zap"
)

type (
	User struct {
		Username string `json:"username,omitempty"`
		Email    string `json:"email,omitempty"`
		Password string `json:"password,omitempty"`
	}
	UserLogin struct {
		ID       string `json:"id,omitempty"`
		Username string `json:"username,omitempty"`
		Password string `json:"password,omitempty"`
	}
	RefToken struct {
		ID            string `json:"id,omitempty"`
		Username      string `json:"username,omitempty"`
		Refresh_Token string `json:"refresh_token,omitempty"`
		IsUsed        bool   `json:"is_used,omitempty"`
	}
)

var usernameRule = []validation.Rule{
	validation.Required.Error("username required"),
	validation.Length(5, 20),
	validation.Match(regexp.MustCompile(`^[A-Za-z]\w{5,}$`)),
}

var emailRule = []validation.Rule{
	validation.Required.Error("email required"),
	is.Email,
}

var passwordRule = []validation.Rule{
	validation.Required.Error("password required"),
	validation.Length(8, 50),
	validation.Match(regexp.MustCompile(`[A-Z]`)),
	validation.Match(regexp.MustCompile(`[a-z]`)),
	validation.Match(regexp.MustCompile(`[0-9]`)),
	validation.Match(regexp.MustCompile(`[-\#\$\.\%\&\*]`)),
}

func NewLogger() (*zap.Logger, error) {
	logger, err := zap.NewDevelopment()
	if err != nil {
		return nil, err
	}
	defer logger.Sync()

	return logger, nil
}

func (u User) Validate() error {
	log, err := NewLogger()
	if err != nil {
		return err
	}
	err = validation.ValidateStruct(&u,
		validation.Field(&u.Username, usernameRule...),
		validation.Field(&u.Email, emailRule...),
		validation.Field(&u.Password, passwordRule...),
	)

	if err != nil {
		fmt.Println(err.Error())
		log.Error("invalid input", zap.Error(err))
		err = errors.ErrInvalidInput.Wrap(err, err.Error())
		return err
	}
	return nil
}

func (u UserLogin) Validate() error {
	log, err := NewLogger()
	if err != nil {
		return err
	}

	err = validation.ValidateStruct(&u,
		validation.Field(&u.Username, usernameRule...),
		validation.Field(&u.Password, passwordRule...))

	if err != nil {
		log.Error("invalid input", zap.Error(err))
		err = errors.ErrInvalidInput.Wrap(err, "invalid input")
		return err
	}

	return nil
}
