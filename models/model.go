package models

import (
	"context"
	"regexp"

	validation "github.com/go-ozzo/ozzo-validation"
	"github.com/go-ozzo/ozzo-validation/is"
	"gitlab.com/Nebil/errors"
	"gitlab.com/Nebil/utils"
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
	validation.Length(5, 20).Error("Username length must be atleast 5 characters"),
	validation.Match(regexp.MustCompile(`^[A-Za-z]\w{4,}$`)).Error("username must be valid"),
	is.Alphanumeric,
}

var emailRule = []validation.Rule{
	validation.Required.Error("email required"),
	is.Email.Error("email must be valid"),
}

var passwordRule = []validation.Rule{
	validation.Required.Error("password required"),
	validation.Length(8, 50).Error("Password length must be atleast 8 characters long"),
	validation.Match(regexp.MustCompile(`[A-Z]`)).Error("Password must contain atleast one uppercase letters,one lowercase letters, digits and special characters"),
	validation.Match(regexp.MustCompile(`[a-z]`)).Error("Password must contain atleast one uppercase letters,one lowercase letters, digits and special characters"),
	validation.Match(regexp.MustCompile(`[0-9]`)).Error("Password must contain atleast one uppercase letters,one lowercase letters, digits and special characters"),
	validation.Match(regexp.MustCompile(`[-\#\$\.\%\&\*]`)).Error("Password must contain atleast one uppercase letters,one lowercase letters, digits and special characters"),
}

func (u User) Validate(ctx context.Context, logger utils.Logger) error {
	err := validation.ValidateStruct(&u,
		validation.Field(&u.Username, usernameRule...),
		validation.Field(&u.Email, emailRule...),
		validation.Field(&u.Password, passwordRule...),
	)

	if err != nil {
		logger.Error(ctx, "invalid input", zap.Error(err), zap.Any("user input", u))
		err = errors.ErrInvalidInput.Wrap(err, err.Error())
		return err
	}
	return nil
}

func (u UserLogin) Validate(ctx context.Context, logger utils.Logger) error {
	err := validation.ValidateStruct(&u,
		validation.Field(&u.Username, usernameRule...),
		validation.Field(&u.Password, passwordRule...))

	if err != nil {
		logger.Error(ctx, "invalid input", zap.Error(err), zap.Any("user input", u))
		err = errors.ErrInvalidInput.Wrap(err, "invalid input")
		return err
	}

	return nil
}
