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
	validation.Length(5, 20),
	validation.Match(regexp.MustCompile(`^[A-Za-z]\w{4,}$`)),
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

// func NewLogger() (*zap.Logger, error) {
// 	logger, err := zap.NewDevelopment()
// 	if err != nil {
// 		return nil, err
// 	}
// 	defer logger.Sync()

// 	return logger, nil
// }

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
