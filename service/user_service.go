package service

import (
	"regexp"

	validation "github.com/go-ozzo/ozzo-validation"
	"github.com/go-ozzo/ozzo-validation/is"
	"github.com/joho/godotenv"
)

type (
	User struct {
		Username string `json:"username,omitempty"`
		Email    string `json:"email,omitempty"`
		Password string `json:"password,omitempty"`
	}
)

var usernameRule = []validation.Rule{
	validation.Required.Error("username must be unique and alphanumeric, with at least 5 characters"),
	validation.Length(5, 20),
	validation.Match(regexp.MustCompile(`^[A-Za-z]\w{5,}$`)),
}

var emailRule = []validation.Rule{
	validation.Required.Error("email must be valid and already exists"),
	is.Email,
}

var passwordRule = []validation.Rule{
	validation.Required.Error("password must be at least 8 characters long, with at least one uppercase letter,one lowercase letter, one digit, and one special character."),
	validation.Length(8, 50),
	validation.Match(regexp.MustCompile(`[A-Z]`)),
	validation.Match(regexp.MustCompile(`[a-z]`)),
	validation.Match(regexp.MustCompile(`[0-9]`)),
	validation.Match(regexp.MustCompile(`[-\#\$\.\%\&\*]`)),
}

func (u User) Validate() error {
	return validation.ValidateStruct(&u,
		validation.Field(&u.Username, usernameRule...),
		validation.Field(&u.Email, emailRule...),
		validation.Field(&u.Password, passwordRule...),
	)
}

func LoadEnv() error {
	err := godotenv.Load(".env")
	if err != nil {
		return err
	}
	return nil
}
