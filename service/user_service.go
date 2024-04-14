package service

import (
	"context"
	"os/exec"
	"regexp"
	"strings"

	"github.com/gin-gonic/gin"
	validation "github.com/go-ozzo/ozzo-validation"
	"github.com/go-ozzo/ozzo-validation/is"
	"github.com/joho/godotenv"
	"github.com/joomcode/errorx"
	"gitlab.com/Nebil/errors"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
)

type UserRepository interface {
	Register(*gin.Context, *User) (*User, error)
	Exists(*gin.Context, *User) (bool, error)
}

type UserService interface {
	RegisterUser(ctx *gin.Context, user User) (*User, error)
}

type userService struct {
	repo   UserRepository
	logger zap.Logger
}

type (
	User struct {
		Username string `json:"username,omitempty"`
		Email    string `json:"email,omitempty"`
		Password string `json:"password,omitempty"`
	}
)

func NewUserService(repo UserRepository, logger zap.Logger) UserService {
	return &userService{repo: repo, logger: logger}
}

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

func GenerateRequestID(ctx *gin.Context) (string, error) {
	uuid, err := exec.Command("uuidgen").Output()
	if err != nil {
		return "", errors.ErrUnableToCreate.Wrap(err, "unable to create")
	}

	requestID := strings.Split(string(uuid), "\n")[0]
	return requestID, nil
}

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	if err != nil {
		return "", errorx.Decorate(err, "error occured on hashing password")
	}
	return string(bytes), nil
}

// RegisterUser implements UserService.
func (u *userService) RegisterUser(ctx *gin.Context, user User) (*User, error) {
	err := user.Validate()
	if err != nil {
		err = errors.ErrInvalidInput.Wrap(err, "invalid username email or password")
		return &User{}, err
	}

	exist, _ := u.repo.Exists(ctx, &user)
	if exist {
		err = errors.ErrUserAlreadyExists.Wrap(errors.ErrUserAlreadyExists.New("user exists"), "user already exists")
		return &User{}, err
	}

	password, err := HashPassword(user.Password)
	if err != nil {
		err = errors.ErrInternalServer.Wrap(err, "internal server error")
		return &User{}, err
	}
	user.Password = password

	us, err := u.repo.Register(ctx, &user)
	if err != nil {
		if err == context.DeadlineExceeded {
			return &User{}, err
		}
		err = errors.ErrUnableToCreate.Wrap(err, "unable to create")
		return &User{}, err
	}
	return us, nil
}
