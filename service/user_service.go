package service

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	validation "github.com/go-ozzo/ozzo-validation"
	"github.com/go-ozzo/ozzo-validation/is"
	"github.com/golang-jwt/jwt"
	"github.com/joho/godotenv"
	"github.com/joomcode/errorx"
	"gitlab.com/Nebil/errors"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
)

type UserRepository interface {
	Register(context.Context, *User) (*User, error)
	Login(context.Context, *UserLogin) (*UserLogin, error)
	Refresh(ctx context.Context, username, refresh_token string) (*RefToken, error)
	IsExists(context.Context, *User) (bool, error)
	IsLoggedIn(ctx context.Context, username string) (bool, error)
	CheckToken(ctx context.Context, username string) (string, error)
	UpdateToken(ctx context.Context, token, username string) (*RefToken, error)
}

type UserService interface {
	RegisterUser(ctx context.Context, requestID string, user User) (*User, error)
	LoginUser(ctx context.Context, requestID string, user UserLogin) (map[string]string, error)
	RefreshToken(ctx context.Context, requestID string, tokeString string) (map[string]string, error)
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
		// logger   zap.Logger
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
		log.Error("invalid input", zap.Error(err))
		err = errors.ErrInvalidInput.Wrap(err, "invalid input")
		return err
	}
	return nil
}

func (u UserLogin) Validate() error {
	return validation.ValidateStruct(&u,
		validation.Field(&u.Username, usernameRule...),
		validation.Field(&u.Password, passwordRule...))
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
	logger, err := NewLogger()
	if err != nil {
		return "", err
	}
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	if err != nil {
		logger.Error("unable to hash password", zap.Error(err))
		err = errors.ErrInternalServer.Wrap(err, "internal server error")
		return "", err
	}
	return string(bytes), nil
}

func CheckPassword(hash, providedPassword string) error {
	logger, err := NewLogger()
	if err != nil {
		return err
	}
	err = bcrypt.CompareHashAndPassword([]byte(hash), []byte(providedPassword))
	if err != nil {
		logger.Error("invalid password", zap.Error(err))
		err := errors.ErrInvalidInput.Wrap(err, "invalid password")
		return err
	}
	return nil
}

func CreateToken(id, username string) (map[string]string, error) {
	logger, err := NewLogger()
	if err != nil {
		return nil, err
	}
	accessToken, err := GenerateAccessToken(id, username)
	if err != nil {
		logger.Error("unable to create access token", zap.Error(err))
		err = errors.ErrUnableToCreate.Wrap(err, "unable to create access token")
		return nil, err
	}

	refreshToken, err := GenerateRefreshToken(id, username)
	if err != nil {
		logger.Error("unable to create refresh token", zap.Error(err))
		err = errors.ErrUnableToCreate.Wrap(err, "unable to create refresh token")
		return nil, err
	}

	return map[string]string{"access_token": accessToken, "refresh_token": refreshToken}, nil
}

func GenerateAccessToken(id, username string) (string, error) {
	secretKey := []byte(os.Getenv("SECRET_KEY"))

	token := jwt.NewWithClaims(jwt.SigningMethodHS256,
		jwt.MapClaims{
			"id":       id,
			"username": username,
			"exp":      time.Now().Add(time.Minute * 15).Unix(),
		})

	accessToken, err := token.SignedString(secretKey)

	if err != nil {
		return "", err
	}

	return accessToken, nil
}

func GenerateRefreshToken(id, username string) (string, error) {
	secretKey := []byte(os.Getenv("SECRET_KEY"))

	refreshToken := jwt.New(jwt.SigningMethodHS256)
	rtClaims := refreshToken.Claims.(jwt.MapClaims)
	rtClaims["id"] = id
	rtClaims["username"] = username
	rtClaims["sub"] = 1
	rtClaims["exp"] = time.Now().Add((time.Hour * 24) * 30).Unix()
	rt, err := refreshToken.SignedString(secretKey)
	if err != nil {
		return "", err
	}

	return rt, nil
}

func VerifyToken(tokenString string) error {
	logger, err := NewLogger()
	if err != nil {
		return err
	}
	secretKey := []byte(os.Getenv("SECRET_KEY"))
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return secretKey, nil
	})

	if err != nil {
		logger.Error("invalid token", zap.Error(err))
		return errors.ErrBadRequest.Wrap(err, "invalid token")
	}

	if !token.Valid {
		return errors.ErrBadRequest.Wrap(err, "invalid token")
	}

	return nil
}

func ExtractUsernameAndID(ctx context.Context, tokenString string) (map[string]string, error) {
	logger, err := NewLogger()
	if err != nil {
		return nil, err
	}
	secretKey := []byte(os.Getenv("SECRET_KEY"))

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			logger.Error("unable to extract username and id", zap.Error(err))
			return nil, errors.ErrBadRequest.Wrap(errorx.IllegalState.New("unexpected signing method: %v", token.Header["alg"]), "invalid header method")
		}

		return secretKey, nil
	})

	if err != nil {
		logger.Error("unable to extract username and id", zap.Error(err))
		return nil, errors.ErrBadRequest.Wrap(err, "bad request")
	}

	var username string
	var id string
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		if _, ok := claims["sub"]; ok {
			if int(claims["sub"].(float64)) == 1 {
				id = claims["id"].(string)
				username = claims["username"].(string)
			}
		} else {
			return nil, errors.ErrBadRequest.Wrap(errors.ErrBadRequest.New("invalid refresh tokren"), "invalid token")
		}
	}

	return map[string]string{"id": id, "username": username}, nil
}

func Encrypt(key []byte, token string) (string, error) {
	logger, err := NewLogger()
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		logger.Error("unable to encrypt refresh token", zap.Error(err))
		err = errors.ErrInternalServer.Wrap(err, "internal server error")
		return "", err
	}

	ciphertext := make([]byte, aes.BlockSize+len(token))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		logger.Error("unable to read refresh token", zap.Error(err))
		err = errors.ErrInternalServer.Wrap(err, "internal server error")
		return "", err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], []byte(token))

	return base64.URLEncoding.EncodeToString(ciphertext), nil
}

func Decrypt(key []byte, token string) (string, error) {
	logger, err := NewLogger()
	if err != nil {
		return "", err
	}
	ciphertext, err := base64.URLEncoding.DecodeString(token)
	if err != nil {
		logger.Error("unable to decrypt refresh token", zap.Error(err))
		err = errors.ErrInternalServer.Wrap(err, "internal server error")
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		logger.Error("unable to create new cipher block", zap.Error(err))
		err = errors.ErrInternalServer.Wrap(err, "internal server error")
		return "", err
	}

	if len(ciphertext) < aes.BlockSize {
		logger.Error("ciphertext too short", zap.Error(err))
		err = errors.ErrBadRequest.Wrap(err, "bad request")
		return "", err
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)

	return string(ciphertext), nil
}

// RegisterUser implements UserService.
func (u *userService) RegisterUser(ctx context.Context, requestID string, user User) (*User, error) {
	err := user.Validate()
	if err != nil {
		return nil, err
	}

	exist, err := u.repo.IsExists(ctx, &user)
	if exist {
		return nil, err
	}

	password, err := HashPassword(user.Password)
	if err != nil {
		return nil, err
	}
	user.Password = password

	us, err := u.repo.Register(ctx, &user)
	if err != nil {
		return nil, err
	}
	return us, nil
}

// LoginUser implements UserService.
func (u *userService) LoginUser(ctx context.Context, requestID string, user UserLogin) (map[string]string, error) {
	err := user.Validate()
	if err != nil {
		return nil, err
	}

	loggedIn, err := u.repo.IsLoggedIn(ctx, user.Username)
	if loggedIn {
		return nil, err
	}

	usr, err := u.repo.Login(ctx, &user)
	if err != nil {
		return nil, err
	}

	err = CheckPassword(usr.Password, user.Password)
	if err != nil {
		return nil, err
	}

	token, err := CreateToken(usr.ID, usr.Username)
	if err != nil {
		return nil, err
	}

	refreshToken := token["refresh_token"]
	key := os.Getenv("ENCRYPTION_KEY")
	encryptedToken, err := Encrypt([]byte(key), refreshToken)

	if err != nil {
		return nil, err
	}
	_, err = u.repo.Refresh(ctx, usr.Username, encryptedToken)
	if err != nil {
		return nil, err
	}

	return token, nil
}

// RefreshToken implements UserService.
func (u *userService) RefreshToken(ctx context.Context, requestID string, tokeString string) (map[string]string, error) {
	err := VerifyToken(tokeString)
	if err != nil {
		return nil, err
	}

	value, err := ExtractUsernameAndID(ctx, tokeString)
	if err != nil {
		return nil, err
	}

	// userID := value["id"]

	rfToken, err := u.repo.CheckToken(ctx, value["username"])
	if err != nil {
		return nil, err
	}

	key := os.Getenv("ENCRYPTION_KEY")
	decryptRefToken, err := Decrypt([]byte(key), rfToken)

	if err != nil {
		return nil, err
	}

	if decryptRefToken != tokeString {
		return nil, errors.ErrBadRequest.Wrap(errors.ErrBadRequest.New("invalid token provided"), "invalid token")
	}

	token, err := CreateToken(value["id"], value["username"])
	if err != nil {
		return nil, err
	}

	refreshToken := token["refresh_token"]
	encryptedToken, err := Encrypt([]byte(key), refreshToken)
	if err != nil {
		return nil, err
	}

	_, err = u.repo.UpdateToken(ctx, encryptedToken, value["username"])
	if err != nil {
		return nil, err
	}

	return token, nil
}
