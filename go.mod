module github.com/id-contact/auth-digid

go 1.16

require (
	github.com/crewjam/saml v0.4.5
	github.com/dgrijalva/jwt-go/v4 v4.0.0-preview1
	github.com/getsentry/sentry-go v0.11.0
	github.com/go-chi/chi/v5 v5.0.3
	github.com/go-co-op/gocron v1.7.0
	github.com/jackc/pgx/v4 v4.11.0
	github.com/lestrrat-go/jwx v1.2.0
	github.com/sirupsen/logrus v1.4.2
	github.com/spf13/viper v1.7.1
	github.com/stretchr/testify v1.7.0
	golang.org/x/text v0.3.7 // indirect
)

replace github.com/crewjam/saml => github.com/id-contact/saml v0.4.6-0.20210715085542-1ef6a54949db
