module github.com/id-contact/auth-digid

go 1.18

require (
	github.com/crewjam/saml v0.4.6
	github.com/dgrijalva/jwt-go/v4 v4.0.0-preview1
	github.com/getsentry/sentry-go v0.13.0
	github.com/go-chi/chi/v5 v5.0.7
	github.com/go-co-op/gocron v1.13.0
	github.com/jackc/pgx/v4 v4.15.0
	github.com/lestrrat-go/jwx v1.2.20
	github.com/sirupsen/logrus v1.8.1
	github.com/spf13/viper v1.10.1
	github.com/stretchr/testify v1.7.1
)

replace github.com/crewjam/saml => github.com/id-contact/saml v0.4.6-0.20210715085542-1ef6a54949db
