# DigiD authentication plugin for Verder Helpen Platform

This repository contains a DigiD authentication plugin for the Verder Helpen Platform.

## Getting started
To build and run this plugin, do:
```bash
go build
./verder-helpen-auth-digid
```

## Running tests
This package contains tests, which can be run in the standard manner for go programs:
```bash
go test
```

Some tests depend on a postgres database, to run these, add the flags `-ldflags "-X github.com/verder-helpen/auth-digid.testdb=<DB URL>"` to the go test invocation, where `<DB URL>` should be the connection url for a postgres database that the tests have full rights to modify (including schema changes).

For a quick setup using Docker, the following commands can be used:
```bash
docker run -e POSTGRES_PASSWORD=password -p 127.0.0.1:5432:5432 --rm postgres
go test -ldflags "-X github.com/verder-helpen/auth-digid.testdb=postgres://postgres:password@127.0.0.1:5432/postgres"
```


## Further reading
Complete documentation for this plugin can be found in [the general Verder Helpen documentation](https://docs.verderhelpen.nl)
