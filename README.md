[<img src="./images/logo.png" width="300" height="150"/>](./images/logo.png)

[![Maven Build & Sonar Analysis](https://github.com/eclipse-ecsp/uidam-authorization-server/actions/workflows/maven-build.yml/badge.svg)](https://github.com/eclipse-ecsp/uidam-authorization-server/actions/workflows/maven-build.yml)
[![License Compliance](https://github.com/eclipse-ecsp/uidam-authorization-server/actions/workflows/licence-compliance.yaml/badge.svg)](https://github.com/eclipse-ecsp/uidam-authorization-server/actions/workflows/licence-compliance.yaml)
[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=eclipse-ecsp_uidam-authorization-server&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=eclipse-ecsp_uidam-authorization-server)
[![Latest Release](https://img.shields.io/github/v/release/eclipse-ecsp/uidam-authorization-server?sort=semver)](https://github.com/eclipse-ecsp/uidam-authorization-server/releases)

# UIDAM-Authorization-Server

This component provides capability of Identity and Access Management Services to manage authentication and authorization across the system. It is based on spring authorization server and ensures that access privileges are granted according to user's roles and client's scopes and all individuals and
services are properly authenticated and authorized before accessing any exposed APIs in the system. It ensures that proper Role Based Access policies are in place and each user/machine are able to access only the authorized features for which they have respective privileges in the system using OAuth 2.1 and OpenID Connect 1.0 specifications.

It handles IDAM(Identity and Access Management) use cases like token generation by different grant types like
client credentials, authorization code, refresh token, adding custom claims to tokens, token revocation, token introspection, 
password recovery, email verification, login services, sign-up services, etc.


# Table of Contents
* [Getting Started](#getting-started)
* [Usage](#usage)
* [How to contribute](#how-to-contribute)
* [Built with Dependencies](#built-with-dependencies)
* [Code of Conduct](#code-of-conduct)
* [Authors](#authors)
* [Security Contact Information](#security-contact-information)
* [Support](#support)
* [Troubleshooting](#troubleshooting)
* [License](#license)
* [Announcements](#announcements)
* [Acknowledgments](#acknowledgments)

## Getting Started

To build the project in the local working directory after the project has been cloned/forked, run:

```mvn clean install```

from the command line interface.

### Prerequisites

1. PostgreSQL Installation and a Database manager tool like DBeaver to handle db transactions when required over Local
   environment.
2. DB Setup by following steps mentioned in [Local DB Setup](#local-db-setup)
3. There would be interaction required with UIDAM User Management for user, client and account authentication. Please make sure to run respective components on different ports and
   update the property user-management-base-url, postgres.username and postgres.password in [application.properties](src/main/resources/application.properties) accordingly.
4. Install Postman locally for running curl commands
5. Maven version 3.6 or higher
6. Java version 17

### Installation

[How to set up maven](https://maven.apache.org/install.html)

[Install Java](https://stackoverflow.com/questions/52511778/how-to-install-openjdk-11-on-windows)

[Multitenancy Configuration](https://github.com/eclipse-ecsp/uidam-user-management/blob/main/docs/MULTITENANCY_DEVELOPER_GUIDE.md)


#### Local DB Setup

1. Install PostgreSQL and a Database manager tool like [DBeaver](https://dbeaver.com/2022/02/17/how-to-download-and-install-dbeaver/)
2. If it is a fresh installation then need to create uidam_management database and uidam schema in uidam_management database before running the application.
3. Steps to create db and schema(fresh installation)
   1. Drop role if exist - DROP ROLE IF EXISTS uidam_management;
   2. Create a user for db - create user uidam_management with password  'uidam_management';
   3. alter user uidam_management CREATEDB;
   4. Create database - CREATE DATABASE uidam_management owner  uidam_management;
   5. \c uidam_management;
   6. Check all schema exists in db - \dn
   7. Create schema - CREATE SCHEMA IF NOT EXISTS uidam;
4. Steps to create schema in case db already exists but schema is not exist:
   1. Check all schema exists in db - \dn
   2. Create schema - CREATE SCHEMA IF NOT EXISTS uidam;
5. When the application is run, Liquibase will take care of creating tables in the schema and populating with default data.

#### Build

Run mvn clean install

#### How to Test on Local

1. Run the Application by running the main class [AuthorizationServerApplication.java](./src/main/java/com/harman/oauth2/server/core/AuthorizationServerApplication.java)
2. As Liquibase in included in the project, so it would take care of tracking, managing and applying database schema changes along with default data creation.
3. Run local curl commands in postman as described in [Usage Section](#usage) using the default credentials as shared in the [Default Data Section](#default-data)
4. To be able to access the Login Page, the following steps can be performed:
   1. Enter the following url in the browser(Client ID, Scopes and Redirect URI can be updated as per the client details in the database)
      ```https://localhost:9443/oauth2/authorize?response_type=code&client_id=<CLIENT_ID>&redirect_uri=<REDIRECT_URI>&scope=<SCOPES>```
   2. Once Login Page is open, enter correct user credentials and click on Login. You may use the default user credentials shared in the [Default Data Section](#default-data)
   3. Once logged in, the user will be redirected to the redirect_uri with the authorization code in the query parameter
   4. Use the authorization code to generate the token using the token endpoint using curl commands in [Curl Commands Section](#curl-commands)

##### Glossary
* CLIENT_ID - Registered Client ID
* SCOPES - List of scopes separated by space. Example: "SelfManage ManageUsers"
* REDIRECT_URI - Redirect URI for the registered client

### Coding style check configuration

[checkStyle.xml](./checkStyle.xml) is the coding standard to follow while writing new/updating existing code.

Checkstyle plugin [maven-checkstyle-plugin:3.2.1](https://maven.apache.org/plugins/maven-checkstyle-plugin/) is integrated in [pom.xml](./pom.xml) which runs in the `validate` phase and `check` goal of the maven lifecycle and fails the build if there are any checkstyle errors in the project.

To run checkstyle plugin explicitly, run the following command:

```mvn checkstyle:check```

### Running the tests

```mvn test```

Or run a specific test

```mvn test -Dtest="TheFirstUnitTest"```

To run a method from within a test

```mvn test -Dtest="TheSecondUnitTest#whenTestCase2_thenPrintTest2_1"```

## Usage
UIDAM Authorization Server can be used to generate tokens using different grant types like client credentials, authorization code, refresh token, etc. It can be used to revoke tokens, introspect tokens, etc. 
It can also be used to add custom claims to tokens as well as support Spring thymeleaf templates for login page, sign up page, forgot password services, etc. with configurable captcha services.
It provides the following services:
1. User/Client Authentication and Token generation using following grant types:
   * Client Credentials
   * Authorization Code (PKCE and non-PKCE)
   * Refresh Token
2. Token Introspection
3. Token Revocation
4. Token Claim Customization
5. Email Verification Services
6. Password Recovery Services
7. Login Services along with configured Captcha Services
8. Federated User Authentication
9. Scope Validation as part of User/Client Authorization

### Default Data
* Default user credentials: admin/ChangeMe
* Default client credentials: test-portal/ChangeMe
* Rest of the predefined data like roles, scopes, default users, default clients, etc. are created by Liquibase scripts as part of the [UIDAM User Management](https://github.com/eclispe-ecsp/uidam-user-management) component

### Curl Commands
1. Access Token Generation using grant type: client credentials

```curl -k --location 'https://localhost:9443/oauth2/token' --header 'content-type: application/x-www-form-urlencoded' --data-urlencode 'grant_type=client_credentials' --data-urlencode 'scope<CLIENT_SCOPES>' --data-urlencode 'client_id=<CLIENT_ID>' --data-urlencode 'client_secret=<CLIENT_SECRET>'```

2. Authorization Code Authorize Endpoint to generate authorization code (try below URL in browser)

https://localhost:9443/oauth2/authorize?response_type=code&client_id=<CLIENT_ID>&redirect_uri=<CLIENT_REDIRECT_URI>&scope=<CLIENT_SCOPES>

3. Authorization Code Token Endpoint to generate token using authorization code(grant type: authorization code)

```curl -k --location 'https://localhost:9443/oauth2/token' --header 'Content-Type: application/x-www-form-urlencoded' --data-urlencode 'grant_type=authorization_code' --data-urlencode 'code=<AUTH_CODE>' --data-urlencode 'client_id=<CLIENT_ID>' --data-urlencode 'redirect_uri=<REDIRECT_URI>' --data-urlencode 'client_secret=<CLIENT_SECRET>'```
4. Authorization Code Authorize Endpoint with PKCE to generate authorization code with PKCE

https://localhost:9443/oauth2/authorize?response_type=code&client_id=<CLIENT_ID>&redirect_uri=<CLIENT_REDIRECT_URI>&scope=<CLIENT_SCOPES>&code_challenge=<CODE_CHALLENGE>&code_challenge_method=S256

5. Authorization Code Token Endpoint with PKCE to generate token using authorization code with PKCE(grant type: authorization code)

```curl -k --location 'https://localhost:9443/oauth2/token' --header 'Content-Type: application/x-www-form-urlencoded' --data-urlencode 'grant_type=authorization_code' --data-urlencode 'code=<AUTH_CODE>' --data-urlencode 'client_id=<CLIENT_ID>' --data-urlencode 'redirect_uri=<REDIRECT_URI>' --data-urlencode 'code_verifier=<CODE_VERIFIER>' --data-urlencode 'client_secret=<CLIENT_SECRET>'```

6. Token Revoke to revoke token

```curl -k --location 'https://localhost:9443/oauth2/revoke' --header 'Authorization: Basic <BASE64_ENCODED_CLIENT_ID_CLIENT_SECRET>' --header 'content-type: application/x-www-form-urlencoded' --data-urlencode 'token=<ACCESS_TOKEN>' --data-urlencode 'client_id=<CLIENT_ID>' --data-urlencode 'client_secret=<CLIENT_SECRET>'```
7. Token Introspect to introspect token

```curl -k --location 'https://localhost:9443/oauth2/introspect' --header 'Authorization: Basic <BASE64_ENCODED_CLIENT_ID_CLIENT_SECRET>' --header 'Content-Type: application/x-www-form-urlencoded' --header 'Accept: application/json' --data-urlencode 'token=<ACCESS_TOKEN>'```
8. Token generation using "refresh token" grant type(Refresh token is generated when token is generated using authorization code or with PKCE)

```curl -k --silent --location --request POST 'https://localhost:9443/oauth2/token' --header 'Content-Type: application/x-www-form-urlencoded' --header 'Authorization: Basic <BASE64_ENCODED_CLIENT_ID_CLIENT_SECRET>' --data-urlencode 'grant_type=refresh_token' --data-urlencode 'scopes=<CLIENT_SCOPES>' --data-urlencode 'refresh_token=<REFRESH_TOKEN>'```

Note: Replace the placeholders with actual values. The above shared curls are for localhost, please replace "localhost" with the actual server URL.

### JKS Generation Steps
* Make sure you have Java installed in your system
* Open CMD
* Go to java JAVA_INSTALLATION_FOLDER\bin
* Use the following command:
   `keytool -genkey -alias <alias_name> -keyalg RSA -keypass <key-password> -storepass <store-password> -keystore <full path where jks to be stored along with jks file name>.jks -validity <validity period in days> -keysize  4096`
* Add required details
* Jks file would be created
* Encoded jks has to be used in uidam chart, so use the following command to generate the same
   To encode jks -> `cat <jks-file-name>.jks | base64 -w 0`
* Update encrypted value in values.yaml (`jks_file`) of uidam-authorization-server charts.
  ex: Source of values.yaml - jks_file
* Along with jks, update the chart with jks alias (`values.yaml -> keyAlias`) and jks password (`values.yaml -> keystorePassword`).

#### Generate Public Key
* Create the public.cert using
     `keytool -export -alias <alias_name> -keystore <jks file name>.jks -rfc -file <public-key-cert-file-name>.cert`
* Use this command to get certificate details:
     `keytool -list -rfc -keystore <jks file name>.jks -alias <alias_name> -storepass <store-password>`
* Create pem file from cert using the following command
     `openssl x509 -in< public-key-cert-file-name>.cert -out <public-key-pem-file-name>.pem`
* To get public key from pem, use below:
     `openssl x509 -pubkey -noout -in public-key-pem-file-name>.pem`
* This public key needs to be updated in UIDAM Authorization server charts values.yaml (`uidam_pub`)
* This pem file would need to be updated in api gateway charts and hivemq charts for token validation.

  
#### Glossary
* CLIENT_SCOPES - Space separated scopes for the registered client like openid SelfManage
* CLIENT_ID - Registered Client ID
* CLIENT_SECRET - Registered Client Secret
* CLIENT_REDIRECT_URI - Redirect URI for the registered client
* CODE_CHALLENGE - PKCE Code Challenge
* CODE_VERIFIER - Code Verifier
* AUTH_CODE - Authorization Code
* ACCESS_TOKEN - Access Token
* REFRESH_TOKEN - Refresh Token
* BASE64_ENCODED_CLIENT_ID_CLIENT_SECRET - Base64 encoded client_id:client_secret, Example testClientid:testClientpwd will be encoded as dGVzdENsaWVudGlkOnRlc3RDbGllbnRwd2Q=


## Built With Dependencies

* [SQL DAO](https://github.com/eclipse-ecsp/sql-dao) - SQL DAO to manage database transactions
* [Spring Boot](https://spring.io/projects/spring-boot/) - The web framework used
* [Maven](https://maven.apache.org/) - Build tool used for dependency management
* [PostgreSQL](https://www.postgresql.org/) - Relational database
* [Spring Authorization Server](https://spring.io/projects/spring-authorization-server) - OAuth2.0 Authorization Server
* [Spring Framework](https://spring.io/projects/spring-framework) - Web framework used for building the application.
* [Junit](https://junit.org/junit5/) - Unit testing framework.
* [Mockito](https://site.mockito.org/) - Mocking framework for testing.
* [Java 17](https://www.oracle.com/java/technologies/javase/jdk17-archive-downloads.html) - Java version
* [Liquibase](https://www.liquibase.org/) - Manages database schema changes.
* [Lombok](https://projectlombok.org/) - Auto-generates Java boilerplate code (e.g., getters, setters, builders).
* [Thymeleaf](https://www.thymeleaf.org/) - Template Engine
* [SnakeYAML](https://bitbucket.org/snakeyaml/snakeyaml) - YAML parser
* [Logback](http://logback.qos.ch/) - Logging facade providing abstraction for various logging frameworks
* [SLF4J](http://www.slf4j.org/) - Logging API

## How to contribute

Please read [CONTRIBUTING.md](./CONTRIBUTING.md) for details on our contribution
guidelines, and the process for submitting pull requests to us.

## Code of Conduct

Please read [CODE_OF_CONDUCT.md](./CODE_OF_CONDUCT.md) for details on our code of conduct,
and the process for submitting pull requests to us.

## Contributors

Check here the list of [contributors](https://github.com/eclipse-ecsp/uidam-authorization-server/graphs/contributors) who participated in this project.

## Security Contact Information

Please read [SECURITY.md](./SECURITY.md) to raise any security related issues.

## Support

Please write to us at [csp@harman.com](mailto:csp@harman.com)

## Troubleshooting

Please read [CONTRIBUTING.md](./CONTRIBUTING.md) for details on how to raise an issue and submit a pull request to us.

## License

This project is licensed under the Apache-2.0 License - see the [LICENSE](./LICENSE) file for details.


## Announcements

All updates to this component are present in our [releases page](https://github.com/eclipse-ecsp/uidam-authorization-server/releases).
For the versions available, see the [tags on this repository](https://github.com/eclipse-ecsp/uidam-authorization-server/tags).

