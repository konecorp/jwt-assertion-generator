# JWT Assertion Token Generator

Generator utilities for JWT Assertion tokens used as authentication for the [Salesforce Oauth2 JWT Bearer flow](https://help.salesforce.com/articleView?id=remoteaccess_oauth_jwt_flow.htm&type=0).

[KONE API Services](https://developer.kone.com/) use this OAuth2 flow to authenticate the API client and provide an access token for API requests.

The tools provided here are meant to help with testing the [KONE API Services](https://developer.kone.com/).

# Using

There are two token generator implementations:

* Bash shell implementation
* Java implementation

The Bash implementation is simpler. Prefer that if you can run Bash scripts. The Java implementation works in environments without the Bash shell.

Both implementations require that you first generate a private signing key. The key is used for signing the generated JWT token.

## Create a signing key

The `openssl` commands below will create a private key for token signing.

The created `private.key` file is used with the Bash JWT generator script. The Java version requires the key in a different format (`private_key.pkcs8`), also generated with the commands below.

The commands also create a public certificate (`server.crt`) signed with the private key. The certificate is sent to KONE during the API subscription process and later used to validate your JWT Bearer Assertion tokens.

```
openssl genrsa -des3 -passout pass:SomePassword -out server.pass.key 2048
openssl rsa -passin pass:SomePassword -in server.pass.key -out server.key
openssl req -new -key server.key -out server.csr
openssl x509 -req -sha256 -days 365 -in server.csr -signkey server.key -out server.crt
openssl pkcs8 -topk8 -inform PEM -outform DER -in server.key -out private_key.pkcs8 -nocrypt
```


## Run with Bash

Clone this repository to get the `generate-token.sh` script.

Run `generate-token.sh` like this:

```
AUDIENCE=your_audience \
ISSUER=your_issuer \
SUBJECT=your_subject \
KEY=/path/to/your_private.key \
./generate-token.sh
```

## Run with Java

Download the executable jar file from [here](https://github.com/konecorp/jwt-assertion-generator/releases/download/v1.0/jwt_assert-1.0.jar).

Run like this:

```
java -jar jwt_assert-1.0.jar \
--audience your_audience \
--issuer your_issuer \
--subject your_subject \
--key /path/to/your/pkcs8_private_key
```

# Building

The following are instructions to build the Java based executables for this project. If you only want to run the token generators, see the Using section above.

## Build from source

You'll need a recent JDK.

Build on linux or macOS: Run `./mvnw clean package`

Build on Windows: Run `mvnw.cmd clean package`

### GraalVM Native Build

**Use the instructions above unless you're adventurous.**

Native macOS, Linux and Windows builds to run the command directly without Java. Doesn't work on Windows for now.

Requires a GraalVM JDK and to set `JAVA_HOME=/path/to/a/graalvm/jdk`.

Build with: `mvn clean package -P build-native`

Executable will be written to: `target/net.majakorpi.jwt.JwtAssertionGenerator`

(Perhaps later a better idea is to use `jpackage` coming with Java 14...)