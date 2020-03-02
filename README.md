# JWT Assertion Token Generator

Mainly for this Salesforce OAuth2 flow: https://help.salesforce.com/articleView?id=remoteaccess_oauth_jwt_flow.htm&type=0

Download a pre-built Java jar file from [here](https://github.com/mmajis/JWTAssertionGenerator/releases/download/v1.0/jwt_assert-1.0.jar). 

Run: 
```
java -jar jwt_assert-1.0.jar \
--audience your_audience \
--issuer your_issuer \
--subject your_subject \
--key /path/to/your/pkcs8_private_key
```

To create a signing key:

```
openssl genrsa -des3 -passout pass:SomePassword -out server.pass.key 2048
openssl rsa -passin pass:SomePassword -in server.pass.key -out server.key
openssl req -new -key server.key -out server.csr
openssl x509 -req -sha256 -days 365 -in server.csr -signkey server.key -out server.crt
openssl pkcs8 -topk8 -inform PEM -outform DER -in server.key -out private_key.pkcs8 -nocrypt
```

## Build from source

You'll need a recent JDK.

Build on linux or macOS: Run `./mvnw clean package`

Build on Windows: Run `mvnw.cmd clean package`

### GraalVM Native Build

Native macOS, Linux and Windows builds to run the command directly without Java. Doesn't work on Windows for now.
Use the instructions above unless you're adventurous.

Requires a GraalVM JDK and to set `JAVA_HOME=/path/to/a/graalvm/jdk`.

Build with: `mvn clean package -P build-native`

Executable will be written to: `target/net.majakorpi.jwt.JwtAssertionGenerator`

(Perhaps later a better idea is to use `jpackage` coming with Java 14...)