FROM amazoncorretto:8 as javabuilder
RUN mkdir /build/
WORKDIR /build

# first make the maven wrapper to download all dependencies
# build dependencies are modified very rarely so they can be cached by Docker
COPY java/pom.xml .
COPY java/mvnw .
RUN mkdir .mvn
COPY java/.mvn .mvn
RUN ./mvnw verify clean --fail-never

# now run the actual build
COPY java/src/ ./
RUN ./mvnw package



FROM golang:1.16 as gobuilder
WORKDIR /
COPY go.* ./
RUN go mod download
COPY main.go .
COPY --from=javabuilder /build/target/evilfactory-1.0-SNAPSHOT.jar .
RUN CGO_ENABLED=0 GOOS=linux go build -a -tags app -o app -ldflags '-w' .


FROM scratch
COPY --from=gobuilder /app /app
ENTRYPOINT ["/app"]
EXPOSE 3000
EXPOSE 1389
