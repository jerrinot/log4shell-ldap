FROM maven:3-amazoncorretto-8 as javabuilder
RUN mkdir /build/
WORKDIR /build
RUN mkdir -p /build/src/main/java/info/jerrinot/log4shell/evilfactory
COPY java/pom.xml /build/
COPY java/EvilFactory.java /build/src/main/java/info/jerrinot/log4shell/evilfactory/
RUN mvn package

FROM golang:1.16 as gobuilder
WORKDIR /
COPY go.* ./
RUN go mod download
COPY main.go .
COPY index.html .
COPY --from=javabuilder /build/target/evilfactory-1.0-SNAPSHOT.jar .
RUN CGO_ENABLED=0 GOOS=linux go build -a -tags app -o app -ldflags '-w' .

FROM scratch
COPY --from=gobuilder /app /app
ENTRYPOINT ["/app"]
