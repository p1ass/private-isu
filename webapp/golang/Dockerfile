FROM golang:1.21

RUN mkdir -p /home/webapp
WORKDIR /home/webapp

COPY go.mod /home/webapp
COPY go.sum /home/webapp
RUN go mod download

COPY . /home/webapp
RUN go build -ldflags "-X main.gitBranchName=master" -o app
CMD ./app
