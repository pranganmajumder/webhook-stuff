# base image go lang is used as a os for running the commands and building ....
FROM golang:latest AS builder
## creates a directory name app inside the container
WORKDIR /app
## copy all files from the local to the current app directory
COPY . .
# ENV key=value
# RUN go build

##need to google this line
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o webhook .

# EXPOSE 8080


## multi stage building starts here
## the idea is the avoid build wil be buil in another light weight os alpine
FROM alpine

WORKDIR /app
## defining flags from to copy form the previous os
COPY --from=builder /app/webhook .

ENTRYPOINT ["./webhook"]

