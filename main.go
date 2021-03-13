package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"github.com/golang/glog"
	flag "github.com/spf13/pflag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
)


var parameters WhSvrParameters

func main() {
	flag.IntVar(&parameters.port,"port", int(8443),"webhook server port")
	flag.StringVar(&parameters.certFile, "tlsCertFile", "/etc/webhook/certs/cert.pem", "File containing the x509 Certificate for HTTPS.")
	flag.StringVar(&parameters.keyFile, "tlsKeyFile", "/etc/webhook/certs/key.pem", "File containing the x509 private key to --tlsCertFile.")
	flag.Parse()

	pair,err:= tls.LoadX509KeyPair(parameters.certFile,parameters.keyFile)

	if err !=nil{
		log.Fatal("Failed to load key pair %v",err)
	}


	whsvr := &WebhookServer{
		server: &http.Server{
			Addr:             fmt.Sprintf(":%v",parameters.port),// strconv.Itoa(parameters.port),

			TLSConfig:        &tls.Config{

				Certificates:                []tls.Certificate{
					pair,
				},

			} ,

		},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/mutate",whsvr.serve)
	mux.HandleFunc("/validate",whsvr.serve)
	whsvr.server.Handler = mux

	go func() {
		if err := whsvr.server.ListenAndServeTLS("",""); err !=nil{
			fmt.Println(whsvr.server.Addr)

			log.Fatal("failed to listen and serve webhook server...",err)
		}
	}()

	log.Println("server started")

	signalChan := make(chan  os.Signal,1)

	signal.Notify(signalChan,syscall.SIGINT,syscall.SIGTERM)
	<- signalChan

	glog.Infof("got os shutdown signal shut down gracefully")

	whsvr.server.Shutdown(context.Background())
}

















