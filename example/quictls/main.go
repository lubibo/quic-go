package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"github.com/quic-go/quic-go/internal/testdata"
	"io"
	"log"
	"os"
	"time"
)

func main() {

	time.Sleep(5 * time.Minute)
}

func Client() {
	var keyLog io.Writer
	keyLogFile := "/Users/boguang.lu/go_project/git.garena.com/boguang.lu/quic-go/example/quictls/client.log"
	f, err := os.Create(keyLogFile)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	keyLog = f

	pool, err := x509.SystemCertPool()
	if err != nil {
		log.Fatal(err)
	}
	testdata.AddRootCA(pool) // 把测试的证书加进去
	cli := tls.QUICClient(&tls.QUICConfig{
		TLSConfig: &tls.Config{
			RootCAs:            pool,
			InsecureSkipVerify: false,
			ServerName:         "localhost",
			KeyLogWriter:       keyLog,
			MinVersion:         tls.VersionTLS13,
		},
		EnableSessionEvents: true,
	})

	go func() {
		err := cli.Start(context.Background())
		if err != nil {
			panic(err)
		}
		for {
			event := cli.NextEvent()
			evtData, _ := json.Marshal(event)
			fmt.Println(string(evtData))
		}
	}()

	go func() {
		cli.HandleData()
	}()
}

func Server() {
	var err error
	certFile, keyFile := testdata.GetCertificatePaths()
	certs := make([]tls.Certificate, 1)
	certs[0], err = tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		panic(err)
	}
	// 打开 sslkeys.log 文件
	serverKeyLogFile, err := os.OpenFile("/Users/boguang.lu/go_project/git.garena.com/boguang.lu/quic-go/example/quictls/server.log",
		os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		log.Fatalf("unable to open key log file: %v", err)
	}
	server := tls.QUICServer(&tls.QUICConfig{
		TLSConfig: &tls.Config{
			Certificates: certs,
			ServerName:   "localhost",
			KeyLogWriter: serverKeyLogFile,
			MinVersion:   tls.VersionTLS13,
		},
		EnableSessionEvents: false,
	})
	go func() {
		err := server.Start(context.Background())
		if err != nil {
			panic(err)
		}
		for {
			event := server.NextEvent()
			evtData, _ := json.Marshal(event)
			fmt.Println(string(evtData))
		}
	}()
}
