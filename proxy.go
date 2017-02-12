package main

import (
	"net"

	log "github.com/zdannar/flogger"
)


const _DEFAULTLOG = "/var/log/go-proxy.log"

func configureLogging() {
	log.SetLevel(log.INFO)
	log.SetLevel(log.DEBUG)

	if err := log.OpenFile(_DEFAULTLOG, log.FLOG_APPEND, 0644); err != nil {
		log.Fatalf("Unable to open log file : %s", err)
	}
}

func handleConnection(clientConn *net.TCPConn){
	defer clientConn.Close()
	log.Debugf("New connection from: %v\n", clientConn.LocalAddr().String() )
}

func main() {
	configureLogging()

	lnaddr, err := net.ResolveTCPAddr("tcp", ":8080")
	if err != nil {
		panic(err)
	}

	listener, err := net.ListenTCP("tcp", lnaddr)
	if err != nil {
		panic(err)
	}
	defer listener.Close()

	log.Infof("Listening for connections on %v\n", listener.Addr())

	for {
		conn, err := listener.AcceptTCP()
		if err != nil {
			log.Infof("Error accepting connection: %v\n", err)
			continue
		}
		log.Infof("New Conn\n")
		go handleConnection(conn)
	}
}
