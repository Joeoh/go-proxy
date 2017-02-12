package main

import (
	"net"

	log "github.com/zdannar/flogger"
	"bufio"
	"strings"
	"strconv"
	"bytes"
)

const _DEFAULTLOG = "/var/log/go-proxy.log"

func configureLogging() {
	log.SetLevel(log.INFO)
	log.SetLevel(log.DEBUG)

	if err := log.OpenFile(_DEFAULTLOG, log.FLOG_APPEND, 0644); err != nil {
		log.Fatalf("Unable to open log file : %s", err)
	}
}

// Send required response to HTTPS Tunnelling request as per spec https://tools.ietf.org/html/draft-luotonen-ssl-tunneling-03
func sendSSLTunnellingResponse(clientWriteBuffer *bufio.Writer) (err error) {
	_, err = clientWriteBuffer.Write([]byte("HTTP/1.0 200 Connection established\r\nProxy-agent: Joe-Go-Proxy/0.1\n\n"))
	if err != nil {
		log.Errorf("Error writing 200 OK", err)
		return err
	}
	err = clientWriteBuffer.Flush()
	if err != nil {
		log.Errorf("Error flushing buffer", err)
		return err
	}

	return nil
}

func getHostAndPortFromHostHeader(hostHeader string) (string, int, error) {
	port := 80
	host := ""
	r := strings.NewReplacer("Host: ", "", "\r\n", "")
	hostnamePort := r.Replace(hostHeader)

	if strings.Contains(hostnamePort, ":") {
		s := strings.Split(hostnamePort, ":")
		host = s[0]
		_, err := strconv.Atoi(s[1])
		port, _ = strconv.Atoi(s[1])
		if err != nil {
			log.Errorf("There was a problem decoding host : %v", hostHeader)
			return "", -1, err
		}
	} else {
		host = hostnamePort
	}

	return host, port, nil
}

func connectToHost(host string, port int) (*net.TCPConn, error) {

	remoteAddrs, err := net.LookupIP(host)

	if err == nil {
		ipAddr := remoteAddrs[0]
		remoteAddrAndPort := &net.TCPAddr{IP: ipAddr, Port: port}

		remoteConn, err := net.DialTCP("tcp", nil, remoteAddrAndPort)
		if err != nil {
			return nil, err
		}
		return remoteConn, nil
	} else {
		return nil, err
	}
}

//Copy the contents of one connection from source to dst
func copy(srcReadBuffer *bufio.Reader, dstWriteBuffer *bufio.Writer, dstHost string) {
	for {
		readByte, err := srcReadBuffer.ReadByte()
		if err != nil {
			return
		}
		err = dstWriteBuffer.WriteByte(readByte)
		if err != nil {
			return
		}
		dstWriteBuffer.Flush()
	}
}

func checkIsHttps(clientReadBuffer *bufio.Reader) (isHttps bool, err error) {

	lookahead, err := clientReadBuffer.Peek(8)

	if err != nil {
		return
	}

	isHttps = strings.HasPrefix(strings.ToUpper(string(lookahead)), "CONNECT")
	return
}

func extern(clientConn *net.TCPConn) {
	log.Infof("Beginning to proxy")

	clientReadBuffer := bufio.NewReader(clientConn)
	clientWriteBuffer := bufio.NewWriter(clientConn)
	var clientHeaderBuffer bytes.Buffer

	// will listen for message to process ending in newline (\n)
	isHttps, err := checkIsHttps(clientReadBuffer)
	if err != nil {
		log.Errorf("Error peaking client connection buffer", err)
		clientConn.Close()
	}
	port := 80
	host := ""
	hostNameLine := ""

	if (isHttps) {
		isHttps = true
		port = 443
	}
	seenHostLine := false
	//Scan headers from client
	for {

		message, err := clientReadBuffer.ReadString('\n')

		if err != nil {
			break
			log.Errorf("Error reading from client connection buffer", err)
		}

		messageString := string(message)
		//Write headers to new buffer to forward for http
		clientHeaderBuffer.WriteString(messageString)

		// reached end of headers
		if messageString == "\r\n" {
			log.Infof("Received end of header client %v \n", string(message))
			break
		} else if strings.HasPrefix(messageString, "Host:") {
			//Extract host and port
			host, port, err = getHostAndPortFromHostHeader(messageString)

			log.Infof("Extracting host from:  %v =@@= %v", string(message), host)
			hostNameLine = messageString
			seenHostLine = true
		}
	}

	if !seenHostLine {
		clientConn.Close()
		return
	}
	if host == "" {
		log.Infof("Got an empty host string\n")
		log.Infof("Host line was: %v \n", hostNameLine)

	}

	remoteConn, _ := connectToHost(host, port)
	if remoteConn == nil {
		log.Errorf("Failed connecting to: %v on behalf of: %v \n", net.JoinHostPort(host, strconv.Itoa(port)), clientConn.RemoteAddr().String())
		return
	}

	remoteWriteBuffer := bufio.NewWriter(remoteConn)

	log.Infof("Connected to: %v on behalf of: %v \n", remoteConn.RemoteAddr().String(), clientConn.RemoteAddr().String())

	if isHttps {
		log.Infof("Connection is HTTPS")
		sendSSLTunnellingResponse(clientWriteBuffer)
	} else {
		sendClientHeadersToHost(clientHeaderBuffer, remoteWriteBuffer)
	}

	go copy(remoteConn, clientConn, "Client")
	go copy(clientConn, remoteConn, "Server")
}

func proxyData(clientConn *net.TCPConn) {
	extern(clientConn)
}

func sendClientHeadersToHost(headers bytes.Buffer, hostBuffer *bufio.Writer) {
	hostBuffer.Write(headers.Bytes())
	hostBuffer.Write([]byte("Connection: close\r\n\r\n"))
	hostBuffer.Flush()
}

func handleTunnel(clientConn *net.TCPConn) {
	log.Debugf("Handling tunnel")

	clientReader := bufio.NewReader(clientConn)
	clientWriter := bufio.NewWriter(clientConn)

	port := 80
	host := ""
	seenHostLine := false
	//Read over entire initial message
	for {
		message, err := clientReader.ReadBytes('\n')

		if err != nil {
			log.Infof("Error reading %v", err)
			return
		}

		messageString := string(message)

		// reached end of headers
		if messageString == "\r\n" {
			log.Infof("Received end of header client %v \n", string(message))
			break
		} else if strings.HasPrefix(messageString, "Host:") {
			//Extract host and port
			host, port, err = getHostAndPortFromHostHeader(messageString)
			log.Infof("Host header: %v", messageString)

			if err != nil {
				log.Infof("Error reading %v", err)
				return
			}
			seenHostLine = true
		}
	}

	if !seenHostLine {
		return
	}

	remoteConn, err := connectToHost(host, port)

	if err != nil {
		return
	}

	err = sendSSLTunnellingResponse(clientWriter)
	if err != nil {
		return
	}

	go copy(remoteConn, clientConn, "Client")
	go copy(clientConn, remoteConn, "Server")

}

func handleInitMessage(clientConn *net.TCPConn) {
	clientReader := bufio.NewReader(clientConn)

	lookahead, err := clientReader.Peek(8)

	if err != nil {
		log.Debugf("Error peeking %v\n", err)
		return
	}

	lookaheadString := string(lookahead)

	//Client has sent Connect message to setup tunneling
	if strings.HasPrefix(strings.ToUpper(lookaheadString), "CONNECT") {
		handleTunnel(clientConn)
	} else {
		proxyData(clientConn)
	}
}

func handleConnection(clientConn *net.TCPConn) {
	//defer clientConn.Close()
	log.Debugf("New connection from: %v\n", clientConn.LocalAddr().String())
	handleInitMessage(clientConn)

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
		go proxyData(conn)
	}
}
