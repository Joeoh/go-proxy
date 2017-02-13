package main

import (
	"net"

	log "github.com/zdannar/flogger"
	"bufio"
	"strings"
	"strconv"
	"bytes"
	"fmt"
)

const _DEFAULTLOG = "/var/log/go-proxy.log"

var connections (chan string)

func configureLogging() {
	log.SetLevel(log.INFO)
	//log.SetLevel(log.DEBUG)

	if err := log.OpenFile(_DEFAULTLOG, log.FLOG_APPEND, 0644); err != nil {
		log.Fatalf("Unable to open log file : %s", err)
	}
}

// Send required response to HTTPS Tunnelling request as per spec https://tools.ietf.org/html/draft-luotonen-ssl-tunneling-03
func sendSSLTunnellingResponse(clientWriteBuffer *bufio.Writer) (err error) {
	_, err = clientWriteBuffer.Write([]byte("HTTP/1.0 200 Connection established\r\nProxy-agent: Joe-Go-Proxy/0.1\r\n\r\n"))
	if err != nil {
		log.Debugf("Error writing 200 OK", err)
		return
	}
	err = clientWriteBuffer.Flush()
	if err != nil {
		log.Debugf("Error flushing buffer", err)
		return
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
			log.Debugf("There was a problem decoding host : %v", hostHeader)
			return "", -1, err
		}
	} else {
		host = hostnamePort
	}

	return host, port, nil
}

func getResourceFromHeader(header string, host string, port int) (string) {
	portString := ":"+strconv.Itoa(port)
	r := strings.NewReplacer("https://"+host, "", "http://"+host, "",portString, "")
	resource := r.Replace(header)
	return resource
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

//Copy the contents of a buffer from source to dst
func copy(srcReadBuffer *bufio.Reader, dstWriteBuffer *bufio.Writer, dstConn *net.TCPConn) {
	defer dstConn.Close()
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

//Checks if the buffer contains connect message within first 8 bytes
func checkIsHttps(clientReadBuffer *bufio.Reader) (isHttps bool, err error) {
	//Block until there is bytes to peek
	clientReadBuffer.ReadByte()
	clientReadBuffer.UnreadByte()
	lookahead, err := clientReadBuffer.Peek(8)
	if err != nil {
		return
	}

	isHttps = strings.HasPrefix(strings.ToUpper(string(lookahead)), "CONNECT")
	return
}

func proxyData(clientConn *net.TCPConn) {
	log.Debugf("Beginning to proxy")

	clientReadBuffer := bufio.NewReader(clientConn)
	clientWriteBuffer := bufio.NewWriter(clientConn)
	var clientHeaderBuffer bytes.Buffer

	// will listen for message to process ending in newline (\n)
	isHttps, err := checkIsHttps(clientReadBuffer)
	if err != nil {
		log.Debugf("Error peaking client connection buffer", err)
		clientConn.Close()
	}
	port := 80
	host := ""
	resourceLine := ""
	if isHttps {
		port = 443
	}
	seenHostLine := false
	seenResourceLine := false
	//Scan headers from client
	for {
		message, err := clientReadBuffer.ReadString('\n')

		if err != nil {
			log.Debugf("Error reading from client connection buffer", err)
			clientConn.Close()
			break
		}

		messageString := string(message)

		// reached end of headers
		if messageString == "\r\n" {
			log.Debugf("Received end of header client %v \n", string(message))
			break
		} else {
			//Write headers to new buffer to forward for http
			clientHeaderBuffer.WriteString(messageString)
		}
		if strings.HasPrefix(messageString, "Host:") {
			//Extract host and port
			host, port, err = getHostAndPortFromHostHeader(messageString)

			if err != nil {
				clientConn.Close()
				break
			}

			log.Debugf("Extracting host from:  %v =@@= %v", string(message), host)
			seenHostLine = true
		} else if strings.HasPrefix(messageString, "GET ") {
			resourceLine = messageString
			seenResourceLine = true
		}
	}
	if !seenHostLine || (!seenResourceLine && !isHttps) {
		clientConn.Close()
		return
	}


	resourceHeader := getResourceFromHeader(resourceLine, host, port)

	remoteConn, err := connectToHost(host, port)
	if err != nil {
		log.Debugf("Failed connecting to: %v on behalf of: %v \n", net.JoinHostPort(host, strconv.Itoa(port)), clientConn.RemoteAddr().String())
		clientConn.Close()
		return
	}

	remoteWriteBuffer := bufio.NewWriter(remoteConn)
	remoteReadBuffer := bufio.NewReader(remoteConn)

	connections <- fmt.Sprintf("Connected to: %v on behalf of: %v \n", remoteConn.RemoteAddr().String(), clientConn.RemoteAddr().String());
	log.Debugf("Connected to: %v on behalf of: %v \n", remoteConn.RemoteAddr().String(), clientConn.RemoteAddr().String())

	if isHttps {
		err = sendSSLTunnellingResponse(clientWriteBuffer)
		if err != nil {
			clientConn.Close()
			remoteConn.Close()
			return
		}
	} else {
		err = sendClientHeadersToHost(clientHeaderBuffer, remoteWriteBuffer, resourceHeader)
		if err != nil {
			clientConn.Close()
			remoteConn.Close()
			return
		}
	}
	//Copy data from Server into client and client to server concurrently

	//Server into client
	go copy(remoteReadBuffer, clientWriteBuffer, clientConn)
	//Client into server
	go copy(clientReadBuffer, remoteWriteBuffer, remoteConn)
}


func sendClientHeadersToHost(headers bytes.Buffer, hostBuffer *bufio.Writer, resourceHeader string) (err error) {

	for {
		line, headerError := headers.ReadString('\n')
		if headerError != nil {
			break
		}
		//Swap out GET header with non abs version
		if strings.HasPrefix(line, "GET ") {
			_, err = hostBuffer.WriteString(resourceHeader)
		} else {
			_, err = hostBuffer.WriteString(line)
		}
		if err != nil {
			break
		}
	}

	_, err = hostBuffer.Write([]byte("Connection: close\r\n\r\n"))
	if err != nil {
		return
	}
	err = hostBuffer.Flush()
	return
}



func connectionPrinter(){
	for {
		connection := <-connections
		log.Infof("Connection info: %v", connection)
	}
}


func main() {
	configureLogging()

	connections = make(chan string)
	go connectionPrinter()

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
		log.Debugf("New Conn\n")
		go proxyData(conn)
	}
}
