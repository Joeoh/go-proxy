package main

import (
	"net"

	log "github.com/zdannar/flogger"
	"bufio"
	"strings"
	"strconv"
	"bytes"
	"fmt"
	"os"
	"sync"
	"io"
)

const _DEFAULTLOG = "/var/log/go-proxy.log"
const _IP_BLACKLIST = "ip_blacklist.txt"
const _DOMAIN_BLACKLIST = "domain_blacklist.txt"
const _403_FILE = "403.html"

var connections = make(chan string)

var blacklist = struct {
	sync.RWMutex
	m map[string]bool
}{m: make(map[string]bool)}

func configureLogging() {
	log.SetLevel(log.INFO)
	log.SetLevel(log.DEBUG)

	if err := log.OpenFile(_DEFAULTLOG, log.FLOG_APPEND, 0644); err != nil {
		log.Fatalf("Unable to open log file : %s", err)
	}
}

/*
func addToBlacklistFile(item string, file os.File) {
	fileWriter := bufio.NewWriter(file)
	fileWriter.WriteString(item+"\n")
	fileWriter.Flush()
}
*/

func addToBlacklist(item string) {
	blacklist.Lock()
	blacklist.m[item] = true
	blacklist.Unlock()
}

func checkBlacklist(item string) bool {
	defer blacklist.RUnlock()
	blacklist.RLock()
	return blacklist.m[item]
}

func isBlocked(domain string) bool {
	if checkBlacklist(domain) {
		return true
	}
	//TODO: Add code here to allow for lookup for *.blank etc
	return false
}

func configureDomainBlacklist() {
	domainBlacklistFile, err := os.Open(_DOMAIN_BLACKLIST)
	bufferedReader := bufio.NewReader(domainBlacklistFile)

	if err != nil {
		log.Info("No domain blacklist or couldn't read file")
		return
	}
	for {
		line, _, err := bufferedReader.ReadLine()
		lineString := string(line)
		if err != nil {
			break
		}
		if strings.Contains(lineString, "#") {
			nonComment := strings.Split(lineString, "#")[0]
			addToBlacklist(nonComment)
		} else {
			addToBlacklist(lineString)
		}
	}

}

func configureBlackLists() {

	configureDomainBlacklist()
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

func getContentLengthFromHeader(header string) (int, error) {
	r := strings.NewReplacer("Content-Length: ", "", "\r\n", "")
	lenString := r.Replace(header)
	contentLength, err := strconv.Atoi(lenString)
	if err != nil {
		return -1, err
	}
	return contentLength, nil

}

func getResourceFromHeader(header string, host string, port int) (string) {
	portString := ":" + strconv.Itoa(port)
	r := strings.NewReplacer("https://"+host, "", "http://"+host, "", portString, "")
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

func connectToHostNew(host string, port int) (net.Conn, error) {
	remoteAddrs, err := net.LookupIP(host)

	if err == nil {
		ipAddr := remoteAddrs[0]
		remoteAddrAndPort := &net.TCPAddr{IP: ipAddr, Port: port}

		return net.Dial("tcp", remoteAddrAndPort.String())
	} else {
		return nil, err
	}

}

//Blindly copies data across
func tunnelSSL(srcReadBuffer *bufio.Reader, dstWriteBuffer *bufio.Writer, dstConn *net.TCPConn, srcConn *net.TCPConn) {
	defer dstConn.Close()
	defer srcConn.Close()
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

//Copy the contents of a buffer from source to dst
func copy(srcReadBuffer *bufio.Reader, dstWriteBuffer *bufio.Writer, dstConn *net.TCPConn, srcConn *net.TCPConn) {
	//defer dstConn.Close()
	//defer srcConn.Close()
	defer closeWithLog(srcConn)
	defer closeWithLog(dstConn)
	headersFinished := false
	contentLength := -1
	isChunked := false
	for {
		if !headersFinished {

			line, err := srcReadBuffer.ReadString('\n')
			if err != nil {
				return
			}
			lineLower := strings.ToLower(line)
			if strings.Contains(lineLower, "transfer-encoding: chunked") {
				isChunked = true
			} else if strings.Contains(lineLower, "content-length: ") {
				contentLength, err = getContentLengthFromHeader(line)
				if err != nil {
					log.Debug(err)
					return
				}
			} else if line == "\r\n" {
				headersFinished = true
			}
			dstWriteBuffer.WriteString(line)

		} else {
			if contentLength > -1 {
				buf := make([]byte, contentLength)
				_, err := srcReadBuffer.Read(buf)
				if err != nil {
					log.Errorf("Error reading buffer", err)
					return
				}
				dstWriteBuffer.Write(buf)
			} else if isChunked {
				tunnelSSL(srcReadBuffer, dstWriteBuffer, dstConn, srcConn)
			}

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

func closeWithLog(conn *net.TCPConn) {
	log.Debugf("Closing conn from: %v to %v", conn.LocalAddr(), conn.RemoteAddr())
	conn.Close()
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
		closeWithLog(clientConn)
		//clientConn.Close()
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
			closeWithLog(clientConn)
			//clientConn.Close()
			break
		}

		messageString := string(message)

		// reached end of headers
		if messageString == "\r\n" {
			log.Debugf("Received end of header client %v \n", string(message))
			break
		} else {
			//Write headers to new buffer to forward for http
			//Exclude Proxy-Connection Header
			if !strings.Contains(messageString, "Proxy-Connection: Keep-Alive") {
				clientHeaderBuffer.WriteString(messageString)

			}
		}
		if strings.HasPrefix(messageString, "Host:") {
			//Extract host and port
			host, port, err = getHostAndPortFromHostHeader(messageString)

			if err != nil {
				closeWithLog(clientConn)
				//clientConn.Close()
				break
			}

			log.Debugf("Extracting host from:  %v =@@= %v", string(message), host)
			seenHostLine = true
		} else if strings.HasPrefix(messageString, "GET ") || strings.HasPrefix(messageString, "POST ") {
			resourceLine = messageString
			seenResourceLine = true
		}
	}
	if !seenHostLine || (!seenResourceLine && !isHttps) {
		//clientConn.Close()
		closeWithLog(clientConn)
		return
	}

	if isBlocked(host) {
		sendBlockedMessage(clientWriteBuffer, host)
		closeWithLog(clientConn)
		return
	}

	resourceHeader := getResourceFromHeader(resourceLine, host, port)

	remoteConn, err := connectToHost(host, port)
	if err != nil {
		log.Debugf("Failed connecting to: %v on behalf of: %v \n", net.JoinHostPort(host, strconv.Itoa(port)), clientConn.RemoteAddr().String())
		closeWithLog(clientConn)
		//clientConn.Close()
		return
	}

	remoteWriteBuffer := bufio.NewWriter(remoteConn)
	remoteReadBuffer := bufio.NewReader(remoteConn)

	go func() {
		connections <- fmt.Sprintf("Connected to: %v on behalf of: %v \n", remoteConn.RemoteAddr().String(), clientConn.RemoteAddr().String())
	}();
	log.Debugf("Connected to: %v on behalf of: %v \n", remoteConn.RemoteAddr().String(), clientConn.RemoteAddr().String())

	if isHttps {
		err = sendSSLTunnellingResponse(clientWriteBuffer)
		if err != nil {
			closeWithLog(clientConn)
			//clientConn.Close()
			closeWithLog(remoteConn)
			//remoteConn.Close()
			return
		}

		//Copy data from Server into client and client to server concurrently
		//Server into client
		go tunnelSSL(remoteReadBuffer, clientWriteBuffer, clientConn, remoteConn)
		//Client into server
		go tunnelSSL(clientReadBuffer, remoteWriteBuffer, remoteConn, clientConn)
	} else {
		err = sendClientHeadersToHost(clientHeaderBuffer, remoteWriteBuffer, resourceHeader)
		if err != nil {
			closeWithLog(clientConn)
			//clientConn.Close()
			closeWithLog(remoteConn)
			//remoteConn.Close()
			return
		}

		//closeWithLog(clientConn)
		//closeWithLog(remoteConn)
		//Server into client
		//copy(clientReadBuffer, remoteWriteBuffer, remoteConn, clientConn)

		copy(remoteReadBuffer, clientWriteBuffer, clientConn, remoteConn)
	}
}

func sendClientHeadersToHost(headers bytes.Buffer, hostBuffer *bufio.Writer, resourceHeader string) (err error) {

	for {
		line, headerError := headers.ReadString('\n')
		if headerError != nil {
			break
		}
		//Swap out GET header with non abs version
		if isHTTPMethod(line) {
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

func write403Contents(clientWriteBuffer *bufio.Writer, host string) {
	defer clientWriteBuffer.Flush()
	domainBlacklistFile, err := os.Open(_403_FILE)
	bufferedReader := bufio.NewReader(domainBlacklistFile)
	//No file to read, write simple
	if err != nil {
		forbiddenString := "Your system admin has blocked access to " + host
		clientWriteBuffer.WriteString(forbiddenString)
		return
	}
	r := strings.NewReplacer("%HOST%", host)

	for {
		line, _, err := bufferedReader.ReadLine()
		lineString := string(line)
		if err != nil {
			break
		}
		//Replace all occurrences of host placeholder with actual host
		lineString = r.Replace(lineString)
		clientWriteBuffer.WriteString(lineString)
	}
}

func sendBlockedMessage(clientWriteBuffer *bufio.Writer, host string) {
	clientWriteBuffer.WriteString("HTTP/1.1 403 FORBIDDEN\r\n\r\n")
	write403Contents(clientWriteBuffer, host)
	clientWriteBuffer.Flush()

}

func connectionPrinter() {
	for {
		connection := <-connections
		log.Infof("Connection info: %v", connection)
	}
}


func isHTTPMethod(header string) bool {
	return strings.HasPrefix(header, "GET ") || strings.HasPrefix(header, "POST ") || strings.HasPrefix(header, "HEAD ") || strings.HasPrefix(header, "OPTIONS ")
}

//Function for testing reading from a non closing connection with  multiple conns
func connectionLoopTest(conn net.Conn) {
	defer conn.Close()
	connReadBuffer := bufio.NewReader(conn)
	connWriteBuffer := bufio.NewWriter(conn)
	var contentBuffer bytes.Buffer
	var host string
	var port int
	//var resourceLine string
	seenResourceLine := false
	hasBody := false
	contentLength := 0
	resourceHeader := ""
	for {
		curString, err := connReadBuffer.ReadString('\n')
		if err != nil {
			log.Debug("Finished reading", err)
			break
		}

		if curString == "\r\n"  {
			contentBuffer.WriteString(curString)
			if hasBody {
				body := make([]byte, contentLength)
				_, err := connReadBuffer.Read(body)
				if err != nil {
					log.Errorf("Error reading buffer", err)
					return
				}
				contentBuffer.Write(body)
			}
			break
		}

		if strings.HasPrefix(curString, "Host:") {
			host, port, err = getHostAndPortFromHostHeader(curString)

			if err != nil {
				log.Debug("Error getting host from header", err)
				return
			}
		} else if strings.HasPrefix(curString, "Content-Length: ") {
			contentLength, err = getContentLengthFromHeader(curString)
			hasBody = true
			if err != nil {
				return
			}
		} else if isHTTPMethod(curString){
			resourceHeader = curString
			seenResourceLine = true
		}
		contentBuffer.WriteString(curString)
	}

	if !seenResourceLine {
		return
	}


	if isBlocked(host) {
		sendBlockedMessage(connWriteBuffer, host)
		return
	}


	remoteConn, err := connectToHostNew(host, port)
	if err != nil {
		log.Debug("Error connecting to host", err)
		return
	}

	remoteConnWriter := bufio.NewWriter(remoteConn)

	resourceHeader = getResourceFromHeader(resourceHeader, host,port)
	sendClientHeadersToHost(contentBuffer, remoteConnWriter, resourceHeader)

	//Copy remote conn into client
	io.Copy(conn, remoteConn)
}

func main() {
	configureLogging()
	configureBlackLists()
	//go connectionPrinter()

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
		conn, err := listener.Accept()
		if err != nil {
			log.Infof("Error accepting connection: %v\n", err)
			continue
		}
		log.Debugf("New Conn from %v", conn.RemoteAddr())
		//go proxyData(conn)
		go connectionLoopTest(conn)
	}
}
