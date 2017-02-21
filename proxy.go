package main

import (
	"net"

	log "github.com/zdannar/flogger"
	"bufio"
	"strings"
	"strconv"
	"bytes"
	"os"
	"sync"
	"io"
	"crypto/md5"
	"encoding/hex"
	"io/ioutil"
	"flag"
	"net/http"
	"time"
	"encoding/json"
)

const _DEFAULTLOG = "/var/log/go-proxy.log"
const _IP_BLACKLIST = "ip_blacklist.txt"
const _DOMAIN_BLACKLIST = "domain_blacklist.txt"
const _403_FILE = "403.html"

var hub = newHub()

var blacklist = struct {
	sync.RWMutex
	m map[string]bool
}{m: make(map[string]bool)}

//Struct used for messages to Management Console
type ConnectionMessage struct {
	Src     string
	Dst     string
	Cached  bool
	Https   bool
	Blocked bool
	Time    int32
	MsgType string
}

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

func removeFromBlacklist(item string) {
	blacklist.Lock()
	blacklist.m[item] = false
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

//Load blacklist files and add to hashmaps
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
	//TODO: Add stuff for IP blacklist etc
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

//Extract Host and Port from Host: Header
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
//Extract contentLength from Header
func getContentLengthFromHeader(header string) (int, error) {
	r := strings.NewReplacer("Content-Length: ", "", "\r\n", "")
	lenString := r.Replace(header)
	contentLength, err := strconv.Atoi(lenString)
	if err != nil {
		return -1, err
	}
	return contentLength, nil

}
//Get the relative resource path. ie remove https:// / http:// from the string so the remote server understands
func getResourceFromHeader(header string, host string, port int) (string) {
	portString := ":" + strconv.Itoa(port)
	r := strings.NewReplacer("https://"+host, "", "http://"+host, "", portString, "")
	resource := r.Replace(header)
	return resource
}

//Return a connection to the host and port
func connectToHost(host string, port int) (net.Conn, error) {
	remoteAddrs, err := net.LookupIP(host)

	if err == nil {
		ipAddr := remoteAddrs[0]
		remoteAddrAndPort := &net.TCPAddr{IP: ipAddr, Port: port}

		return net.Dial("tcp", remoteAddrAndPort.String())
	} else {
		return nil, err
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
//Alter the headers and then send them on
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

//Response sent to user if site is blocked. Has template backed file or failing that a dynamic string is returned
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

	// Basic templating - replace occurances of strings and write to clientBuffer
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
//Checks if a header string has a HTTP Method in it
func isHTTPMethod(header string) bool {
	return strings.HasPrefix(header, "GET ") || strings.HasPrefix(header, "POST ") || strings.HasPrefix(header, "HEAD ") || strings.HasPrefix(header, "OPTIONS ")
}

//Procedure for HTTP Connections
func handleHTTP(conn net.Conn, connReadBuffer *bufio.Reader, connWriteBuffer *bufio.Writer) {
	defer conn.Close()
	var contentBuffer bytes.Buffer
	var host string
	var port int

	seenResourceLine := false
	hasBody := false
	contentLength := 0
	resourceHeader := ""

	//Process entire set of headers so we have Host and Get/Post etc so we can remove the host from Get
	for {
		curString, err := connReadBuffer.ReadString('\n')
		if err != nil {
			log.Debug("Finished reading", err)
			break
		}

		if curString == "\r\n" {
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
		} else if isHTTPMethod(curString) {
			resourceHeader = curString
			seenResourceLine = true
		}
		contentBuffer.WriteString(curString)
	}

	//We need to method line to do anything
	if !seenResourceLine {
		return
	}

	if isBlocked(host) {
		sendConnectionInfoToConsole(conn.LocalAddr().String(), host, false, false, true)

		sendBlockedMessage(connWriteBuffer, host)
		return
	}
	//Backup to use for cache check - need full string with host for uniqueness
	oldResourceHeader := resourceHeader
	data, exists := checkCacheAndRetrieve(oldResourceHeader)
	//Log to MGMT console
	sendConnectionInfoToConsole(conn.LocalAddr().String(), host, exists, false, false)

	if exists {
		log.Infof("Cache HIT!!")
		reader := bytes.NewReader(data)
		io.Copy(conn, reader)
	} else {
		//Cache MISS
		log.Infof("Cache MISS!! - %v", oldResourceHeader)

		remoteConn, err := connectToHost(host, port)
		if err != nil {
			log.Debug("Error connecting to host", err)
			return
		}

		remoteConnWriter := bufio.NewWriter(remoteConn)
		resourceHeader = getResourceFromHeader(resourceHeader, host, port)
		sendClientHeadersToHost(contentBuffer, remoteConnWriter, resourceHeader)


		/*Code below splits the servers response into two buffers so that we can read it twice concurrently
		  One is sent to the client and the other is checked if it is cacheable and writes it to disk
		*/
		//The below code was mostly taken from here http://rodaine.com/2015/04/async-split-io-reader-in-golang/
		pr, pw := io.Pipe()
		tr := io.TeeReader(remoteConn, pw)

		// create channels to synchronize
		done := make(chan bool)
		errs := make(chan error)
		//defer close(done)
		defer close(errs)

		go func() {
			_, err := io.Copy(conn, pr)

			if err != nil {
				errs <- err
				return
			}

			done <- true
		}()

		go func() {
			// close the PipeWriter after the
			// TeeReader completes to trigger EOF
			defer pw.Close()

			_, err := cacheData(tr, oldResourceHeader)
			if err != nil {
				errs <- err
				return
			}

			done <- true
		}()

		// wait until both are done
		// or an error occurs
		for c := 0; c < 2; {
			select {
			case <-errs:
				return
			case <-done:
				c++
			}
		}

	}
}

//Determine if the given data should be cached and Cache the given data- returns a bool saying if it was cached or not
func cacheData(data io.Reader, resourceName string) (bool, error) {
	br := bufio.NewReader(data)
	var contentBuffer bytes.Buffer

	shouldCache := false
	cacheLine := ""

	for {
		line, err := br.ReadString('\n')

		if err != nil {
			break
		}

		contentBuffer.WriteString(line)

/*		if strings.HasPrefix(line, "HTTP/1.1: ") {
			if checkHTTPStatusCodeForCache(line) {
				//TODO: Remove codes that don't cache
			}
		}*/
		lineLower := strings.ToLower(line)
		if strings.HasPrefix(lineLower, "cache-control: ") {
			cacheLine = line
			shouldCache = checkCacheHeader(cacheLine)

		}

	}


	//Copy remaining data after headers
	for {
		curByte, err := br.ReadByte()
		if err != nil {
			break
		}
		contentBuffer.WriteByte(curByte)
	}

	if shouldCache {
		writeCacheItem(resourceName, contentBuffer)
	}
	return shouldCache, nil
}
func checkHTTPStatusCodeForCache(header string) bool {
	r := strings.NewReplacer("HTTP/1.1 : ", "", "\r\n", "")
	codeString := r.Replace(header)

	if strings.HasPrefix(codeString, "200") {
		return true
	}

	return false
}



func getMD5Hash(text string) string {
	hasher := md5.New()
	hasher.Write([]byte(text))
	return hex.EncodeToString(hasher.Sum(nil))
}

//Cache is based on a file with a name that is the MD5 of the request eg GET http://www.tcd.ie/index.html HTTP 1.1
// Could have cleaned out the start and end but no need
func writeCacheItem(resourceName string, content bytes.Buffer) {
	resourceName = getMD5Hash(resourceName)
	log.Debugf("MD5: %v", resourceName)
	f, err := os.Create("cache/" + resourceName)
	defer f.Close()

	if err != nil {
		log.Error("Could not create file", err)
	}

	contentReader := bufio.NewReader(&content)
	io.Copy(f,contentReader)
}

//Check if file exists with required hash
func checkCacheHit(resourceName string) bool {
	hash := getMD5Hash(resourceName)

	if _, err := os.Stat("cache/" + hash); os.IsNotExist(err) {
		return false
	}
	log.Infof("Hit for : %v - %v",resourceName, hash)
	return true
}

//False if no data -
func checkCacheAndRetrieve(resourceName string) ([]byte, bool) {
	hash := getMD5Hash(resourceName)

	if !checkCacheHit(resourceName) {
		return nil, false
	}

	b, err := ioutil.ReadFile("cache/" + hash) // just pass the file name

	if err != nil {
		return nil, false
	}
	return b, true
}


//Header values not to cache
func isCacheValue(value string) (bool) {
	if value == "no-cache" || value == "max-age=0" || value == "private" || value == "max-age=2" {
		return false
	}

	return true

}

//Returns false if the header indicates the data shouldn't be cached - true if that data should be cached
func checkCacheHeader(header string) (bool) {
	header = strings.ToLower(header)
	r := strings.NewReplacer("cache-control: ", "", "\r\n", "")
	cacheLine := r.Replace(header)

	if strings.Contains(cacheLine, ",") {
		cacheLineElements := strings.Split(cacheLine, ",")

		for i := 0; i < len(cacheLineElements); i++ {
			el := cacheLineElements[i]
			if isCacheValue(el) == false {
				return false
			}
		}

	} else {
		return isCacheValue(cacheLine)
	}

	return true
}
// Base area where conn is checked if is requesting to open HTTPS tunnel
func handleConnection(conn net.Conn) {
	connectionReader := bufio.NewReader(conn)
	connectionWriter := bufio.NewWriter(conn)

	isHttps, err := checkIsHttps(connectionReader)
	if err != nil {
		return
	}
	if isHttps {
		handleHTTPS(conn, connectionReader, connectionWriter)
	} else {
		handleHTTP(conn, connectionReader, connectionWriter)
	}
}

//Procedure for HTTPS - Very simple compared to HTTP
// Open remote conn, send local client the message to indicate tunnel is ready and then concurrently copy from
// client to server and vice versa
// https://tools.ietf.org/html/draft-luotonen-ssl-tunneling-03
func handleHTTPS(conn net.Conn, reader *bufio.Reader, writer *bufio.Writer) {
	var host string
	var port int

	for {
		curLine, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		if strings.HasPrefix(curLine, "Host: ") {
			host, port, err = getHostAndPortFromHostHeader(curLine)
			if err != nil {
				return
			}
			break
		}
	}

	if isBlocked(host) {
		sendConnectionInfoToConsole(conn.LocalAddr().String(), host, false, true, true)
		sendBlockedMessage(writer, host)
		return
	}

	remoteConn, err := connectToHost(host, port)
	if err != nil {
		log.Debug("Error connecting to host", err)
		return
	}

	sendConnectionInfoToConsole(conn.LocalAddr().String(), host, false, true, false)


	remoteConnWriter := bufio.NewWriter(remoteConn)

	sendSSLTunnellingResponse(writer)

	//Copy remote conn into client
	go io.Copy(remoteConnWriter, conn)
	go io.Copy(conn, remoteConn)
}

//Pull domain to be blocked/unblocked out of command
func getDomainFromCommand(command string) string {
	r := strings.NewReplacer("unblock ", "", "block ", "", "\r\n", "")
	return r.Replace(command)
}

// Process available commands in MGMT console
func handleManagementConsoleMessage(command string) (ConnectionMessage) {

	line := strings.ToLower(command)

	if strings.HasPrefix(line, "block ") {
		domain := getDomainFromCommand(line)
		addToBlacklist(domain)
		return ConnectionMessage{Dst: domain, MsgType:"block"}
	}

	if strings.HasPrefix(line, "unblock ") {
		domain := getDomainFromCommand(line)
		removeFromBlacklist(domain)
		return ConnectionMessage{Dst: domain, MsgType:"unblock"}
	}

	return ConnectionMessage{}

}

var addr = flag.String("addr", ":8081", "http service address")

//Serves required files for MGMT console
//Most of this websocket code is taken from the example for the gorilla/websocket library
//Altered to add another channel for commands
//All functionality I needed was in the example
func serveHome(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.Error(w, "Not found", 404)
		return
	}
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", 405)
		return
	}
	http.ServeFile(w, r, "home.html")
}

func setupWebsockets(hub *Hub) {
	flag.Parse()
	go hub.run()
	http.HandleFunc("/", serveHome)
	http.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		serveWs(hub, w, r)
	})

	err := http.ListenAndServe(*addr, nil)
	if err != nil {
		log.Fatal("ListenAndServe: ", err)
	}
}

//write bytes to broadcast channel - this is caught in the Hub and sent to all clients(Management Console Clients)
func sendToConsole(msg []byte) {
	hub.broadcast <- msg
}
//Build object and convert to json to write broadcast channel
func sendConnectionInfoToConsole(src string, dst string, cached bool, https bool, blocked bool) {
	msg := ConnectionMessage{Src: src, Dst: dst, Cached: cached, Https: https, Blocked: blocked, Time: int32(time.Now().Unix()), MsgType: "connMsg"}
	json, err := json.Marshal(msg)

	if err != nil {
		return
	}
	sendToConsole(json)
}

func main() {
	configureLogging()
	configureBlackLists()

	go setupWebsockets(hub)

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
		go handleConnection(conn)
	}
}
