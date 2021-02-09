package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
)

/*************************************************************************************
* DNS Lookup
*************************************************************************************/

// CustomDNSDialer is able to switch the target resolving DNS server
func CustomDNSDialer(ctx context.Context, network, address string) (net.Conn, error) {
	d := net.Dialer{}

	svr := readConfig.PilotLight.DNSServer
	fmt.Println("using DNS server: " + svr)
	return d.DialContext(ctx, "udp", svr)
}

// NslookupIP resolves an IP to a hostname via reverse DNS
func NslookupIP(ip string) (address []string, reterr error) {
	ctx, cancel := context.WithCancel(context.Background())
	r := net.Resolver{
		PreferGo: true,
		Dial:     CustomDNSDialer,
	}
	addresses, err := r.LookupAddr(ctx, ip)
	if err != nil {
		fmt.Println("error:", err)
		reterr = err
		cancel()
		return nil, err
	}
	if len(addresses) == 0 {
		fmt.Printf("error: addresses has a length of zero")
		address = addresses
		reterr = errors.New("error: addresses has a length of zero")
		cancel()
		return
	}
	fmt.Printf("reverse lookup from %s results in: %s\n", ip, addresses)
	address = addresses
	reterr = nil
	cancel()
	return
}

/*************************************************************************************
* IP Resolution
*************************************************************************************/

// ReadUserIP gets the requesting client's IP so you can do a reverse DNS lookup
func ReadUserIP(r *http.Request) string {
	IPAddress := r.Header.Get("X-Real-Ip")
	if IPAddress == "" {
		IPAddress = r.Header.Get("X-Forwarded-For")
	}
	if IPAddress == "" {
		IPAddress = r.RemoteAddr
	}
	return IPAddress
}

// ReadUserIPNoPort gets the requesting client's IP without the port so you can do a reverse DNS lookup
func ReadUserIPNoPort(r *http.Request) string {
	IPAddress := ReadUserIP(r)

	NoPort := strings.Split(IPAddress, ":")
	if len(NoPort) > 0 {
		NoPort = NoPort[:len(NoPort)-1]
	}
	JoinedAddress := strings.Join(NoPort[:], ":")
	return JoinedAddress
}
