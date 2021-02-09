package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

// NewRouter generates the router used in the HTTP Server
func NewRouter(generationPath string) *http.ServeMux {
	if generationPath == "" {
		generationPath = "/generate"
	}
	// Create router and define routes and return that router
	router := http.NewServeMux()

	router.HandleFunc("/version", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Pilot Light version: %s\n", plVersion)
	})

	router.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "OK")
	})

	router.HandleFunc("/assets/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "OK")
	})

	router.HandleFunc(generationPath, func(w http.ResponseWriter, r *http.Request) {
		clientIPAddress := ReadUserIPNoPort(r)
		address, err := NslookupIP(clientIPAddress)
		if err != nil {
			log.Printf("Error in DNS resolution!\n\n%s", err)
		}
		if err == nil {
			log.Printf("Address %s Resolved To Hostname: %s", clientIPAddress, address[0])
		}

		// Loop through ignition sets to do matching
		matchedHostname := false
		for k, v := range readConfig.PilotLight.IgnitionSets {
			if strings.Contains(address[0], v.HostnameFormat) {
				matchedHostname = true
				log.Printf("Matched hostname %s to IgnitionSet #%d %s", address[0], k, v.Name)
				dat, err := ioutil.ReadFile(readConfig.PilotLight.AssetDirectory + "/conf/" + v.Type + ".ign")
				check(err)
				fmt.Fprintf(w, string(dat))
			}
		}
		if !matchedHostname {
			if readConfig.PilotLight.DefaultIgnitionFile != "none" {
				log.Printf("No match for hostname %s to any IgnitionSets, serving %s.ign", address[0], readConfig.PilotLight.DefaultIgnitionFile)
				dat, err := ioutil.ReadFile(readConfig.PilotLight.AssetDirectory + "/conf/" + readConfig.PilotLight.DefaultIgnitionFile + ".ign")
				check(err)
				fmt.Fprintf(w, string(dat))
			} else {
				log.Printf("No match for hostname %s to any IgnitionSets", address[0])
			}
		}
	})

	return router
}

// RunHTTPServer will run the HTTP Server
func (config Config) RunHTTPServer() {
	// Set up a channel to listen to for interrupt signals
	var runChan = make(chan os.Signal, 1)

	// Set up a context to allow for graceful server shutdowns in the event
	// of an OS interrupt (defers the cancel just in case)
	ctx, cancel := context.WithTimeout(
		context.Background(),
		config.PilotLight.Server.Timeout.Server,
	)
	defer cancel()

	// Create install-config.yaml file
	PreflightSetup(config)

	// Define server options
	server := &http.Server{
		Addr:         config.PilotLight.Server.Host + ":" + config.PilotLight.Server.Port,
		Handler:      NewRouter(config.PilotLight.Server.Path),
		ReadTimeout:  config.PilotLight.Server.Timeout.Read * time.Second,
		WriteTimeout: config.PilotLight.Server.Timeout.Write * time.Second,
		IdleTimeout:  config.PilotLight.Server.Timeout.Idle * time.Second,
	}

	// Only listen on IPV4
	l, err := net.Listen("tcp4", config.PilotLight.Server.Host+":"+config.PilotLight.Server.Port)
	check(err)

	// Handle ctrl+c/ctrl+x interrupt
	signal.Notify(runChan, os.Interrupt, syscall.SIGTSTP)

	// Alert the user that the server is starting
	log.Printf("Server is starting on %s\n", server.Addr)

	// Run the server on a new goroutine
	go func() {
		//if err := server.ListenAndServe(); err != nil {
		if err := server.Serve(l); err != nil {
			if err == http.ErrServerClosed {
				// Normal interrupt operation, ignore
			} else {
				log.Fatalf("Server failed to start due to err: %v", err)
			}
		}
	}()

	// Block on this channel listeninf for those previously defined syscalls assign
	// to variable so we can let the user know why the server is shutting down
	interrupt := <-runChan

	// If we get one of the pre-prescribed syscalls, gracefully terminate the server
	// while alerting the user
	log.Printf("Server is shutting down due to %+v\n", interrupt)
	if err := server.Shutdown(ctx); err != nil {
		log.Fatalf("Server was unable to gracefully shutdown due to err: %+v", err)
	}
}
