package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/viper"
	"gopkg.in/yaml.v2"
)

var plVersion string = "0.0.1"
var readConfig *Config

// Config struct for webapp config
type Config struct {
	PilotLight PilotLightYaml `yaml:"pilot_light"`
}

// PilotLightYaml is what is defined for this Pilot Light server
type PilotLightYaml struct {
	Version       string        `yaml:"version"`
	DNSServer     string        `yaml:"dns_server"`
	Server        Server        `yaml:"server"`
	Database      Database      `yaml:"database"`
	IgnitionSets  []IgnitionSet `yaml:"ignition_sets"`
	InstallConfig InstallConfig `yaml:"install_config,omitempty"`
}

// Server configures the HTTP server providing Ignition files
type Server struct {
	// Host is the local machine IP Address to bind the HTTP Server to
	Host string `yaml:"host"`

	Path string `yaml:"path"`

	// Port is the local machine TCP Port to bind the HTTP Server to
	Port    string `yaml:"port"`
	Timeout struct {
		// Server is the general server timeout to use
		// for graceful shutdowns
		Server time.Duration `yaml:"server"`

		// Write is the amount of time to wait until an HTTP server
		// write opperation is cancelled
		Write time.Duration `yaml:"write"`

		// Read is the amount of time to wait until an HTTP server
		// read operation is cancelled
		Read time.Duration `yaml:"read"`

		// Read is the amount of time to wait
		// until an IDLE HTTP session is closed
		Idle time.Duration `yaml:"idle"`
	} `yaml:"timeout"`
}

// Database will store provided Ignition files with the request IPs/hostnames
type Database struct {
	Type string `yaml:"local"`
	Path string `yaml:"path"`
}

// IgnitionSet provides an interface to define the machine types it should respond to
type IgnitionSet struct {
	Name             string `yaml:"name"`
	Type             string `yaml:"type"`
	HostnameFormat   string `yaml:"hostname_format"`
	IgnitionTemplate string `yaml:"ignition_template,omitempty"`
}

// InstallConfig defines the attached InstallConfig from the general configuration of openshift-install or whatever i dunno i'm drunk
type InstallConfig struct {
	APIVersion   string            `yaml:"apiVersion"`
	BaseDomain   string            `yaml:"baseDomain"`
	Compute      []ComputeResource `yaml:"compute"`
	ControlPlane struct {
		HyperThreading string `yaml:"hyperthreading"`
		Name           string `yaml:"name"`
		replicas       int    `yaml:"replicas"`
	} `yaml:"controlPlane"`
	MetaData struct {
		Name string `yaml:"name"`
	} `yaml:"metadata"`
	Networking struct {
		NetworkType     string           `yaml:"networkType"`
		ClusterNetworks []ClusterNetwork `yaml:"clusterNetwork"`
		ServiceNetworks []string         `yaml:"serviceNetwork"`
	} `yaml:"networking"`
	Platform struct {
		None struct{} `yaml:"none"`
	} `yaml:"platform"`
	FIPSMode   bool   `yaml:"fips"`
	pullSecret string `yaml:"pullSecret"`
	SSHKey     string `yaml:"sshKey"`
}

// ComputeResource is for all the compute resources you can't define lol
type ComputeResource struct {
	HyperThreading string `yaml:"hyperthreading"`
	Name           string `yaml:"name"`
	replicas       int    `yaml:"replicas"`
}

// ClusterNetwork technically is a mapped list...or whatever
type ClusterNetwork struct {
	CIDR       string `yaml:"cidr"`
	HostPrefix int    `yaml:"hostPrefix"`
}

// errorString is a trivial implementation of error.
type errorString struct {
	s string
}

func (e *errorString) Error() string {
	return e.s
}

// SchedulerConfig is meant to map to the /manifests/cluster-scheduler-02-config.yml file so you can set the Control Plnae nodes to not run workloads (taint em good)
type SchedulerConfig struct {
	apiVersion string `yaml:"apiVersion"`
	King       string `yaml:"kind"`
	Metadata   struct {
		CreationTimestamp string `yaml:"creationTimestamp"`
		Name              string `yaml:"name"`
	} `yaml:"metadata"`
	Spec struct {
		MastersSchedulable bool `yaml:"mastersSchedulable"`
		Policy             struct {
			Name string `yaml:"name"`
		} `yaml:"policy"`
	} `yaml:"spec"`
	Status struct{} `yaml:"status"`
}

// NewConfig returns a new decoded Config struct
func NewConfig(configPath string) (*Config, error) {
	// Create config structure
	config := &Config{}

	// Open config file
	file, err := os.Open(configPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	// Init new YAML decode
	d := yaml.NewDecoder(file)

	// Start YAML decoding from file
	if err := d.Decode(&config); err != nil {
		return nil, err
	}

	readConfig = config

	return config, nil
}

// ValidateConfigPath just makes sure, that the path provided is a file,
// that can be read
func ValidateConfigPath(path string) error {
	s, err := os.Stat(path)
	if err != nil {
		return err
	}
	if s.IsDir() {
		return fmt.Errorf("'%s' is a directory, not a normal file", path)
	}
	return nil
}

// ParseFlags will create and parse the CLI flags
// and return the path to be used elsewhere
func ParseFlags() (string, error) {
	// String that contains the configured configuration path
	var configPath string

	// Set up a CLI flag called "-config" to allow users
	// to supply the configuration file
	flag.StringVar(&configPath, "config", "./config.yml", "path to config file")

	// Actually parse the flags
	flag.Parse()

	// Validate the path first
	if err := ValidateConfigPath(configPath); err != nil {
		return "", err
	}

	// Return the configuration path
	return configPath, nil
}

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

	router.HandleFunc(generationPath, func(w http.ResponseWriter, r *http.Request) {
		clientIPAddress := ReadUserIPNoPort(r)
		address, err := NslookupIP(clientIPAddress)
		if err != nil {
			fmt.Fprintf(w, "Error in DNS resolution!\n\n%s", err)
		}
		if err == nil {
			fmt.Fprintf(w, "Address %s Resolved To Hostname: %s", clientIPAddress, address[0])
		}
	})

	return router
}

// Run will run the HTTP Server
func (config Config) Run() {
	// Set up a channel to listen to for interrupt signals
	var runChan = make(chan os.Signal, 1)

	// Set up a context to allow for graceful server shutdowns in the event
	// of an OS interrupt (defers the cancel just in case)
	ctx, cancel := context.WithTimeout(
		context.Background(),
		config.PilotLight.Server.Timeout.Server,
	)
	defer cancel()

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
	if err != nil {
		log.Fatal(err)
	}

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

// CustomDNSDialer is able to switch the target resolving DNS server
func CustomDNSDialer(ctx context.Context, network, address string) (net.Conn, error) {
	d := net.Dialer{}

	svr := readConfig.PilotLight.DNSServer
	fmt.Println("using DNS server: " + svr)
	return d.DialContext(ctx, "udp", svr)
}

// NslookupIP resolves an IP to a hostname via reverse DNS
func NslookupIP(ip string) (address []string, reterr error) {
	//ctx := context.Background()
	//ctx, cancel := context.WithTimeout(context.Background(), readConfig.PilotLight.Server.Timeout.Server)
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
	IPAddress := r.Header.Get("X-Real-Ip")
	if IPAddress == "" {
		IPAddress = r.Header.Get("X-Forwarded-For")
	}
	if IPAddress == "" {
		IPAddress = r.RemoteAddr
	}
	NoPort := strings.Split(IPAddress, ":")
	if len(NoPort) > 0 {
		NoPort = NoPort[:len(NoPort)-1]
	}
	JoinedAddress := strings.Join(NoPort[:], ":")
	return JoinedAddress
}

// OpenSchedulerYAMLFile opens a YAML file
func OpenSchedulerYAMLFile(fileName string, fileExt string, filePath string) (SchC SchedulerConfig) {
	if fileName == "" {
		fileName = "config"
	}
	if fileExt == "" {
		fileExt = "yml"
	}
	if filePath == "" {
		filePath = "."
	}
	viper.SetConfigName(fileName)
	viper.SetConfigType(fileExt)
	viper.AddConfigPath("/etc/pilot-light/")
	viper.AddConfigPath("$HOME/.pilot-light/")
	viper.AddConfigPath(filePath)

	err := viper.ReadInConfig() // Find and read the config file
	if err != nil {             // Handle errors reading the config file
		log.Fatal(err)
	}

	SchC = SchedulerConfig{}

	err = viper.Unmarshal(&SchC)
	if err != nil {
		log.Fatalf("unable to decode into struct, %v", err)
	}

	fmt.Println(SchC)

	return SchC

}

// Func main should be as small as possible and do as little as possible by convention
func main() {
	// Generate our config based on the config supplied
	// by the user in the flags
	cfgPath, err := ParseFlags()
	if err != nil {
		log.Fatal(err)
	}
	cfg, err := NewConfig(cfgPath)
	if err != nil {
		log.Fatal(err)
	}

	// Run the server
	cfg.Run()
}
