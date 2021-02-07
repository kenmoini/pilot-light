package main

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/viper"
	"gopkg.in/yaml.v2"
)

var plVersion string = "0.0.1"
var readConfig *Config

// BUFFERSIZE is for copying files
var BUFFERSIZE int64 = 4096

// Config struct for webapp config
type Config struct {
	PilotLight PilotLightYaml `yaml:"pilot_light"`
}

// PilotLightYaml is what is defined for this Pilot Light server
type PilotLightYaml struct {
	Version             string        `yaml:"version"`
	AssetDirectory      string        `yaml:"asset_directory"`
	DNSServer           string        `yaml:"dns_server"`
	InstallConfigPath   string        `yaml:"install_config_path"`
	MastersSchedulable  bool          `yaml:"masters_schedulable"`
	DefaultIgnitionFile string        `yaml:"default_ignition_file"`
	OCPStream           string        `yaml:"ocp_stream"`
	OCPVersion          string        `yaml:"ocp_version"`
	Server              Server        `yaml:"server"`
	Database            Database      `yaml:"database"`
	IgnitionSets        []IgnitionSet `yaml:"ignition_sets"`
	InstallConfig       InstallConfig `yaml:"install_config,omitempty"`
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

// InstallConfig defines the attached InstallConfig from the general configuration of openshift-install or whatever i dunno i'm drunk - so evidently this doesn't work and doesnt properly do sshKey and pullSecret when writing to yaml file
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

// copy a file
func copy(src, dst string, BUFFERSIZE int64) error {
	log.Printf("Copying  %s to %s\n", src, dst)
	if BUFFERSIZE == 0 {
		BUFFERSIZE = 4096
	}
	sourceFileStat, err := os.Stat(src)
	if err != nil {
		return err
	}

	if !sourceFileStat.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", src)
	}

	source, err := os.Open(src)
	if err != nil {
		return err
	}
	defer source.Close()

	_, err = os.Stat(dst)
	if err == nil {
		return fmt.Errorf("File %s already exists", dst)
	}

	destination, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer destination.Close()

	if err != nil {
		panic(err)
	}

	buf := make([]byte, BUFFERSIZE)
	for {
		n, err := source.Read(buf)
		if err != nil && err != io.EOF {
			return err
		}
		if n == 0 {
			break
		}

		if _, err := destination.Write(buf[:n]); err != nil {
			return err
		}
	}
	return err
}

// DownloadFile will download a url to a local file. It's efficient because it will
// write as it downloads and not load the whole file into memory.
func DownloadFile(filepath string, url string) error {
	log.Printf("Downloading %s to %s\n", url, filepath)
	// Get the data
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Create the file
	out, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer out.Close()

	// Write the body to file
	_, err = io.Copy(out, resp.Body)
	return err
}

// Untar takes a destination path and a reader; a tar reader loops over the tarfile
// creating the file structure at 'dst' along the way, and writing any files
func Untar(dst string, srcFile string) error {
	log.Printf("Extracting %s to %s\n", srcFile, dst)
	r, err := os.Open(srcFile)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	defer r.Close()

	gzr, err := gzip.NewReader(r)
	if err != nil {
		return err
	}
	defer gzr.Close()

	tr := tar.NewReader(gzr)

	for {
		header, err := tr.Next()

		switch {

		// if no more files are found return
		case err == io.EOF:
			return nil

		// return any other error
		case err != nil:
			return err

		// if the header is nil, just skip it (not sure how this happens)
		case header == nil:
			continue
		}

		// the target location where the dir/file should be created
		target := filepath.Join(dst, header.Name)

		// the following switch could also be done using fi.Mode(), not sure if there
		// a benefit of using one vs. the other.
		// fi := header.FileInfo()

		// check the file type
		switch header.Typeflag {

		// if its a dir and it doesn't exist create it
		case tar.TypeDir:
			if _, err := os.Stat(target); err != nil {
				if err := os.MkdirAll(target, 0755); err != nil {
					return err
				}
			}

		// if it's a file create it
		case tar.TypeReg:
			f, err := os.OpenFile(target, os.O_CREATE|os.O_RDWR, os.FileMode(header.Mode))
			if err != nil {
				return err
			}

			// copy over contents
			if _, err := io.Copy(f, tr); err != nil {
				return err
			}

			// manually close here after each file operation; defering would cause each file close
			// to wait until all operations have completed.
			f.Close()
		}
	}
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

func replaceMastersSchedulable(filePath string) {
	input, err := ioutil.ReadFile(filePath)
	check(err)

	lines := strings.Split(string(input), "\n")

	for i, line := range lines {
		if strings.Contains(line, "mastersSchedulable: true") {
			lines[i] = "  mastersSchedulable: false"
		}
	}
	output := strings.Join(lines, "\n")
	err = ioutil.WriteFile(filePath, []byte(output), 0644)
	check(err)
}

// createDirectory is self explanitory
func createDirectory(path string) {
	log.Printf("Creating directory %s\n", path)
	_, err := os.Stat(path)
	if os.IsNotExist(err) {
		errDir := os.MkdirAll(path, 0755)
		check(errDir)
	}
}

// deleteFile deletes a file
func deleteFile(path string) {
	log.Printf("Deleting %s\n", path)
	e := os.Remove(path)
	check(e)
}

// PreflightSetup is to write the install-config.yaml file for openshift-install
func PreflightSetup(config Config) {
	// Remove generation directory if it exists
	log.Printf("Cleaning up asset directory %s\n", config.PilotLight.AssetDirectory)
	err := os.RemoveAll(config.PilotLight.AssetDirectory)
	check(err)

	absoluteBinPath, err := filepath.Abs(config.PilotLight.AssetDirectory + "/bin/")
	check(err)
	absoluteConfPath, err := filepath.Abs(config.PilotLight.AssetDirectory + "/conf/")
	check(err)

	// Create generation directory
	createDirectory(config.PilotLight.AssetDirectory)

	// Create bin directory
	createDirectory(absoluteBinPath)

	// Create conf directory
	createDirectory(absoluteConfPath)

	// Copy over the install-config.yml file
	copy(config.PilotLight.InstallConfigPath, absoluteConfPath+"/install-config.yaml", BUFFERSIZE)

	os := "linux"
	if runtime.GOOS == "darwin" {
		os = "mac"
	}

	// Download the openshift-install package
	err = DownloadFile(absoluteBinPath+"/openshift-install-"+os+".tar.gz", "https://mirror.openshift.com/pub/openshift-v4/clients/ocp/latest/openshift-install-"+os+".tar.gz")
	check(err)

	// Unzip the openshift-install package
	Untar(absoluteBinPath, absoluteBinPath+"/openshift-install-"+os+".tar.gz")

	// Remove unneeded files
	deleteFile(absoluteBinPath + "/openshift-install-" + os + ".tar.gz")
	deleteFile(absoluteBinPath + "/README.md")

	// Create bootstrap files
	log.Println("Creating bootstrap files...")
	d1 := []byte("#!/bin/sh\n" + absoluteBinPath + "/openshift-install create manifests --dir=" + absoluteConfPath)
	err = ioutil.WriteFile(absoluteBinPath+"/create_manifests.sh", d1, 0755)
	check(err)
	d2 := []byte("#!/bin/sh\n" + absoluteBinPath + "/openshift-install create ignition-configs --dir=" + absoluteConfPath)
	err = ioutil.WriteFile(absoluteBinPath+"/create_ignition_configs.sh", d2, 0755)
	check(err)

	// Run Manifest creation command
	log.Println("Creating manifests...")
	cmd := exec.Command(absoluteBinPath + "/create_manifests.sh")
	err = cmd.Start()
	check(err)

	// wait for command to finish
	cmd.Wait()
	log.Println("Manifest files created!")

	// Edit manifest file to disable scheduling workloads on Control Plane nodes
	if config.PilotLight.MastersSchedulable == false {
		log.Println("Setting Control Plane to not run workloads...")
		//ModifySchedulerYAMLFile("cluster-scheduler-02-config", "yml", absoluteConfPath+"/manifests/")
		replaceMastersSchedulable(absoluteConfPath + "/manifests/cluster-scheduler-02-config.yml")
	}

	// Create ignition files
	log.Println("Creating ignition configs...")
	cmd = exec.Command(absoluteBinPath + "/create_ignition_configs.sh")
	err = cmd.Start()
	check(err)

	log.Println("Preflight complete!")
}

// check does error checking
func check(e error) {
	if e != nil {
		log.Fatalf("error: %v", e)
	}
}

// ModifySchedulerYAMLFile opens a YAML file
func ModifySchedulerYAMLFile(fileName string, fileExt string, filePath string) {
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
	viper.AddConfigPath(filePath)

	err := viper.ReadInConfig() // Find and read the config file
	if err != nil {             // Handle errors reading the config file
		log.Fatal(err)
	}

	SchC := SchedulerConfig{}

	err = viper.Unmarshal(&SchC)
	if err != nil {
		log.Fatalf("unable to decode into struct, %v", err)
	}

	// Change value in map and marshal back into yaml
	viper.Set("spec.mastersSchedulable", false)

	_, err = yaml.Marshal(&SchC)
	if err != nil {
		log.Fatalf("error: %v", err)
	}

	viper.WriteConfig()

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
