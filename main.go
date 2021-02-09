package main

import (
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/spf13/viper"
	"gopkg.in/yaml.v2"
)

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

// replaceMastersSchedulable is a dirty hack
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
	CreateDirectory(config.PilotLight.AssetDirectory)

	// Create bin directory
	CreateDirectory(absoluteBinPath)

	// Create conf directory
	CreateDirectory(absoluteConfPath)

	// Copy over the install-config.yml file
	CopyFile(config.PilotLight.InstallConfigPath, absoluteConfPath+"/install-config.yaml", BUFFERSIZE)

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
	DeleteFile(absoluteBinPath + "/openshift-install-" + os + ".tar.gz")
	DeleteFile(absoluteBinPath + "/README.md")

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
	cfg.RunHTTPServer()
}
