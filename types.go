package main

import "time"

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
	AssetServer         bool          `yaml:"asset_server"`
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

	Path string `yaml:"ignition_path"`

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
