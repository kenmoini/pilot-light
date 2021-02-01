# Pilot Light - Reverse DNS-based Ignition Server for OpenShift

Imagine you want to install OpenShift with the Bare Metal UPI Installation method and you have an environment which does ***NOT*** allow you to:

- Pass Ignition or Afterburner Configuration to your Machines
- Set DHCP/PXE boot parameters
- Boot from ISO

...but you ***CAN***:

- Map and set Static IPs
- Manage forward and reverse DNS for your Machines
- Boot a QCow2 or similar VM Image that has the `/ignition.firstboot` file modified with:
  - A specific DNS server (your with Reverse A records), eg `nameserver=10.128.10.10`
  - The ignition url set to point to a server, eg `coreos.inst.ignition_url=http://10.128.10.10:8082/ignition-generator`
  - *Learn how to modify a Qcow2 file easily here:* https://kenmoini.com/blog/modify_disk_images_with_guestfish/

...then ***Pilot Light*** is for you!

## What Pilot Light Does

Pilot Light is a simple Golang application, which when supplied a `config.yml` file and an `install-config.yaml` for an OpenShift bare metal install, will generate the needed manifests and Ignition Configs for the cluster and serve them via an HTTP server for Machines that match a hostname pattern as matched from a Reverse DNS query.

## How to Use Pilot Light

```bash
$ ./pilot-light [-config file]
```

### 1. Generate The OpenShift Bare Metal UPI `install-config.yaml` file

An example `install-config.yaml` file looks like the following, making sure to change the `baseDomain`, `metadata.name`, `pullSecret`, and `sshKey`:

```yaml
apiVersion: v1
baseDomain: example.com
compute:
- hyperthreading: Enabled
  name: worker
  replicas: 0
controlPlane:
  hyperthreading: Enabled
  name: master
  replicas: 3
metadata:
  name: test
networking:
  clusterNetwork:
  - cidr: 10.128.0.0/14
    hostPrefix: 23
  networkType: OpenShiftSDN
  serviceNetwork:
  - 172.30.0.0/16
platform:
  none: {}
fips: false
pullSecret: '{"auths": ...}'
sshKey: 'ssh-ed25519 AAAA...'
```

### 2. Generate the Pilot Light `config.yml` file

A sample `config.yml` looks like this:

```yaml
pilot_light:
  version: 0.0.1

  asset_directory: ./.generated/
  dns_server: 10.128.10.10:53
  install_config_path: ./install-config.yaml
  masters_schedulable: false
  default_ignition_file: bootstrap

  server:
    host: 0.0.0.0
    path: "/generate-manifest"
    port: 8082
    timeout:
      server: 30
      read: 15
      write: 10
      idle: 5

  database:
    type: local
    path: db.sqlite

  ignition_sets:
    - name: bootstrap
      type: bootstrap
      hostname_format: bootstrap

    - name: control plane
      type: master
      hostname_format: master

    - name: application
      type: worker
      hostname_format: worker
```

### 3. Run Pilot Light

Running Pilot Light will do the following:

1. Create a Generation Directory and subdirectories
2. Copy over the `install-config.yaml` file to a `conf` directory
3. Download the OpenShift Install binary, unpack it, create manifests
4. [Optional] Set Control Plane nodes to not run workloads
5. Create the Ignition Configs
6. Start an HTTP Server
7. Respond to requests, do a reverse DNS lookup, match hostnames to Ignition Configs