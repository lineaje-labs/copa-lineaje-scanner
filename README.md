# 🏭 Copacetic Scanner Plugin Template

This is a template repo for creating a scanner plugin for [Copacetic](https://github.com/project-copacetic/copacetic).

Learn more about Copacetic's scanner plugins [here](https://project-copacetic.github.io/copacetic/scanner-plugins).

## Development Pre-requisites

> [!NOTE]
> You may have different pre-requisites for your scanner plugin, you are not required to use these tools.

The following tools are required to build and run this template:

- `git`: for cloning this repo
- `Go`: for building the plugin
- `make`: for the Makefile

## Example Development Workflow

This is an example development workflow for this template.

```shell
# clone this repo
git clone https://github.com/lineaje-labs/copa-lineaje-scanner.git

# change directory to the repo
cd copa-lineaje-scanner

# build the copa-lineaje-scanner binary
make

# add copa-lineaje-scanner binary to PATH
export PATH=$PATH:dist/linux_amd64/release/

# test plugin with example config
copa-lineaje-scanner testdata/fake_report.json
# this will print the report in JSON format
# {"apiVersion":"v1alpha1","metadata":{"os":{"type":"alpine","version":"3.18.0"},"config":{"arch":"x86_64"}},"updates":[{"name":"ssl_client","installedVersion":"1.36.0-r9","fixedVersion":"1.36.1-r7","vulnerabilityID":""},{"name":"musl","installedVersion":"1.2.4-r0","fixedVersion":"1.2.4-r3","vulnerabilityID":""},{"name":"libssl3","installedVersion":"3.1.0-r4","fixedVersion":"3.1.8-r0","vulnerabilityID":""},{"name":"musl-utils","installedVersion":"1.2.4-r0","fixedVersion":"1.2.4-r3","vulnerabilityID":""},{"name":"busybox-binsh","installedVersion":"1.36.0-r9","fixedVersion":"1.36.1-r7","vulnerabilityID":""},{"name":"libcrypto3","installedVersion":"3.1.0-r4","fixedVersion":"3.1.8-r0","vulnerabilityID":""},{"name":"busybox","installedVersion":"1.36.0-r9","fixedVersion":"1.36.1-r7","vulnerabilityID":""}]}

# run copa with the scanner plugin (copa-lineaje-scanner) and the report file
copa patch -i $IMAGE -r testdata/fake_report.json --scanner lineaje-scanner
# this is for illustration purposes only
# it will fail with "Error: unsupported osType FakeOS specified"
```