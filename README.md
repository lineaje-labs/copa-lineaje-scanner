# 🏭 Copacetic Scanner Plugin Template

This is a template repo for creating a scanner plugin for [Copacetic](https://github.com/project-copacetic/copacetic).

Learn more about Copacetic's scanner plugins [here](https://project-copacetic.github.io/copacetic/scanner-plugins).

## Development

These instructions are for developing a new scanner plugin for [Copacetic](https://github.com/project-copacetic/copacetic) from this template.

1. Clone this repo
2. Rename the `scanner-plugin-template` repo to the name of your plugin
3. Update applicable types for [`FakeReport`](types.go) to match your scanner's structure
4. Update [`parse`](main.go) to parse your scanner's report format accordingly
5. Update `CLI_BINARY` in the [`Makefile`](Makefile) to match your scanner's CLI binary name (resulting binary must be prefixed with `copa-`)
5. Update this [`README.md`](README.md) to match your plugin's usage

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
copa-lineaje-scanner report.json
# this will print the report in JSON format
#  {"apiVersion":"v1alpha1","metadata":{"os":{"type":"debian","version":"11"},"config":{"arch":"amd64"}},"updates":[{"name":"ncurses-bin","installedVersion":"6.2+20201114-2","fixedVersion":"6.2+20201114-2+deb11u2","vulnerabilityID":"CVE-1234-56789"},{"name":"perl-base","installedVersion":"5.32.1-4+deb11u2","fixedVersion":"5.32.1-4+deb11u4","vulnerabilityID":"CVE-1234-56789"}]}

# run copa with the scanner plugin (copa-lineaje-scanner) and the report file
copa patch -i $IMAGE -r report.json --scanner lineaje
# this is for illustration purposes only
# it will fail with "Error: unsupported osType debian specified"
```