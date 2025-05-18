# 🏭 Copacetic Scanner Plugin Template

This is a template repo for creating a scanner plugin for [Copacetic](https://github.com/project-copacetic/copacetic).

Learn more about Copacetic's scanner plugins [here](https://project-copacetic.github.io/copacetic/website/scanner-plugins).

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
git clone https://github.com/project-copacetic/scanner-plugin-template.git

# change directory to the repo
cd scanner-plugin-template

# build the copa-fake binary
make

# add copa-fake binary to PATH
export PATH=$PATH:dist/linux_amd64/release/

# test plugin with example config
copa-fake testdata/fake_report.json
# this will print the report in JSON format
# {"apiVersion":"v1alpha1","metadata":{"os":{"type":"FakeOS","version":"42"},"config":{"arch":"amd64"}},"updates":[{"name":"foo","installedVersion":"1.0.0","fixedVersion":"1.0.1","vulnerabilityID":"VULN001"},{"name":"bar","installedVersion":"2.0.0","fixedVersion":"2.0.1","vulnerabilityID":"VULN002"}]}

# run copa with the scanner plugin (copa-fake) and the report file
copa patch -i $IMAGE -r testdata/fake_report.json --scanner fake
# this is for illustration purposes only
# it will fail with "Error: unsupported osType FakeOS specified"
```
