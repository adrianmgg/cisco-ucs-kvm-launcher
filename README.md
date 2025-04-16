# about
utility to launch the java-based KVM for a Cisco UCS server,
without the need for a browser with flash & java applet support.

# installation
either:
- install with `cargo install --git https://github.com/adrianmgg/cisco-ucs-kvm-launcher.git`
- or, clone and `cargo install --path .`

# usage
```
Usage: cisco-ucs-kvm-launcher [OPTIONS] --ip <IP> --username <USERNAME> --password <PASSWORD> --javaws <JAVAWS>

Options:
  -i, --ip <IP>
          [env: UCS_IP=]
  -u, --username <USERNAME>
          [env: UCS_USERNAME=]
  -p, --password <PASSWORD>
          [env: UCS_PASSWORD=]
  -j, --javaws <JAVAWS>
          path to OpenWebStart's javaws executable (or some other javaws, but YMMV) [env: JAVAWS_PATH=]
      --javaws-args <JAVAWS_ARGS>...
          extra arguments to be passed to javaws
      --do-cert-validation
          enable certificate validation (disabled by default)
      --use-https
          use https (will be http by default)
      --no-patch-jnlp-version
          skip patching the jvm version in the downloaded jnlp file
      --patch-jnlp-version-to <VERSION>
          [default: 1.8*]
  -h, --help
          Print help
  -V, --version
          Print version
```
> [!TIP]
> some cli arguments can also be supplied via environment variables, e.g. `UCS_IP` in place of `--ip`

# development
for better errors & more logging, run with these environment vars set:
- `RUST_LIB_BACKTRACE=1` (or `=full`)
- `RUST_LOG=debug` (or `=trace`)

# some stuff I referenced to build this
- [Manage UCS C-Series M3 and M4 Servers that Do Not Support HTML5 After Flash Deprecation](https://www.cisco.com/c/en/us/support/docs/servers-unified-computing/integrated-management-controller/217676-manage-ucs-c-series-m3-and-m4-servers-th.html)
- [Cisco UCS Rack-Mount Servers Cisco IMC XML API Programmer's Guide, Release 4.0](https://www.cisco.com/c/en/us/td/docs/unified_computing/ucs/c/sw/api/4_0/b_Cisco_IMC_api_40.pdf)
