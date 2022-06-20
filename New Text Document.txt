# Negoexrelayx - Negoex relaying tool

Toolkit for abusing Kerberos PKU2U and NegoEx.
Requires [impacket](https://github.com/SecureAuthCorp/impacket)
It is recommended to install impacket from git directly to have the latest version available.

## negoexrelayx.py
This tool allows you to relay NegoEx (with PKU2U) authentication to other copmuter and authenticate without knowing the credentials, similar to Ntlmrelayx.
```
NegoEx relay tool. By @rubin_mor

Main options:
  -h, --help            show this help message and exit
  -debug                Turn DEBUG output ON
  -t TARGET, --target TARGET
                        Target to attack, since this is Kerberos, only HOSTNAMES are valid. Example: smb://server:445 If
                        unspecified, will store tickets for later use.
  -tf TARGETSFILE       File that contains targets by hostname or full URL, one per line
  -w                    Watch the target file for changes and update target list automatically (only valid with -tf)
  -ip INTERFACE_IP, --interface-ip INTERFACE_IP
                        IP address of interface to bind SMB and HTTP servers
  -r SMBSERVER          Redirect HTTP requests to a file:// path on SMBSERVER
  -l LOOTDIR, --lootdir LOOTDIR
                        Loot directory in which gathered loot (TGTs or dumps) will be stored (default: current directory).
  -codec CODEC          Sets encoding used (codec) from the target's output (default "utf-8"). If errors are detected, run
                        chcp.com at the target, map the result with https://docs.python.org/2.4/lib/standard-encodings.html and
                        then execute ntlmrelayx.py again with -codec and the corresponding codec
  -no-smb2support       Disable SMB2 Support
                        Prompt for authentication N times for clients without MS16-077 installed before serving a WPAD file.
  -6, --ipv6            Listen on both IPv6 and IPv4

SMB attack options:
  -e FILE               File to execute on the target system. If not specified, hashes will be dumped (secretsdump.py must be
                        in the same directory)
  -c COMMAND            Command to execute on target system. If not specified, hashes will be dumped (secretsdump.py must be in
                        the same directory).
  --enum-local-admins   If relayed user is not admin, attempt SAMR lookup to see who is (only works pre Win 10 Anniversary)

```