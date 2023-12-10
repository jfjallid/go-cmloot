# go-CMLoot

## Description
Package go-cmloot is a tool built to find interesting files in the System
Center Configuration Manager (SCCM) SMB share. It is heavily inspired by the
projects https://github.com/1njected/CMLoot created by Tomas Rzepka and its
Python fork https://github.com/shelltrail/cmloot created by ShellTrail.
It is built on top of the library https://github.com/jfjallid/go-smb
and provides functionality to enumerate and download files from the
SCCMContentLib$ share.

## Usage
```
Usage: ./go-cmloot [options]

options:
      --host                Hostname or ip address of remote server
  -P, --port                SMB Port (default 445)
  -d, --domain              Domain name to use for login
  -u, --user                Username
  -p, --pass                Password
  -n, --no-pass             Disable password prompt and send no credentials
      --hash                Hex encoded NT Hash for user password
      --local               Authenticate as a local user instead of domain user
      --null	            Attempt null session authentication
      --inventory           File to store (or read from) all indexed filepaths (default sccmfiles.txt)
      --download <outdir>   Downloads all the files referenced by the inventory file to the <outdir>
      --single-file <path>  Download a single file with a specified path to the DataLib formatted as in the inventory file
      --relay               Start an SMB listener that will relay incoming
                            NTLM authentications to the remote server and
                            use that connection. NOTE that this forces SMB 2.1
                            without encryption.
      --relay-port <port>   Listening port for relay (default 445)
      --socks-host <target> Establish connection via a SOCKS5 proxy server
      --socks-port <port>   SOCKS5 proxy port (default 1080)
  -t, --timeout             Dial timeout in seconds (default 5)
      --share               Name of share to connect to (default SCCMContentLib$)
      --include-name        Regular expression filter for files from the inventory to download
      --include-exts        Comma-separated list of file extensions to download from the inventory.
                            Mutually exclusive with exclude-exts. (default INI,XML,CONFIG)
      --exclude-exts        Comma-separated list of file extensions to exclude from the inventory enumeration and the download.
                            Mutually exclusive with include-exts
      --min-size            Minimum file size to download in bytes
      --max-size            Maximum file size to download in bytes
      --noenc               Disable smb encryption
      --smb2                Force smb 2.1
      --verbose             Enable verbose logging
      --debug               Enable debug logging
  -v, --version             Show version
```

## Examples

### Enumerate files from SCCM server and create an inventory file

```
./go-cmloot --host server001 --user testuser --pass secretPass123 -d test.local
```

### Download all .ini, .xml, and .config files listed in the local inventory file

```
./go-cmloot --host server001 --user testuser --pass secretPass123 -d test.local --download loot
```

### Download all CAB files using a custom inventory file

```
./go-cmloot --host server001 --user testuser --pass secretPass123 -d test.local --include-exts cab --inventory index.txt --download loot
```

### Download a single file using datalib path

Make sure to properly quote or escape the double backslash
```
./go-cmloot --host server001 --user testuser --pass secretPass123 -d test.local --single-file '\\sccm\SCCMContentLib$\DataLib\SC10008D.1\Manifest.xml' --download loot
```
