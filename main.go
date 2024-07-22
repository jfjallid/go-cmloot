// MIT License
//
// # Copyright (c) 2023 Jimmy Fjällid
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
package main

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"

	rundebug "runtime/debug"

	"golang.org/x/net/proxy"
	"golang.org/x/term"

	"github.com/jfjallid/go-smb/smb"
	"github.com/jfjallid/go-smb/spnego"
	"github.com/jfjallid/golog"
)

var log = golog.Get("")
var release string = "0.4.0"
var includedExts map[string]interface{}
var excludedExts map[string]interface{}
var nameRegexp *regexp.Regexp
var fileSizeThreshold uint64
var fileSizeLimit uint64
var downloadDir, inventoryFile string
var download bool

var hashRegexp *regexp.Regexp
var sizeRegexp *regexp.Regexp

const (
	KiB                 = 1024
	MiB                 = KiB * 1024
	GiB                 = MiB * 1024
	inventoryBufferSize = 1000 // Write every n rows to disk when building the inventory
)

type downloadProgress struct {
	fileSize int
	fd       *os.File
	ctr      int
}

func (self *downloadProgress) Write(b []byte) (int, error) {
	self.ctr += len(b)
	percent := (self.ctr * 100) / self.fileSize
	fmt.Printf("\rDownloaded %d%% (%d/%d) bytes", percent, self.ctr, self.fileSize)
	return self.fd.Write(b)
}

func formatSize(size int64) string {
	switch {
	case size >= GiB:
		return fmt.Sprintf("%.2f GiB", float64(size)/float64(GiB))
	case size >= MiB:
		return fmt.Sprintf("%.2f MiB", float64(size)/float64(MiB))
	case size >= KiB:
		return fmt.Sprintf("%.2f KiB", float64(size)/float64(KiB))
	default:
		return fmt.Sprintf("%d bytes", size)
	}
}

func isFlagSet(name string) bool {
	found := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == name {
			found = true
		}
	})
	return found
}

func parseINIFile(data []byte) (hash string, size int, err error) {
	matches := hashRegexp.FindSubmatch(data)
	if len(matches) < 2 {
		err = fmt.Errorf("data did not contain a Hash")
		log.Errorln(err)
		return
	}
	hash = string(matches[1])

	matches = sizeRegexp.FindSubmatch(data)
	if len(matches) < 2 {
		err = fmt.Errorf("data did not contain a Size")
		log.Errorln(err)
		return
	}
	size, err = strconv.Atoi(string(matches[1]))
	return
}

func writeInventoryLinesToFile(f *os.File, names <-chan string) error {
	writer := bufio.NewWriter(f)
	buffer := make([]string, 0, inventoryBufferSize)

	for name := range names {
		buffer = append(buffer, name)

		if len(buffer) >= inventoryBufferSize {
			if err := flushLineBuffer(writer, &buffer); err != nil {
				return err
			}
		}
	}

	if len(buffer) > 0 {
		if err := flushLineBuffer(writer, &buffer); err != nil {
			return err
		}
	}

	return nil
}

func flushLineBuffer(writer *bufio.Writer, buffer *[]string) error {
	for _, line := range *buffer {
		if _, err := writer.WriteString(line); err != nil {
			return err
		}
	}

	if err := writer.Flush(); err != nil {
		return err
	}

	*buffer = (*buffer)[:0]
	return nil
}

func downloadFile(session *smb.Connection, file string, skipFilters bool) {
	// Strip filepath of prefix
	tmpPath := strings.TrimPrefix(file, "\\\\")

	parts := strings.Split(tmpPath, "\\")
	if len(parts) < 5 {
		log.Errorf("Invalid path to download (%s)\n", file)
		return
	}
	share := parts[1]
	// When running this tool on linux against a windows SMB share, the path separators will differ
	_, filename := path.Split(strings.ReplaceAll(tmpPath, "\\", string(os.PathSeparator)))
	metafilepath := strings.Join(parts[2:], "\\")
	extension := strings.ToUpper(path.Ext(filename))

	// Filter based on extension and filename
	if !skipFilters {
		if includedExts != nil {
			if _, ok := includedExts[extension]; !ok {
				log.Debugf("Skipping download of file with name: %s due to extension missing from --include-exts\n", filename)
				// Skip file
				return
			}
		} else if excludedExts != nil {
			if _, ok := excludedExts[extension]; ok {
				log.Debugf("Skipping download of file with name: %s due to explicitly excluded extension\n", filename)
				// Skip file
				return
			}
		}

		// Check name regexp
		if nameRegexp != nil {
			if !nameRegexp.MatchString(filename) {
				log.Debugf("Skipping download of file with name: %s due to not matching --include-name regexp\n", filename)
				// Skip file
				return
			}
		}
	}

	buf := bytes.NewBuffer([]byte{})
	err := session.RetrieveFile(share, metafilepath+".INI", 0, buf.Write)
	if err != nil {
		log.Errorf("Failed to retrieve the INI file (%s). Likely permission denied\n", file)
		return
	}

	hash, size, err := parseINIFile(buf.Bytes())
	if !skipFilters {
		// Filter based on file size
		if size < int(fileSizeThreshold) {
			// Skip
			log.Infof("Skipping download of file with name: %s and size: %d due to below specified min-size\n", filename, size)
			return
		}
		if (fileSizeLimit > 0) && (size > int(fileSizeLimit)) {
			// Skip
			log.Infof("Skipping download of file with name: %s and size: %d due to above specified max-size\n", filename, size)
			return
		}
	}

	// Do not replace existing files, just log that file was already downloaded
	// Open local file in the outdir and start downloading the file
	// The filename will be first 4 Hex characters of the hash followed by a dash (-) and then the filename
	// There is still a risk of duplicates being ignored but that is accepted as the content is probably identical
	localFilename := fmt.Sprintf("%s%s%s-%s", downloadDir, string(os.PathSeparator), hash[0:4], filename)
	f, err := os.OpenFile(localFilename, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0640)
	if err != nil {
		if os.IsExist(err) {
			log.Errorf("Already downloaded file (%s)\n", localFilename)
			return
		}
		log.Errorln(err)
		return
	}

	/*
	   Download the file referenced in the inventory file
	   Then parse the value of the Hash
	   Use the first 4 hex characters to located the FileLib directory
	   Download the file with the hash as name located in the 4 hex char directory
	   and write it into the opened file on disk
	*/

	// Call library function to retrieve the file
	filepath := fmt.Sprintf("FileLib\\%s\\%s", hash[0:4], hash)
	// Show progress of file download
	log.Noticef("Starting to download (%s) with size: %s\n", strings.TrimPrefix(localFilename, downloadDir+string(os.PathSeparator)), formatSize(int64(size)))
	dp := downloadProgress{fileSize: size, fd: f}
	err = session.RetrieveFile(share, filepath, 0, dp.Write)
	//err = session.RetrieveFile(share, filepath, 0, f.Write)
	if err != nil {
		log.Errorln(err)
		f.Close()
		return
	}
	// Clear the progress outprint
	fmt.Printf("\r%s\r", string(make([]byte, 80)))
	log.Noticef("Downloaded (%s)\n", strings.TrimPrefix(localFilename, downloadDir+string(os.PathSeparator)))
	f.Close()
	return
}

func listFilesRecursively(session *smb.Connection, share, dir string, callback func(name string) error) (err error) {
	files, err := session.ListDirectory(share, dir, "*")
	if err != nil {
		if err == smb.StatusMap[smb.StatusAccessDenied] {
			log.Errorf("Could connect to [%s] but listing files in directory (%s) was prohibited\n", share, dir)
			return
		}
		log.Errorln(err)
		return
	}

	for _, file := range files {
		if file.IsDir && !file.IsJunction {
			err = listFilesRecursively(session, share, file.FullPath, callback)
			if err != nil {
				log.Errorf("Failed to list files in directory %s with error: %s\n", file.FullPath, err)
				continue
			}
		} else if !file.IsDir && !file.IsJunction {
			err = callback(file.FullPath)
			if err != nil {
				log.Errorln(err)
			}
		}
	}

	return
}

func buildInventory(session *smb.Connection, share string, callback func(path string) error) (err error) {
	log.Noticef("Attempting to open share: %s and list content\n", share)

	// Connect to share
	err = session.TreeConnect(share)
	if err != nil {
		if err == smb.StatusMap[smb.StatusBadNetworkName] {
			log.Errorf("Share %s can not be found!\n", share)
			return
		}
		log.Errorln(err)
		return
	}
	defer session.TreeDisconnect(share)

	items, err := session.ListDirectory(share, "DataLib", "*")
	if err != nil {
		if err == smb.StatusMap[smb.StatusAccessDenied] {
			log.Errorf("Could connect to [%s] but listing files in directory DataLib was prohibited\n", share)
			return
		}
		log.Errorln(err)
		return
	}
	folders := make([]smb.SharedFile, 0)

	// Filter out only folders and skip all INI files
	for _, item := range items {
		if item.IsDir && !item.IsJunction {
			folders = append(folders, item)
		}
	}

	/*
	   The SCCMContentLib\DataLib folder contains subfolders and INI files with the same name as the subfolders.
	   The INI files directly inside the DataLib folder are not relevant so have to skip those and dive directly
	   into the nested folders.
	*/
	// List files recursively in the subfolders of DataLib
	numFiles := 0
	numFolders := len(folders)
	for i, folder := range folders {
		err = listFilesRecursively(session, share, folder.FullPath, func(name string) error {
			if excludedExts != nil {
				fpath := strings.TrimSuffix(name, ".INI")
				extension := strings.ToUpper(path.Ext(fpath))
				if _, ok := excludedExts[extension]; ok {
					// Skip excluded file from adding to the inventory
					return nil
				}
			}
			err = callback(name)
			if err != nil {
				log.Errorln(err)
				return err
			}
			numFiles += 1
			fmt.Printf("\r%s\r", string(make([]byte, 80)))
			fmt.Printf("\rCollecting INI files in (%s), %d thus far, in folder (%d/%d) ", folder.FullPath, numFiles, i, numFolders)
			return nil
		})
		if err != nil {
			log.Errorf("Failed to list files in directory %s with error: %s\n", folder.FullPath, err)
			continue
		}
	}
	fmt.Println()

	return
}

var helpMsg = `
    Usage: ` + os.Args[0] + ` [options]

    options:
          --host                Hostname or ip address of remote server. Must be hostname when using Kerberos
      -P, --port                SMB Port (default 445)
      -d, --domain              Domain name to use for login
      -u, --user                Username
      -p, --pass                Password
      -n, --no-pass             Disable password prompt and send no credentials
          --hash                Hex encoded NT Hash for user password
          --local               Authenticate as a local user instead of domain user
          --null	            Attempt null session authentication
      -k, --kerberos            Use Kerberos authentication. (KRB5CCNAME will be checked on Linux)
          --dc-ip               Optionally specify ip of KDC when using Kerberos authentication
          --target-ip           Optionally specify ip of target when using Kerberos authentication
          --aes-key             Use a hex encoded AES128/256 key for Kerberos authentication
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
`

func main() {
	var host, username, password, hash, domain, shareFlag, includeName, includeExt, excludeExt, singleFile, socksIP, targetIP, dcIP, aesKey string
	var port, dialTimeout, socksPort, relayPort int
	var debug, noEnc, forceSMB2, localUser, nullSession, version, verbose, relay, noPass, kerberos bool
	var err error

	flag.Usage = func() {
		fmt.Println(helpMsg)
		os.Exit(0)
	}

	flag.StringVar(&host, "host", "", "")
	flag.StringVar(&username, "u", "", "")
	flag.StringVar(&username, "user", "", "")
	flag.StringVar(&password, "p", "", "")
	flag.StringVar(&password, "pass", "", "")
	flag.StringVar(&hash, "hash", "", "")
	flag.StringVar(&domain, "d", "", "")
	flag.StringVar(&domain, "domain", "", "")
	flag.IntVar(&port, "P", 445, "")
	flag.IntVar(&port, "port", 445, "")
	flag.BoolVar(&debug, "debug", false, "")
	flag.StringVar(&shareFlag, "share", "SCCMContentLib$", "")
	flag.StringVar(&includeName, "include-name", "", "")
	flag.StringVar(&includeExt, "include-exts", "ini,xml,config", "")
	flag.StringVar(&excludeExt, "exclude-exts", "", "")
	flag.Uint64Var(&fileSizeThreshold, "min-size", 0, "")
	flag.Uint64Var(&fileSizeLimit, "max-size", 0, "")
	flag.StringVar(&inventoryFile, "inventory", "sccmfiles.txt", "")
	flag.StringVar(&downloadDir, "download", "", "")
	flag.StringVar(&singleFile, "single-file", "", "")
	flag.BoolVar(&noEnc, "noenc", false, "")
	flag.BoolVar(&forceSMB2, "smb2", false, "")
	flag.BoolVar(&localUser, "local", false, "")
	flag.IntVar(&dialTimeout, "t", 5, "")
	flag.IntVar(&dialTimeout, "timeout", 5, "")
	flag.BoolVar(&nullSession, "null", false, "")
	flag.BoolVar(&version, "v", false, "")
	flag.BoolVar(&verbose, "verbose", false, "")
	flag.BoolVar(&version, "version", false, "")
	flag.BoolVar(&relay, "relay", false, "")
	flag.IntVar(&relayPort, "relay-port", 445, "")
	flag.StringVar(&socksIP, "socks-host", "", "")
	flag.IntVar(&socksPort, "socks-port", 1080, "")
	flag.BoolVar(&noPass, "no-pass", false, "")
	flag.BoolVar(&noPass, "n", false, "")
	flag.BoolVar(&kerberos, "k", false, "")
	flag.BoolVar(&kerberos, "kerberos", false, "")
	flag.StringVar(&targetIP, "target-ip", "", "")
	flag.StringVar(&dcIP, "dc-ip", "", "")
	flag.StringVar(&aesKey, "aes-key", "", "")

	flag.Parse()

	if debug {
		golog.Set("github.com/jfjallid/go-smb/smb", "smb", golog.LevelDebug, golog.LstdFlags|golog.Lshortfile, golog.DefaultOutput, golog.DefaultErrOutput)
		golog.Set("github.com/jfjallid/go-smb/spnego", "spnego", golog.LevelDebug, golog.LstdFlags|golog.Lshortfile, golog.DefaultOutput, golog.DefaultErrOutput)
		golog.Set("github.com/jfjallid/go-smb/gss", "gss", golog.LevelDebug, golog.LstdFlags|golog.Lshortfile, golog.DefaultOutput, golog.DefaultErrOutput)
		golog.Set("github.com/jfjallid/go-smb/krb5ssp", "krb5ssp", golog.LevelDebug, golog.LstdFlags|golog.Lshortfile, golog.DefaultOutput, golog.DefaultErrOutput)
		log.SetFlags(golog.LstdFlags | golog.Lshortfile)
		log.SetLogLevel(golog.LevelDebug)
	} else if verbose {
		golog.Set("github.com/jfjallid/go-smb/smb", "smb", golog.LevelInfo, golog.LstdFlags|golog.Lshortfile, golog.DefaultOutput, golog.DefaultErrOutput)
		golog.Set("github.com/jfjallid/go-smb/spnego", "spnego", golog.LevelInfo, golog.LstdFlags|golog.Lshortfile, golog.DefaultOutput, golog.DefaultErrOutput)
		golog.Set("github.com/jfjallid/go-smb/gss", "gss", golog.LevelInfo, golog.LstdFlags|golog.Lshortfile, golog.DefaultOutput, golog.DefaultErrOutput)
		golog.Set("github.com/jfjallid/go-smb/krb5ssp", "krb5ssp", golog.LevelInfo, golog.LstdFlags|golog.Lshortfile, golog.DefaultOutput, golog.DefaultErrOutput)
		log.SetLogLevel(golog.LevelInfo)
	} else {
		golog.Set("github.com/jfjallid/go-smb/smb", "smb", golog.LevelNotice, golog.LstdFlags|golog.Lshortfile, golog.DefaultOutput, golog.DefaultErrOutput)
		golog.Set("github.com/jfjallid/go-smb/spnego", "spnego", golog.LevelNotice, golog.LstdFlags|golog.Lshortfile, golog.DefaultOutput, golog.DefaultErrOutput)
		golog.Set("github.com/jfjallid/go-smb/gss", "gss", golog.LevelNotice, golog.LstdFlags|golog.Lshortfile, golog.DefaultOutput, golog.DefaultErrOutput)
		golog.Set("github.com/jfjallid/go-smb/krb5ssp", "krb5ssp", golog.LevelNotice, golog.LstdFlags|golog.Lshortfile, golog.DefaultOutput, golog.DefaultErrOutput)
	}

	if version {
		fmt.Printf("Version: %s\n", release)
		bi, ok := rundebug.ReadBuildInfo()
		if !ok {
			log.Errorln("Failed to read build info to locate version imported modules")
		}
		for _, m := range bi.Deps {
			fmt.Printf("Package: %s, Version: %s\n", m.Path, m.Version)
		}
		return
	}

	if isFlagSet("download") {
		download = true
		if downloadDir == "" {
			downloadDir = "."
		}
		if (inventoryFile == "") && (singleFile == "") {
			log.Errorln("--inventory <index file> or --single-file <path> is required when --download flag is set")
			flag.Usage()
			return
		}
	} else if singleFile != "" {
		// Allow single-file download without specifying a download dir
		download = true
		downloadDir = "."
	} else if inventoryFile == "" {
		log.Errorln("--inventory <index file> cannot be empty without specifying --single-file <path>")
		flag.Usage()
		return
	}

	if shareFlag == "" {
		log.Errorln("--share cannot be empty")
		flag.Usage()
		return
	}

	// Validate regexp if set
	if includeName != "" {
		nameRegexp, err = regexp.Compile(includeName)
		if err != nil {
			log.Errorln(err)
			flag.Usage()
			return
		}
	}

	if includeExt != "" && excludeExt != "" {
		if isFlagSet("include-exts") {
			log.Errorln("--include-ext and --exclude-ext are mutually exclusive, so don't supply both!")
			flag.Usage()
			return
		} else {
			log.Noticef("Clearing default --include-exts settings as --exlude-exts was specified")
			includeExt = ""
		}
	}

	if includeExt != "" {
		includedExts = make(map[string]interface{})
		exts := strings.Split(includeExt, ",")
		for _, e := range exts {
			includedExts["."+strings.ToUpper(strings.TrimPrefix(e, "."))] = nil
		}
	}

	if excludeExt != "" {
		excludedExts = make(map[string]interface{})
		exts := strings.Split(excludeExt, ",")
		for _, e := range exts {
			excludedExts["."+strings.ToUpper(strings.TrimPrefix(e, "."))] = nil
		}
	}

	var hashBytes []byte
	var aesKeyBytes []byte

	if host == "" && targetIP == "" {
		log.Errorln("Must specify a hostname or ip")
		flag.Usage()
		return
	}
	if host != "" && targetIP == "" {
		targetIP = host
	} else if host == "" && targetIP != "" {
		host = targetIP
	}

	if socksIP != "" && isFlagSet("timeout") {
		log.Errorln("When a socks proxy is specified, --timeout is not supported")
		flag.Usage()
		return
	}

	if dialTimeout < 1 {
		log.Errorln("Valid value for the timeout is > 0 seconds")
		return
	}

	if hash != "" {
		hashBytes, err = hex.DecodeString(hash)
		if err != nil {
			fmt.Println("Failed to decode hash")
			log.Errorln(err)
			return
		}
	}

	if aesKey != "" {
		aesKeyBytes, err = hex.DecodeString(aesKey)
		if err != nil {
			fmt.Println("Failed to decode aesKey")
			log.Errorln(err)
			return
		}
		if len(aesKeyBytes) != 16 && len(aesKeyBytes) != 32 {
			fmt.Println("Invalid keysize of AES Key")
			return
		}
	}

	if noPass {
		password = ""
		hashBytes = nil
		aesKeyBytes = nil
	} else {
		if (password == "") && (hashBytes == nil) && (aesKeyBytes == nil) {
			if (username != "") && (!nullSession) {
				// Check if password is already specified to be empty
				if !isFlagSet("P") && !isFlagSet("pass") {
					fmt.Printf("Enter password: ")
					passBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
					fmt.Println()
					if err != nil {
						log.Errorln(err)
						return
					}
					password = string(passBytes)
				}
			}
		}
	}

	hashRegexp, err = regexp.Compile("Hash[^=]*=([A-Z0-9]+)")
	if err != nil {
		log.Errorln(err)
		return
	}

	sizeRegexp, err = regexp.Compile("Size[^=]*=([A-Z0-9]+)")
	if err != nil {
		log.Errorln(err)
		return
	}

	options := smb.Options{
		Host:              targetIP,
		Port:              port,
		DisableEncryption: noEnc,
		ForceSMB2:         forceSMB2,
	}

	if kerberos {
		options.Initiator = &spnego.KRB5Initiator{
			User:     username,
			Password: password,
			Domain:   domain,
			Hash:     hashBytes,
			AESKey:   aesKeyBytes,
			SPN:      "cifs/" + host,
			DCIP:     dcIP,
		}
	} else {
		options.Initiator = &spnego.NTLMInitiator{
			User:        username,
			Password:    password,
			Hash:        hashBytes,
			Domain:      domain,
			LocalUser:   localUser,
			NullSession: nullSession,
		}
	}

	// Only if not using SOCKS
	if socksIP == "" {
		options.DialTimeout, err = time.ParseDuration(fmt.Sprintf("%ds", dialTimeout))
		if err != nil {
			log.Errorln(err)
			return
		}
	}

	var session *smb.Connection

	if socksIP != "" {
		dialSocksProxy, err := proxy.SOCKS5("tcp", fmt.Sprintf("%s:%d", socksIP, socksPort), nil, proxy.Direct)
		if err != nil {
			log.Errorln(err)
			return
		}
		options.ProxyDialer = dialSocksProxy
	}

	if relay {
		options.RelayPort = relayPort
		session, err = smb.NewRelayConnection(options)
	} else {
		session, err = smb.NewConnection(options)
	}
	if err != nil {
		log.Criticalln(err)
		return
	}

	defer session.Close()

	if session.IsSigningRequired() {
		log.Noticeln("[-] Signing is required")
	} else {
		log.Noticeln("[+] Signing is NOT required")
	}

	if session.IsAuthenticated() {
		log.Noticef("[+] Login successful as %s\n", session.GetAuthUsername())
	} else {
		log.Noticeln("[-] Login failed")
		return
	}

	if !download {
		// Check if inventory file can be created or if it already exists
		f, err := os.OpenFile(inventoryFile, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0644)
		if err != nil {
			if os.IsExist(err) {
				log.Errorln("Inventory file exists. Delete the file or specify another name if you want to recreate the inventory.")
				return
			}
			log.Errorln(err)
			return
		}
		defer f.Close()

		log.Noticeln("[+] Building inventory file")
		inventoryLineChan := make(chan string)
		go func() {
			err := writeInventoryLinesToFile(f, inventoryLineChan)
			if err != nil {
				log.Errorf("Failed to write to inventory file with error: %s\n", err)
				// Perhaps something less drastic?
				os.Exit(1)
			}
		}()

		// Build the index
		err = buildInventory(session, shareFlag, func(path string) error {
			name := fmt.Sprintf("\\\\%s\\%s\\%s\n", host, shareFlag, strings.TrimSuffix(path, ".INI"))
			inventoryLineChan <- name
			return nil
		})

		if err != nil {
			log.Errorln(err)
			return
		}

		log.Noticef("[+] Inventory written to file %s\n", inventoryFile)
	} else {
		// Create download directory
		err = os.Mkdir(downloadDir, 0755)
		if err != nil {
			if !os.IsExist(err) {
				log.Errorln(err)
				return
			}
		}

		if singleFile != "" {
			downloadFile(session, singleFile, true)
		} else {
			f, err := os.Open(inventoryFile)
			if err != nil {
				log.Errorln(err)
				return
			}
			defer f.Close()

			if includeExt != "" {
				log.Noticef("[+] Extensions to download: %s\n", includeExt)
			} else if excludeExt != "" {
				log.Noticef("[+] Extensions that won't be downloaded: %s\n", includeExt)
			}
			if fileSizeThreshold > 0 {
				log.Noticef("[+] Only downloading files with a size greater than %d bytes\n", fileSizeThreshold)
			}

			if fileSizeLimit > 0 {
				log.Noticef("[+] Only downloading files with a size less than %d bytes\n", fileSizeLimit)
			}

			scanner := bufio.NewScanner(f)
			scanner.Split(bufio.ScanLines)

			for scanner.Scan() {
				path := scanner.Text()
				downloadFile(session, path, false)
			}

			err = scanner.Err()
			if err != nil {
				log.Errorln(err)
				return
			}
		}
	}

	log.Noticef("Done")
}
