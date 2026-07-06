// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// Copyright (c) 2026 CrossCom Engineering (crosscom.ch)
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	hclog "github.com/hashicorp/go-hclog"
	"golang.org/x/sync/errgroup"

	"gitlab.com/Blockdaemon/go-tsm-sdkv2/v73/tsm"
	"gitlab.com/Blockdaemon/go-tsm-sdkv2/v73/tsm/tsmutils"
)

var version = "v0.1.1"
var logger hclog.Logger

type ClientConfig struct {
	URLs    []string
	APIKeys []string
	Cert    string
	Key     string
	PinKey  string
}

func initLogger(name string) {
	level := hclog.LevelFromString(os.Getenv("LOG_LEVEL"))
	if level == hclog.NoLevel {
		level = hclog.Info // default
	}
	logger = hclog.New(&hclog.LoggerOptions{
		Name:       name,
		Level:      level,
		JSONFormat: os.Getenv("LOG_FORMAT") == "json",
		Output:     os.Stderr,
	})
}

// keyIDPattern matches strings composed solely of ASCII letters, digits,
// underscores, and hyphens — the only characters permitted in a TSM key ID
// according to regex ^[A-Za-z0-9_-]+$ from validateKeyID() in tsm/util.go
var keyIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

// validateKeyID enforces the naming rules:
//   - length between 1 and 28 characters (inclusive)
//   - only ASCII a–z, A–Z, 0–9, '_', '-'
func validateKeyID(id string) error {
	switch {
	case len(id) == 0:
		return fmt.Errorf("key ID must not be empty")
	case len(id) > 28:
		return fmt.Errorf("key ID %q is %d characters; maximum is 28", id, len(id))
	case !keyIDPattern.MatchString(id):
		return fmt.Errorf("key ID %q contains invalid characters; "+
			"only ASCII letters, digits, '_', and '-' are allowed", id)
	}
	return nil
}

// parseKeyLength converts a bit count to the byte length expected by GenerateKey
// Allowed values: 128, 192, or 256 bit => 16m 24, or 32 byte
func parseKeyLength(bits int) (int, error) {
	switch bits {
	case 128:
		return 16, nil
	case 192:
		return 24, nil
	case 256:
		return 32, nil
	default:
		return 0, fmt.Errorf("unsupported key size %d: must be 128, 192, or 256", bits)
	}
}

func getClientConfig(nodesFlag, apiKeysFlag, certFlag, keyFlag, pinKeyFlag string) (*ClientConfig, error) {
	var urls []string
	var keys []string

	// If flags are explicitly set, use them
	if nodesFlag != "" {
		urls = strings.Split(nodesFlag, ",")
		for i := range urls {
			urls[i] = strings.TrimSpace(urls[i])
		}
		if apiKeysFlag != "" {
			keys = strings.Split(apiKeysFlag, ",")
			for i := range keys {
				keys[i] = strings.TrimSpace(keys[i])
			}
		}
	} else {
		// Otherwise, look at TSM_NODE<N>_URL env vars
		for i := 0; ; i++ {
			url := os.Getenv(fmt.Sprintf("TSM_NODE%d_URL", i))
			key := os.Getenv(fmt.Sprintf("TSM_NODE%d_APIKEY", i))
			if url == "" {
				break
			}
			urls = append(urls, strings.TrimSpace(url))
			keys = append(keys, strings.TrimSpace(key))
		}
	}

	// Fallback to Local TSM Deployment (or Hosted Sandbox) by default if empty
	if len(urls) == 0 {
		urls = []string{"http://localhost:8500", "http://localhost:8501", "http://localhost:8502"}
		keys = []string{"apikey0", "apikey1", "apikey2"}
		//urls = []string{"https://tsm-sandbox.prd.wallet.blockdaemon.app:8080",
		//		"https://tsm-sandbox.prd.wallet.blockdaemon.app:8081",
		//		"https://tsm-sandbox.prd.wallet.blockdaemon.app:8082"}
		// and set env vars MPCTSM_CLIENT_KEY_0, MPCTSM_CLIENT_KEY_1, MPCTSM_CLIENT_KEY_2
	}

	// Make sure keys array matches urls length
	for len(keys) < len(urls) {
		keys = append(keys, "")
	}
	return &ClientConfig{
		URLs:    urls,
		APIKeys: keys,
		Cert:    certFlag,
		Key:     keyFlag,
		PinKey:  pinKeyFlag,
	}, nil
}

func makeTSMConfiguration(url string, apiKey string, certPath, keyPath, pinKeyStr string) (*tsm.Configuration, error) {
	cfg := &tsm.Configuration{URL: url}

	if apiKey != "" {
		cfg = cfg.WithAPIKeyAuthentication(apiKey)
	}

	if certPath != "" && keyPath != "" {
		cfg = cfg.WithMTLSAuthentication(keyPath, certPath, nil)
	}

	if pinKeyStr != "" {
		var pemData []byte
		if _, err := os.Stat(pinKeyStr); err == nil {
			var errRead error
			pemData, errRead = os.ReadFile(pinKeyStr)
			if errRead != nil {
				return nil, fmt.Errorf("failed to read pinned public key file: %w", errRead)
			}
		} else {
			pemData = []byte(pinKeyStr)
		}

		block, _ := pem.Decode(pemData)
		if block == nil {
			return nil, fmt.Errorf("failed to decode PEM for pinned public key")
		}
		pk, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse PKIX public key: %w", err)
		}
		pkix, err := x509.MarshalPKIXPublicKey(pk)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal PKIX public key: %w", err)
		}
		cfg = cfg.WithPublicKeyPinning(pkix)
	}
	return cfg, nil
}

func connectClients(ctx context.Context, config *ClientConfig) ([]*tsm.Client, []int, error) {
	clients := make([]*tsm.Client, len(config.URLs))
	var playerIDs []int
	var mu sync.Mutex
	var wg sync.WaitGroup

	for i, url := range config.URLs {
		wg.Add(1)
		go func(idx int, nodeURL string) {
			defer wg.Done()
			cfg, err := makeTSMConfiguration(nodeURL, config.APIKeys[idx], config.Cert, config.Key, config.PinKey)
			if err != nil {
				logger.Debug("Failed to create TSM config", "node", idx, "url", nodeURL, "error", err)
				return
			}

			start := time.Now()
			client, err := tsm.NewClient(cfg)
			duration := time.Since(start)

			if err == nil {
				_, errVer := client.TSMVersion()
				if errVer == nil {
					mu.Lock()
					clients[idx] = client
					playerIDs = append(playerIDs, idx)
					mu.Unlock()
					logger.Debug("Connected to node", "node", idx, "RTT", duration.String())
					return
				}
				logger.Debug("Node connected but TSMVersion failed", "node", idx, "error", errVer)
			} else {
				logger.Debug("Failed to connect to node", "node", idx, "url", nodeURL, "error", err)
			}
		}(i, url)
	}
	wg.Wait()

	sort.Ints(playerIDs)
	return clients, playerIDs, nil
}

func nodesHoldingKey(ctx context.Context, clients []*tsm.Client, playerIDs []int, keyID string) ([]int, error) {
	type result struct {
		nodeIdx int
		found   bool
		err     error
	}

	results := make(chan result, len(playerIDs))
	for _, pID := range playerIDs {
		pID := pID
		go func() {
			ids, err := clients[pID].KeyManagement().ListKeys(ctx)
			if err != nil {
				results <- result{nodeIdx: pID, err: err}
				return
			}
			for _, id := range ids {
				if id == keyID {
					results <- result{nodeIdx: pID, found: true}
					return
				}
			}
			results <- result{nodeIdx: pID, found: false}
		}()
	}

	var holders []int
	var errs []string
	for range playerIDs {
		r := <-results
		if r.err != nil {
			errs = append(errs, fmt.Sprintf("node %d: %v", r.nodeIdx, r.err))
		} else if r.found {
			holders = append(holders, r.nodeIdx)
		}
	}

	if len(errs) > 0 {
		return holders, fmt.Errorf("ListKeys failed on %d node(s): %s", len(errs), strings.Join(errs, "; "))
	}
	return holders, nil
}

func confirmOverwrite(ctx context.Context, clients []*tsm.Client, playerIDs []int, keyID string, force bool) bool {
	if force {
		return true
	}
	fmt.Printf("Checking for existing key %q across %d node(s)...\n", keyID, len(playerIDs))

	holders, err := nodesHoldingKey(ctx, clients, playerIDs, keyID)
	sort.Ints(holders)
	if err != nil {
		fmt.Fprintf(os.Stderr, "WARNING: could not reliably check for existing key: %v\n", err)
	}

	if len(holders) == 0 {
		fmt.Printf("Key %q not found on any node — safe to proceed.\n\n", keyID)
		return true
	}

	fmt.Fprintf(os.Stderr, "\n WARNING: key %q already exists \n", keyID)
	fmt.Fprintf(os.Stderr, " Found on nodes: %v \n", holders)
	fmt.Fprintf(os.Stderr, " \n")
	fmt.Fprintf(os.Stderr, " Proceeding will PERMANENTLY OVERWRITE the existing key. \n")
	fmt.Fprintf(os.Stderr, " This action cannot be undone. \n")
	fmt.Fprintf(os.Stderr, " \n")
	fmt.Fprintf(os.Stderr, " Type \"yes\" to overwrite, or anything else to abort: ")

	scanner := bufio.NewScanner(os.Stdin)
	if !scanner.Scan() {
		fmt.Fprintln(os.Stderr, "\nAborted (no input).")
		return false
	}
	answer := strings.TrimSpace(scanner.Text())
	if answer != "yes" {
		fmt.Fprintln(os.Stderr, "Aborted.")
		return false
	}
	fmt.Fprintf(os.Stderr, "\n")
	return true
}

func confirmDelete(clients []*tsm.Client, playerIDs []int, keyID string, force bool) bool {
	if force {
		return true
	}
	logger.Debug("Checking for existing", "keyID", keyID, "on nodes", playerIDs)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	holders, err := nodesHoldingKey(ctx, clients, playerIDs, keyID)
	if err != nil {
		logger.Warn("Unable to reliably check for existing key", "err", err)
		return false
	}
	if len(holders) == 0 {
		logger.Info("No key shares found on any node, nothing to delete", "keyID", keyID)
		return false
	}

	fmt.Fprintf(os.Stderr, "\n WARNING: key shares with keyID %q exist \n", keyID)
	fmt.Fprintf(os.Stderr, " Found on nodes: %v \n", holders)
	fmt.Fprintf(os.Stderr, "\n Proceeding will PERMANENTLY DELETE these key shares. \n")
	fmt.Fprintf(os.Stderr, " This action cannot be undone. \n")
	fmt.Fprintf(os.Stderr, "\n Type \"yes\" to delete, or anything else to abort: ")

	scanner := bufio.NewScanner(os.Stdin)
	if !scanner.Scan() {
		fmt.Fprintln(os.Stderr, "\nAborted (no input).")
		return false
	}
	answer := strings.TrimSpace(scanner.Text())
	if answer != "yes" {
		fmt.Fprintln(os.Stderr, "Aborted.")
		return false
	}
	return true
}

func main() {
        initLogger("tsmtool")
        logger.Info("started", "version", version)
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	cmd := os.Args[1]
	switch cmd {
	case "probe":
		runProbe(os.Args[2:])
	case "generate":
		runGenerate(os.Args[2:])
	case "list":
		runList(os.Args[2:])
	case "delete":
		runDelete(os.Args[2:])
	case "encrypt":
		runEncrypt(os.Args[2:])
	case "decrypt":
		runDecrypt(os.Args[2:])
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", cmd)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("tsmtool: CLI tool for managing AES keys in TSM clusters")
	fmt.Println("Usage: tsmtool <command> [flags]")
	fmt.Println("\nCommands:")
	fmt.Println("  probe     Probes TSM services on specified nodes")
	fmt.Println("  generate  Generates a threshold-shared AES key")
	fmt.Println("  list      Lists key shares across the TSM nodes")
	fmt.Println("  delete    Deletes key shares for a specific key ID")
	fmt.Println("  encrypt   Encrypts a plaintext using a generated AES key")
	fmt.Println("  decrypt   Decrypts a ciphertext using a generated AES key")
	fmt.Println("\nUse 'tsmtool <command> -h' for command-specific flags.")
}

func runProbe(args []string) {
	fs := flag.NewFlagSet("probe", flag.ExitOnError)
	nodesFlag := fs.String("nodes", "", "Comma-separated TSM node URLs")
	apiKeysFlag := fs.String("apikeys", "", "Comma-separated TSM API keys")
	certFlag := fs.String("cert", "", "Path to client certificate (mTLS)")
	keyFlag := fs.String("key", "", "Path to client private key (mTLS)")
	pinKeyFlag := fs.String("pin-key", "", "Path to public key file for pinning or raw PEM")
	fs.Parse(args)

	initLogger("probe")
	logger.Info("started")

	cfg, err := getClientConfig(*nodesFlag, *apiKeysFlag, *certFlag, *keyFlag, *pinKeyFlag)
	if err != nil {
		logger.Error("failed to parse connection config: ", "error", err)
		os.Exit(1)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	clients, playerIDs, err := connectClients(ctx, cfg)
	if err != nil {
		logger.Error("failed to setup clients", "error", err)
		os.Exit(1)
	}

	if len(playerIDs) == 0 {
		logger.Error("No reachable TSM nodes found")
		os.Exit(1)
	}

	for _, idx := range playerIDs {
		client := clients[idx]
		nodeName := fmt.Sprintf("Node %d (%s)", idx, cfg.URLs[idx])
		probeNode(client, nodeName)
	}
}

func probeNode(c *tsm.Client, name string) {
	fmt.Printf("%s:\n", name)
	tsmVer, err := c.TSMVersion()
	if err == nil {
		fmt.Printf("Version Information:\n")
		fmt.Printf("  %-20s: %s\n", "SDK Release version", tsmVer.Version)
		fmt.Printf("  %-20s: %s\n", "Client API", tsmVer.ClientAPI)
		fmt.Printf("  %-20s: %s\n", "Client Communication", tsmVer.ClientCommunication)
		fmt.Printf("  %-20s: %s\n", "Node Communication", tsmVer.NodeCommunication)
		fmt.Printf("  %-20s: %s\n", "Node Configuration", tsmVer.NodeConfiguration)
	} else {
		fmt.Printf("Version Information: FAILED (%v)\n", err)
	}

	check := func(serviceName string, fn func()) {
		defer func() {
			if r := recover(); r != nil {
				fmt.Printf("  %-14s DISABLED (%v)\n", serviceName, r)
			}
		}()
		fn()
		fmt.Printf("  %-14s ENABLED\n", serviceName)
	}

	fmt.Printf("Services:\n")
	check("KeyManagement", func() { _ = c.KeyManagement() })
	check("WrappingKey", func() { _ = c.WrappingKey() })
	check("ECDSA", func() { _ = c.ECDSA() })
	check("Schnorr", func() { _ = c.Schnorr() })
	check("Broadcast", func() { _ = c.Broadcast() })
	check("AES", func() { _ = c.AES() })
	check("HMAC", func() { _ = c.HMAC() })
	check("RSA", func() { _ = c.RSA() })

	pi := *c.ProtocolInformation()
	fmt.Printf("client.ProtocolInformation(): \n")
	t := reflect.TypeOf(pi)
	v := reflect.ValueOf(pi)
	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		value := v.Field(i)
		fmt.Printf("  %-14s: %v\n", field.Name, value)
	}
	fmt.Println()
}

func runGenerate(args []string) {
	fs := flag.NewFlagSet("generate", flag.ExitOnError)
	bitsFlag := fs.Int("bits", 256, "AES key size in bits: 128, 192, or 256")
	keyIDFlag := fs.String("keyid", "", "Desired key ID: 1-28 chars, alphanumeric, '_' or '-'")
	nodesFlag := fs.String("nodes", "", "Comma-separated TSM node URLs")
	apiKeysFlag := fs.String("apikeys", "", "Comma-separated TSM API keys")
	certFlag := fs.String("cert", "", "Path to client certificate")
	keyFlag := fs.String("key", "", "Path to client private key")
	pinKeyFlag := fs.String("pin-key", "", "Path to pinned public key")
	thresholdFlag := fs.Int("threshold", 1, "Security threshold t")
	minPlayersFlag := fs.Int("minplayers", 2, "Minimum players")
	forceFlag := fs.Bool("force", false, "Force overwrite existing keys without prompt")
	fs.Parse(args)

	initLogger("generateKeys")
	logger.Info("started")

	if *keyIDFlag == "" {
		fmt.Fprintln(os.Stderr, "error: -keyid is required")
		fs.Usage()
		os.Exit(1)
	}

	if err := validateKeyID(*keyIDFlag); err != nil {
		logger.Error("invalid -keyid", "error", err)
		os.Exit(1)
	}

	keyLenBytes, err := parseKeyLength(*bitsFlag)
	if err != nil {
		logger.Error("invalid -bits", "error", err)
		os.Exit(1)
	}

	cfg, err := getClientConfig(*nodesFlag, *apiKeysFlag, *certFlag, *keyFlag, *pinKeyFlag)
	if err != nil {
		logger.Error("failed to parse connection config", "error", err)
		os.Exit(1)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	clients, playerIDs, err := connectClients(ctx, cfg)
	if err != nil {
		logger.Error("failed to setup clients", "error", err)
		os.Exit(1)
	}

	if len(playerIDs) != len(cfg.URLs) {
		logger.Error("Generation requires all TSM nodes to be online", "got", len(playerIDs), "of", len(cfg.URLs))
		os.Exit(1)
	}

	minPlayers := *minPlayersFlag
	if minPlayers == 0 {
		minPlayers = len(playerIDs)
	}

	threshold := *thresholdFlag
	if threshold < 1 || threshold >= minPlayers {
		logger.Error("threshold must satisfy 1 <= threshold < minPlayers got", "threshold", threshold, "minPlayers", minPlayers)
		os.Exit(1)
	}

	if !confirmOverwrite(ctx, clients, playerIDs, *keyIDFlag, *forceFlag) {
		os.Exit(1)
	}

	sessionID := tsm.GenerateSessionID()
	sessionCfg := tsm.NewSessionConfig(sessionID, playerIDs, nil, nil)

	fmt.Printf("AES key generation parameters:\n")
	fmt.Printf("  Key ID (desired) : %s\n", *keyIDFlag)
	fmt.Printf("  Key size         : %d bits (%d bytes)\n", *bitsFlag, keyLenBytes)
	fmt.Printf("  Players          : %v\n", playerIDs)
	fmt.Printf("  Min players      : %d\n", minPlayers)
	fmt.Printf("  Threshold        : %d\n", threshold)
	fmt.Printf("  Session ID       : %s\n", sessionID)
	fmt.Println()

	keyIDs := make([]string, len(playerIDs))
	eg, egCtx := errgroup.WithContext(ctx)

	for i, playerID := range playerIDs {
		i, playerID := i, playerID
		client := clients[playerID]
		eg.Go(func() error {
			keyID, err := client.AES().GenerateKey(
				egCtx,
				sessionCfg,
				minPlayers,
				threshold,
				keyLenBytes,
				*keyIDFlag,
			)
			if err != nil {
				return fmt.Errorf("node %d GenerateKey: %w", playerID, err)
			}
			keyIDs[i] = keyID
			return nil
		})
	}

	if err := eg.Wait(); err != nil {
		logger.Error("Validation of generated key shares failed", "error", err)
		os.Exit(1)
	}

	keyID := keyIDs[0]
	for i, kid := range keyIDs {
		if kid != keyID {
			logger.Error("node", playerIDs[i], "returned keyID", kid, "but node 0 returned", keyID)
			os.Exit(1)
		}
	}

	fmt.Printf("AES key generation succeeded!\n")
	fmt.Printf("  Assigned key ID  : %s\n", keyID)
	fmt.Printf("  Key size         : %d bits\n", *bitsFlag)
	fmt.Printf("  Key IDs per node : %v\n", keyIDs)
	logger.Info("done.")
}

func runList(args []string) {
	fs := flag.NewFlagSet("list", flag.ExitOnError)
	nodesFlag := fs.String("nodes", "", "Comma-separated TSM node URLs")
	apiKeysFlag := fs.String("apikeys", "", "Comma-separated TSM API keys")
	certFlag := fs.String("cert", "", "Path to client certificate")
	keyFlag := fs.String("key", "", "Path to client private key")
	pinKeyFlag := fs.String("pin-key", "", "Path to pinned public key")
	fs.Parse(args)

	initLogger("listKeys")
	logger.Info("started")

	cfg, err := getClientConfig(*nodesFlag, *apiKeysFlag, *certFlag, *keyFlag, *pinKeyFlag)
	if err != nil {
		logger.Error("failed to parse connection config", "error", err)
		os.Exit(1)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	clients, playerIDs, err := connectClients(ctx, cfg)
	if err != nil {
		logger.Error("failed to setup clients", "error", err)
		os.Exit(1)
	}

	if len(playerIDs) == 0 {
		logger.Error("no reachable TSM nodes found")
		os.Exit(1)
	}

	results := make([]nodeResult, len(cfg.URLs))
	for i := range results {
		results[i] = nodeResult{
			playerIndex: i,
			err:         fmt.Errorf("node offline/unavailable"),
		}
	}

	var wgList sync.WaitGroup
	for _, pID := range playerIDs {
		wgList.Add(1)
		go func(nodeIdx int, client *tsm.Client) {
			defer wgList.Done()
			ids, err := client.KeyManagement().ListKeys(ctx)
			results[nodeIdx] = nodeResult{playerIndex: nodeIdx, keyIDs: ids, err: err}
		}(pID, clients[pID])
	}
	wgList.Wait()

	freq := make(map[string]int)
	fmt.Println("=== Per-node key shares ===")
	for _, r := range results {
		if r.err != nil {
			fmt.Printf("  node %d: ERROR – %v\n", r.playerIndex, r.err)
			continue
		}
		sort.Strings(r.keyIDs)
		fmt.Printf("  node %d: %d key share(s)\n", r.playerIndex, len(r.keyIDs))
		for _, id := range r.keyIDs {
			fmt.Printf("    %s = %s\n", id, hex.EncodeToString([]byte(id)))
			freq[id]++
		}
	}

	reachable := len(playerIDs)
	var union, full []string
	for id, count := range freq {
		union = append(union, id)
		if count == reachable {
			full = append(full, id)
		}
	}
	sort.Strings(union)
	sort.Strings(full)

	fmt.Printf("\n=== Union across all nodes (%d unique key IDs) ===\n", len(union))
	if len(union) == 0 {
		fmt.Println("  (none)")
	}
	for _, id := range union {
		var attrStr string
		attr, err := getKeyAttributes(ctx, id, results, clients)
		if err == nil {
			attrStr = fmt.Sprintf("   %s, by: %s, at: %s, labeled: '%s'", attr.Algorithm, attr.Creator, attr.Created, attr.Label)
		} else {
			logger.Debug("GetKeyAttributes() failed", "keyID", id, "error", err)
		}
		fmt.Printf("  %s  [%d/%d nodes]%s\n", id, freq[id], reachable, attrStr)
	}

	fmt.Printf("\n=== Keys present on all %d reachable node(s) ===\n", reachable)
	if len(full) == 0 {
		fmt.Println("  (none)")
	}
	for _, id := range full {
		fmt.Println(" ", id)
	}
	logger.Info("done.")
}

type nodeResult struct {
	playerIndex int
	keyIDs      []string
	err         error
}

func getKeyAttributes(ctx context.Context, keyID string, results []nodeResult, clients []*tsm.Client) (*tsm.KeyAttributes, error) {
	for _, r := range results {
		if r.err == nil {
			for _, id := range r.keyIDs {
				if id == keyID {
					if clients[r.playerIndex] != nil {
						return clients[r.playerIndex].KeyManagement().GetKeyAttributes(ctx, keyID)
					}
				}
			}
		}
	}
	return nil, fmt.Errorf("no online node holds key %s", keyID)
}

func runDelete(args []string) {
	fs := flag.NewFlagSet("delete", flag.ExitOnError)
	keyIDFlag := fs.String("keyid", "", "Key ID to delete: 1-28 chars")
	thresholdFlag := fs.Int("threshold", 1, "Security threshold t")
	nodesFlag := fs.String("nodes", "", "Comma-separated TSM node URLs")
	apiKeysFlag := fs.String("apikeys", "", "Comma-separated TSM API keys")
	certFlag := fs.String("cert", "", "Path to client certificate")
	keyFlag := fs.String("key", "", "Path to client private key")
	pinKeyFlag := fs.String("pin-key", "", "Path to pinned public key")
	forceFlag := fs.Bool("force", false, "Force delete without prompting")
	fs.Parse(args)

	initLogger("deleteKeys")
	logger.Info("started")

	keyID := *keyIDFlag
	threshold := *thresholdFlag

	if keyID == "" {
		fmt.Fprintln(os.Stderr, "error: -keyid is required")
		fs.Usage()
		os.Exit(1)
	}

	if err := validateKeyID(keyID); err != nil {
		logger.Error("invalid -keyid", "error", err)
		os.Exit(1)
	}

	cfg, err := getClientConfig(*nodesFlag, *apiKeysFlag, *certFlag, *keyFlag, *pinKeyFlag)
	if err != nil {
		logger.Error("failed to parse connection config", "error", err)
		os.Exit(1)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	clients, playerIDs, err := connectClients(ctx, cfg)
	if err != nil {
		logger.Error("failed to setup clients", "error", err)
		os.Exit(1)
	}

	if len(playerIDs) == 0 {
		logger.Error("No reachable TSM nodes found")
		os.Exit(1)
	}

	if len(playerIDs) <= threshold {
		fmt.Fprintf(os.Stderr, "\n WARNING: A subset with %v of %v nodes in TSM cluster are reachable: %v only. \n",
			len(playerIDs), len(cfg.URLs), playerIDs)
		fmt.Fprintf(os.Stderr, " These are fewer nodes %v than the threshold+1 %v.\n", len(playerIDs), threshold+1)
		if !*forceFlag {
			fmt.Fprintf(os.Stderr, "\n Force to delete key shares on those nodes %v only? (yes/no): ", playerIDs)
			scanner := bufio.NewScanner(os.Stdin)
			if !scanner.Scan() || strings.TrimSpace(scanner.Text()) != "yes" {
				fmt.Fprintln(os.Stderr, "Aborted.")
				os.Exit(1)
			}
		}
	} else if len(playerIDs) < len(cfg.URLs) {
		if !*forceFlag {
			fmt.Fprintf(os.Stderr, "\n Continue and delete key shares on those nodes %v only? (yes/no): ", playerIDs)
			scanner := bufio.NewScanner(os.Stdin)
			if !scanner.Scan() || strings.TrimSpace(scanner.Text()) != "yes" {
				fmt.Fprintln(os.Stderr, "Aborted.")
				os.Exit(1)
			}
		}
	}

	if !confirmDelete(clients, playerIDs, keyID, *forceFlag) {
		logger.Error("Key not deleted", "keyID", keyID)
		os.Exit(1)
	}

	logger.Debug("Delete key shares on subset of nodes in parallel")
	var egDelete errgroup.Group
	startAll := time.Now()

	for _, pID := range playerIDs {
		pID := pID
		egDelete.Go(func() error {
			start := time.Now()
			err := clients[pID].KeyManagement().DeleteKeyShare(ctx, keyID)
			duration := time.Since(start)
			if err != nil {
				logger.Debug("failed to delete key share from", "node", pID, "RTT", duration.String(), "err", err)
				return fmt.Errorf("failed to delete key share from node %d: %w", pID, err)
			}
			logger.Debug("Deleted key share from", "node", pID, "RTT", duration.String())
			return nil
		})
	}

	durationAll := time.Since(startAll)
	if err := egDelete.Wait(); err != nil {
		logger.Error("Key share deletion partial only! ;-(", "RTT", durationAll, "error", err)
		os.Exit(1)
	} else {
		logger.Debug("Key shares deleted :-)", "keyID", keyID, "elapsed", durationAll.String())
		fmt.Printf("Key shares deleted successfully!\n")
	}
	logger.Info("done.")
}

var TheFox = "The quick brown fox jumps over the lazy dog's back 0123456789."
var AAD = []byte("some Additional Authenticated Data")

func runEncrypt(args []string) {
	fs := flag.NewFlagSet("encrypt", flag.ExitOnError)
	keyIDFlag := fs.String("keyid", "", "Key ID to use for encryption")
	//plaintextFlag := fs.String("plaintext", "", "Plaintext to encrypt")
	plaintextFlag := fs.String("plaintext", TheFox, "Plaintext to encrypt")
	nodesFlag := fs.String("nodes", "", "Comma-separated TSM node URLs")
	apiKeysFlag := fs.String("apikeys", "", "Comma-separated TSM API keys")
	certFlag := fs.String("cert", "", "Path to client certificate")
	keyFlag := fs.String("key", "", "Path to client private key")
	pinKeyFlag := fs.String("pin-key", "", "Path to pinned public key")
	thresholdFlag := fs.Int("threshold", 1, "Security threshold t")
	minPlayersFlag := fs.Int("minplayers", 2, "Minimum players required")
	fs.Parse(args)

	initLogger("encrypt")
	logger.Info("started")

	keyID := *keyIDFlag
	plaintext := *plaintextFlag
	threshold := *thresholdFlag
	minPlayers := *minPlayersFlag

	if keyID == "" || plaintext == "" {
		fmt.Fprintln(os.Stderr, "error: -keyid and -plaintext are required")
		fs.Usage()
		os.Exit(1)
	}
	logger.Debug("input", "plaintext", *plaintextFlag)

	cfg, err := getClientConfig(*nodesFlag, *apiKeysFlag, *certFlag, *keyFlag, *pinKeyFlag)
	if err != nil {
		logger.Error("failed to parse connection config", "error", err)
		os.Exit(1)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	clients, playerIDs, err := connectClients(ctx, cfg)
	if err != nil {
		logger.Error("failed to setup clients", "error", err)
		os.Exit(1)
	}

	if len(playerIDs) < minPlayers {
		logger.Error("not enough online nodes", "got", len(playerIDs), "need at least", minPlayers)
		os.Exit(1)
	}

	activePlayerIDs := playerIDs
	if len(activePlayerIDs) > minPlayers {
		//activePlayerIDs = activePlayerIDs[:minPlayers]	// TODO: verify
	}

	//plaintextShares, err := tsmutils.SplitInput(activePlayerIDs, minPlayers, threshold, []byte(plaintext))
	plaintextShares, err := tsmutils.SplitInput(activePlayerIDs, len(clients), threshold, []byte(plaintext))
	if err != nil {
		logger.Error("failed to split plaintext", "error", err)
		os.Exit(1)
	}

	iv := make([]byte, 12)
	if _, err := rand.Read(iv); err != nil {
		logger.Error("failed to generate random IV", "error", err)
		os.Exit(1)
	}

	aad := AAD
	sessionID := tsm.GenerateSessionID()
	sessionCfg := tsm.NewSessionConfig(sessionID, activePlayerIDs, nil, nil)

	startAll := time.Now()
	partialResults := make([][]byte, len(activePlayerIDs))
	var eg errgroup.Group

	for i, playerID := range activePlayerIDs {
		i, playerID := i, playerID
		client := clients[playerID]
		share := plaintextShares[i]
		eg.Go(func() error {
			start := time.Now()
			res, err := client.AES().GCMEncrypt(ctx, sessionCfg, keyID, iv, share, aad)
			duration := time.Since(start)
			if err != nil {
				logger.Debug("AES().GCMEncrypt()", "player", playerID, "RTT", duration.String(), "error", err)
				return fmt.Errorf("node %d AES().GCMEncrypt(): %w", playerID, err)
			}
			logger.Debug("AES().GCMEncrypt()", "player", playerID, "RTT", duration.String())
			partialResults[i] = res
			return nil
		})
	}

	if err := eg.Wait(); err != nil {
		logger.Error("AES().GCMEncrypt() failed", "error", err)
		os.Exit(1)
	}

	finalizeResult, err := tsm.AESFinalizeGCMEncrypt(partialResults)
	durationAll := time.Since(startAll)
	if err != nil {
		logger.Error("AESFinalizeGCMEncrypt() failed", "RTT", durationAll.String(), "error", err)
		os.Exit(1)
	} else {
		logger.Debug("AESFinalizeGCMEncrypt()", "RTT", durationAll.String())
	}

	fmt.Printf("Encryption successful!\n")
	fmt.Printf("  Ciphertext : %s\n", hex.EncodeToString(finalizeResult.Ciphertext))
	fmt.Printf("  IV         : %s\n", hex.EncodeToString(iv))
	fmt.Printf("  Tag        : %s\n", hex.EncodeToString(finalizeResult.Tag))
	logger.Info("done.")
}

func runDecrypt(args []string) {
	fs := flag.NewFlagSet("decrypt", flag.ExitOnError)
	keyIDFlag := fs.String("keyid", "", "Key ID to use for decryption")
	ciphertextFlag := fs.String("ciphertext", "", "Hex-encoded ciphertext")
	ivFlag := fs.String("iv", "", "Hex-encoded IV")
	tagFlag := fs.String("tag", "", "Hex-encoded Tag")
	nodesFlag := fs.String("nodes", "", "Comma-separated TSM node URLs")
	apiKeysFlag := fs.String("apikeys", "", "Comma-separated TSM API keys")
	certFlag := fs.String("cert", "", "Path to client certificate")
	keyFlag := fs.String("key", "", "Path to client private key")
	pinKeyFlag := fs.String("pin-key", "", "Path to pinned public key")
	minPlayersFlag := fs.Int("minplayers", 2, "Minimum players required (default 2)")
	fs.Parse(args)

	initLogger("decrypt")
	logger.Info("started")

	keyID := *keyIDFlag
	ciphertextHex := *ciphertextFlag
	ivHex := *ivFlag
	tagHex := *tagFlag
	minPlayers := *minPlayersFlag

	if keyID == "" || ciphertextHex == "" || ivHex == "" || tagHex == "" {
		fmt.Fprintln(os.Stderr, "error: -keyid, -ciphertext, -iv, and -tag are required")
		fs.Usage()
		os.Exit(1)
	}

	ciphertext, err := hex.DecodeString(ciphertextHex)
	if err != nil {
		logger.Error("invalid hex ciphertext", "error", err)
		os.Exit(1)
	}

	iv, err := hex.DecodeString(ivHex)
	if err != nil {
		logger.Error("invalid hex IV", "error", err)
		os.Exit(1)
	}

	tag, err := hex.DecodeString(tagHex)
	if err != nil {
		logger.Error("invalid hex tag", "error", err)
		os.Exit(1)
	}

	cfg, err := getClientConfig(*nodesFlag, *apiKeysFlag, *certFlag, *keyFlag, *pinKeyFlag)
	if err != nil {
		logger.Error("failed to parse connection config", "error", err)
		os.Exit(1)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	clients, playerIDs, err := connectClients(ctx, cfg)
	if err != nil {
		logger.Error("failed to setup clients", "error", err)
		os.Exit(1)
	}

	if len(playerIDs) < minPlayers {
		logger.Error("ot enough online nodes: ", "got", len(playerIDs), "need at least", minPlayers)
		os.Exit(1)
	}

	activePlayerIDs := playerIDs
	if len(activePlayerIDs) > minPlayers {
		//activePlayerIDs = activePlayerIDs[:minPlayers]	// TODO: verify
	}

	aad := AAD // must be identical to input of Encrypt, otherwise Decrypt detects mismatch!
	//aad[0] ^=  0x01		// optional: inject bit error => "message authentication failed"
	sessionID := tsm.GenerateSessionID()
	sessionCfg := tsm.NewSessionConfig(sessionID, activePlayerIDs, nil, nil)

	startAll := time.Now()
	partialResults := make([][]byte, len(activePlayerIDs))
	var eg errgroup.Group

	for i, playerID := range activePlayerIDs {
		i, playerID := i, playerID
		client := clients[playerID]
		eg.Go(func() error {
			start := time.Now()
			res, err := client.AES().GCMDecrypt(ctx, sessionCfg, keyID, iv, ciphertext, aad, tag)
			duration := time.Since(start)
			if err != nil {
				logger.Debug("AES().GCMDecrypt()", "player", playerID, "RTT", duration.String(), "error", err)
				return fmt.Errorf("node %d GCMDecrypt: %w", playerID, err)
			}
			logger.Debug("AES().GCMDecrypt()", "player", playerID, "RTT", duration.String())
			partialResults[i] = res
			return nil
		})
	}

	if err := eg.Wait(); err != nil {
		logger.Error("GCMDecrypt failed", "error", err)
		os.Exit(1)
	}

	decrypted, err := tsm.AESFinalizeGCMDecrypt(partialResults)
	durationAll := time.Since(startAll)
	if err != nil {
		logger.Error("AESFinalizeGCMDecrypt() failed", "RTT", durationAll.String(), "error", err)
		os.Exit(1)
	} else {
		logger.Debug("AESFinalizeGCMDecrypt()", "RTT", durationAll.String())
	}

	fmt.Printf("Decryption successful!\n")
	fmt.Printf("  Plaintext : %s\n", string(decrypted))
	logger.Info("done.")
}
