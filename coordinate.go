package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/term"

	flag "github.com/spf13/pflag"
)

// instance is the per-host (and per-worker) state carried through a run.
type instance struct {
	ID       int
	IP       string
	Username string
	Password string
	Script   string
	Hostname string
}

// ConfigEntry is one credential row in config.json, mirroring the Linux tool.
type ConfigEntry struct {
	IP       string
	Username string
	Password string
}

var (
	timeout time.Duration

	// brokenHosts and configEntries are appended to from many goroutines,
	// so they are guarded by their own mutexes (the Linux original raced here).
	brokenMu      sync.Mutex
	brokenHosts   []string
	configMu      sync.Mutex
	configEntries []ConfigEntry
)

var (
	port      = flag.IntP("port", "P", 5985, "WinRM port (5985 http / 5986 https)")
	threads   = flag.IntP("limit", "l", 3, "Concurrent scripts per host")
	timelimit = flag.IntP("timeout", "T", 60, "Time limit (seconds) per script")
	targets   = flag.StringP("targets", "t", "", "Target IPs (ex: 10.0.0.1-10.0.0.5,192.168.1.0/24)")
	usernames = flag.StringP("usernames", "u", "", "Comma-separated usernames (use DOMAIN\\\\user or user@domain for AD)")
	passwords = flag.StringP("passwords", "p", "", "Comma-separated passwords")
	callbacks = flag.StringP("callbacks", "c", "", "Callback IP address(es) for #CALLBACK_IP substitution")
	outdir    = flag.StringP("outdir", "o", "", "Directory to save per-host output. If empty, output is not saved.")
	environ   = flag.StringP("env", "E", "", "PowerShell statements to run before each script (semicolon-separated)")
	https     = flag.BoolP("https", "s", false, "Use HTTPS (port 5986) instead of HTTP")
	insecure  = flag.BoolP("insecure", "k", true, "Skip TLS certificate verification (HTTPS only)")
	basicAuth = flag.BoolP("basic", "b", false, "Use HTTP Basic auth instead of NTLM/Negotiate (requires AllowUnencrypted on target)")
	quiet     = flag.BoolP("quiet", "q", false, "Print only script output")
	debug     = flag.BoolP("debug", "d", false, "Print debug messages")
	yes       = flag.BoolP("yes", "y", false, "Skip the confirmation prompt")
	errs      = flag.BoolP("errors", "e", false, "Print errors only (no stdout)")

	createConfig = flag.BoolP("create-config", "C", false, "Build config.json from script output lines of the form user,password")
	useConfig    = flag.BoolP("use-config", "U", false, "Use per-host credentials from config.json instead of -u/-p")

	callbackIPs  = []string{}
	scripts      = []string{}
	usernameList = []string{}
	passwordList = []string{}
	environCmds  = []string{}
	addresses    = []string{}
)

func main() {
	InitLogger()
	flag.Parse()

	timeout = time.Duration(*timelimit) * time.Second
	if *https && !flag.CommandLine.Changed("port") {
		*port = 5986
	}

	scripts = flag.Args()

	if len(scripts) == 0 || ((*usernames == "" || *targets == "") && !*useConfig) {
		Err("Missing target(s), script(s), and/or username(s).")
		fmt.Println("Usage:\n  coordinate [flags] script1.ps1 [script2.ps1 ...]")
		flag.PrintDefaults()
		return
	}

	if *environ != "" {
		environCmds = strings.Split(*environ, ";")
	}
	if *callbacks != "" {
		callbackIPs = strings.Split(*callbacks, ",")
	}

	if *outdir != "" {
		if err := os.MkdirAll(*outdir, 0700); err != nil {
			Fatal("Could not create output directory:", err)
		}
	}

	if !*useConfig {
		var err error
		addresses, err = expandTargets(*targets)
		if err != nil {
			Fatal(err)
		}
		if len(addresses) == 0 {
			Fatal("No target addresses parsed.")
		}

		usernameList = strings.Split(*usernames, ",")
		if *passwords == "" {
			fmt.Print("Password: ")
			pw, err := term.ReadPassword(int(syscall.Stdin))
			if err != nil {
				Fatal(err)
			}
			passwordList = []string{strings.TrimSpace(string(pw))}
			fmt.Println()
		} else {
			passwordList = strings.Split(*passwords, ",")
		}
	}

	if !*quiet {
		if !*useConfig {
			fmt.Printf("Specified targets (%d addresses):\n\t%s\n", len(addresses), strings.Join(addresses, "\n\t"))
		}
		fmt.Printf("Specified scripts (%d files):\n\t%s\n", len(scripts), strings.Join(scripts, "\n\t"))
		if len(environCmds) != 0 {
			fmt.Printf("Specified environmental commands (%d items):\n\t%s\n", len(environCmds), strings.Join(environCmds, "\n\t"))
		}
	}

	if !*yes {
		reader := bufio.NewReader(os.Stdin)
		fmt.Printf("Use The Coordinate? [y/n]: ")
		response, err := reader.ReadString('\n')
		if err != nil {
			Fatal(err)
		}
		response = strings.ToLower(strings.TrimSpace(response))
		if response != "y" && response != "yes" {
			os.Exit(1)
		}
	}

	var wg sync.WaitGroup
	if !*useConfig {
		for _, ip := range addresses {
			wg.Add(1)
			go runner(ip, &wg)
		}
	} else {
		entries, err := readConfig()
		if err != nil {
			Fatal(err)
		}
		if len(entries) == 0 {
			Fatal("config.json has no entries.")
		}
		for _, e := range entries {
			wg.Add(1)
			go geraldRunner(e.IP, e.Username, e.Password, &wg)
		}
	}
	wg.Wait()

	brokenMu.Lock()
	if len(brokenHosts) > 0 {
		Err("The following hosts had WinRM trouble and should be checked manually:")
		for _, host := range brokenHosts {
			fmt.Println("\t" + host)
		}
	}
	brokenMu.Unlock()

	if *createConfig {
		writeConfig()
	}
}

// expandTargets parses comma-separated single IPs, A-B ranges, and CIDR
// prefixes into a flat list of address strings, using the standard-library
// net/netip (the Linux tool used the now-archived inet.af/netaddr).
func expandTargets(spec string) ([]string, error) {
	var out []string
	for _, tok := range strings.Split(spec, ",") {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		switch {
		case strings.Contains(tok, "/"):
			prefix, err := netip.ParsePrefix(tok)
			if err != nil {
				return nil, fmt.Errorf("bad CIDR %q: %w", tok, err)
			}
			for addr := prefix.Masked().Addr(); prefix.Contains(addr); addr = addr.Next() {
				out = append(out, addr.String())
			}
		case strings.Contains(tok, "-"):
			parts := strings.SplitN(tok, "-", 2)
			start, err := netip.ParseAddr(strings.TrimSpace(parts[0]))
			if err != nil {
				return nil, fmt.Errorf("bad range start %q: %w", parts[0], err)
			}
			end, err := netip.ParseAddr(strings.TrimSpace(parts[1]))
			if err != nil {
				return nil, fmt.Errorf("bad range end %q: %w", parts[1], err)
			}
			for addr := start; addr.Compare(end) <= 0; addr = addr.Next() {
				out = append(out, addr.String())
				if !addr.IsValid() {
					break
				}
			}
		default:
			addr, err := netip.ParseAddr(tok)
			if err != nil {
				return nil, fmt.Errorf("bad IP %q: %w", tok, err)
			}
			out = append(out, addr.String())
		}
	}
	return out, nil
}

func readConfig() ([]ConfigEntry, error) {
	raw, err := os.ReadFile("config.json")
	if err != nil {
		return nil, fmt.Errorf("reading config.json: %w", err)
	}
	var entries []ConfigEntry
	if err := json.Unmarshal(raw, &entries); err != nil {
		return nil, fmt.Errorf("parsing config.json: %w", err)
	}
	return entries, nil
}

func writeConfig() {
	configMu.Lock()
	defer configMu.Unlock()
	if len(configEntries) == 0 {
		Err("No config entries collected. Not writing config.json.")
		return
	}
	data, err := json.MarshalIndent(configEntries, "", "  ")
	if err != nil {
		Err("Error marshaling config.json:", err)
		return
	}
	if err := os.WriteFile("config.json", data, 0600); err != nil {
		Err("Error writing config.json:", err)
		return
	}
	Info(fmt.Sprintf("Wrote %d entries to config.json", len(configEntries)))
}
