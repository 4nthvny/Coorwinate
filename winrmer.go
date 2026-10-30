package main

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/masterzen/winrm"
)

// bootstrap reads the full script off stdin and runs it. Sending the script
// over stdin instead of on the command line avoids the ~8191-char command
// length limit and keeps quoting sane. $ProgressPreference is silenced so
// progress bars don't pollute stderr.
const bootstrap = `$ProgressPreference='SilentlyContinue';` +
	`$code=[Console]::In.ReadToEnd();Invoke-Expression $code`

// isPortOpen mirrors the Linux tool's dead-host check, against the WinRM port.
func isPortOpen(host string, port int) bool {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, fmt.Sprint(port)), 1500*time.Millisecond)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// newClient builds a WinRM client for a host/credential pair. NTLM message
// encryption is used by default so the payload is protected even over plain
// HTTP (Windows refuses unencrypted WinRM unless AllowUnencrypted is set).
// -b/--basic switches to HTTP Basic, which needs AllowUnencrypted or HTTPS.
func newClient(i instance) (*winrm.Client, error) {
	endpoint := winrm.NewEndpoint(i.IP, *port, *https, *insecure, nil, nil, nil, timeout)
	params := winrm.NewParameters(fmt.Sprintf("PT%dS", *timelimit), "en-US", 153600)
	if !*basicAuth {
		params.TransportDecorator = func() winrm.Transporter {
			enc, err := winrm.NewEncryption("ntlm")
			if err != nil {
				// Fall back to the default transport; Post will surface the error.
				return &winrm.ClientNTLM{}
			}
			return enc
		}
	}
	return winrm.NewClientWithParameters(endpoint, i.Username, i.Password, params)
}

// testAuth runs a trivial command to confirm the credentials work.
func testAuth(client *winrm.Client, i instance) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	_, stderr, code, err := client.RunPSWithContextWithString(ctx, "whoami", "")
	if err != nil {
		return err
	}
	if code != 0 {
		return fmt.Errorf("auth probe exited %d: %s", code, strings.TrimSpace(stderr))
	}
	return nil
}

// runner tries each username/password combination against a host and, on the
// first success, deploys the scripts.
func runner(ip string, w *sync.WaitGroup) {
	defer w.Done()

	i := instance{IP: ip}
	if !isPortOpen(ip, *port) {
		Debug(fmt.Sprintf("WinRM port %d is closed on %s", *port, ip))
		return
	}

	var client *winrm.Client
	found := false
	for _, u := range usernameList {
		for _, p := range passwordList {
			i.Username, i.Password = u, p
			c, err := newClient(i)
			if err != nil {
				Debug(fmt.Sprintf("client build failed for %s: %s", ip, err))
				continue
			}
			if err := testAuth(c, i); err != nil {
				if *debug {
					InfoExtra(i, "Login failed:", err)
				}
				continue
			}
			client, found = c, true
			InfoExtra(i, "Valid credentials for", i.Username)
			break
		}
		if found {
			break
		}
	}

	if !found {
		ErrExtra(i, "Login attempts failed!")
		return
	}
	deploy(client, i)
}

// geraldRunner deploys using a single known credential pair (config.json flow).
func geraldRunner(ip, username, password string, w *sync.WaitGroup) {
	defer w.Done()

	i := instance{IP: ip, Username: username, Password: password}
	if !isPortOpen(ip, *port) {
		Debug(fmt.Sprintf("WinRM port %d is closed on %s", *port, ip))
		return
	}
	client, err := newClient(i)
	if err != nil {
		ErrExtra(i, "Client build failed:", err)
		return
	}
	if err := testAuth(client, i); err != nil {
		ErrExtra(i, "Login attempts failed!", err)
		return
	}
	InfoExtra(i, "Valid credentials for", i.Username)
	deploy(client, i)
}

// deploy resolves the hostname and fans the script list out across a worker
// pool bounded by -l (concurrent scripts per host).
func deploy(client *winrm.Client, i instance) {
	i.Hostname = resolveHostname(client, i)

	scriptChan := make(chan string)
	var wg sync.WaitGroup

	n := *threads
	if n > len(scripts) {
		n = len(scripts)
	}
	for t := 0; t < n; t++ {
		wg.Add(1)
		worker := i
		worker.ID = t
		go func(w instance) {
			defer wg.Done()
			for script := range scriptChan {
				w.Script = script
				runScript(client, w)
			}
		}(worker)
	}

	for _, s := range scripts {
		scriptChan <- s
	}
	close(scriptChan)
	wg.Wait()
}

func resolveHostname(client *winrm.Client, i instance) string {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	out, _, code, err := client.RunPSWithContextWithString(ctx, "$env:COMPUTERNAME", "")
	if err != nil || code != 0 {
		return i.IP
	}
	name := strings.TrimSpace(out)
	if name == "" {
		return i.IP
	}
	return name
}

// runScript reads a script file, applies substitutions, and executes it on the
// remote host over a fresh WinRM shell, reporting stdout/stderr and exit code.
func runScript(client *winrm.Client, i instance) {
	raw, err := os.ReadFile(i.Script)
	if err != nil {
		Crit(i, "Error opening "+i.Script+":", err)
		return
	}

	body := string(raw)
	if len(callbackIPs) > 0 && strings.Contains(body, "#CALLBACK_IP") {
		cb := callbackIPs[rand.Intn(len(callbackIPs))]
		body = strings.ReplaceAll(body, "#CALLBACK_IP", cb)
	}
	if len(environCmds) > 0 {
		body = strings.Join(environCmds, "\n") + "\n" + body
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	stdout, stderr, code, err := client.RunPSWithContextWithString(ctx, bootstrap, body)
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			Crit(i, "Script timed out after", timeout)
		} else {
			Crit(i, "Execution error:", err)
		}
		return
	}

	stdout = strings.TrimSpace(stdout)
	stderr = strings.TrimSpace(stderr)

	if !*errs && stdout != "" {
		Stdout(i, stdout)
		if *createConfig {
			collectConfig(i, stdout)
		}
	}
	if stderr != "" {
		Stderr(i, stderr)
	}
	if code != 0 {
		Crit(i, fmt.Sprintf("Script exited with code %d", code))
	} else {
		InfoExtra(i, "Finished running script!")
	}

	if *outdir != "" && stdout != "" {
		saveOutput(i, stdout)
	}
}

// saveOutput appends each script's output to <outdir>/<hostname>.<script>.txt.
// The Linux tool truncated on every write, losing all but the last script;
// here each script gets its own file and we append.
func saveOutput(i instance, content string) {
	base := fmt.Sprintf("%s.%s.txt", i.Hostname, filepath.Base(i.Script))
	path := filepath.Join(*outdir, base)
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		Crit(i, "Could not open output file:", err)
		return
	}
	defer f.Close()
	fmt.Fprintln(f, content)
}

// collectConfig parses "user,password" lines (e.g. from a password-rotation
// script) into config entries for -C, matching the Linux tool's behavior.
func collectConfig(i instance, out string) {
	for _, line := range strings.Split(out, "\n") {
		parts := strings.SplitN(strings.TrimSpace(line), ",", 2)
		if len(parts) == 2 && parts[0] == i.Username {
			configMu.Lock()
			configEntries = append(configEntries, ConfigEntry{IP: i.IP, Username: i.Username, Password: parts[1]})
			configMu.Unlock()
		}
	}
}
