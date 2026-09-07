package cli

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"google.golang.org/grpc"

	"github.com/mevijays/goca/internal/csi"
	v1alpha1 "github.com/mevijays/goca/internal/csi/v1alpha1"
	"github.com/mevijays/goca/internal/service"
	"github.com/mevijays/goca/internal/web"
)

func newRunCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "run",
		Short: "Run a goca service in the foreground",
	}
	cmd.AddCommand(newRunWebCmd(), newRunCSIProviderCmd())
	return cmd
}

func newRunWebCmd() *cobra.Command {
	var (
		port    int
		listen  string
		tlsCert string
		tlsKey  string
	)
	cmd := &cobra.Command{
		Use:   "web",
		Short: "Serve the embedded web portal and REST API",
		Long: strings.TrimSpace(`
Serves the portal on the configured address, using the configuration written by
` + "`goca setup`" + `. Flags given here override the config file for this run only.`),
		Example: strings.TrimSpace(`
  goca run web
  goca run web --port=8080
  goca run web --listen=127.0.0.1 --port=9000
  goca run web --port=8443 --tls-cert=server.crt --tls-key=server.key`),
		RunE: func(cmd *cobra.Command, _ []string) error {
			a, err := open()
			if err != nil {
				return err
			}
			defer a.Close()

			srv, err := web.NewServer(a.svc, a.auth, a.log)
			if err != nil {
				return err
			}

			ctx, stop := signal.NotifyContext(context.Background(),
				os.Interrupt, syscall.SIGTERM)
			defer stop()

			return srv.Run(ctx, web.Options{
				Listen:  listen,
				Port:    port,
				TLSCert: tlsCert,
				TLSKey:  tlsKey,
				Logger:  a.log,
			})
		},
	}
	cmd.Flags().IntVar(&port, "port", 0, "port to listen on (overrides the config file)")
	cmd.Flags().StringVar(&listen, "listen", "", "address to bind (overrides the config file)")
	cmd.Flags().StringVar(&tlsCert, "tls-cert", "", "serve HTTPS with this certificate")
	cmd.Flags().StringVar(&tlsKey, "tls-key", "", "private key for --tls-cert")
	return cmd
}

// newRunCSIProviderCmd serves the Kubernetes Secrets Store CSI Driver
// provider side of the secret manager. Unlike every other `goca run`/CLI
// command, this one never calls open(): it holds no database or vault key
// material of its own and needs no config.yaml. See internal/csi's package
// doc for why - every Mount call is just relayed, over HTTPS with the
// requesting pod's own token, to a central goca server that does the actual
// authentication and decryption.
func newRunCSIProviderCmd() *cobra.Command {
	var (
		socketDir          string
		providerName       string
		audience           string
		authMethod         string
		gocaAddress        string
		caCertFile         string
		insecureSkipVerify bool
		timeout            time.Duration
	)
	cmd := &cobra.Command{
		Use:   "csi-provider",
		Short: "Serve the Kubernetes Secrets Store CSI Driver provider",
		Long: strings.TrimSpace(`
Runs the gRPC server the upstream secrets-store-csi-driver talks to over a
Unix domain socket - one instance per node, as a DaemonSet. It holds no
database or vault key material of its own: every Mount call forwards the
requesting pod's own bound ServiceAccount token to the central goca server
named by --goca-address (or a SecretProviderClass's own gocaAddress
parameter), which is the only place that authenticates the token, checks its
bindings, and decrypts anything - the same trust boundary that already
guards CA private keys and every other secret in goca.

See k8s-demo/csi for a working DaemonSet, CSIDriver, RBAC and
SecretProviderClass example, and docs/secrets.md for the full walkthrough.`),
		Example: strings.TrimSpace(`
  goca run csi-provider --goca-address https://goca.mylab.lan --audience goca-csi
  goca run csi-provider --audience goca-csi --ca-cert /var/run/secrets/goca-ca/ca.crt`),
		RunE: func(cmd *cobra.Command, _ []string) error {
			log := newLogger()

			tlsCfg := &tls.Config{}
			if insecureSkipVerify {
				tlsCfg.InsecureSkipVerify = true //nolint:gosec // opt-in, lab use only
			}
			if caCertFile != "" {
				pem, err := os.ReadFile(caCertFile)
				if err != nil {
					return fmt.Errorf("read --ca-cert: %w", err)
				}
				pool := x509.NewCertPool()
				if !pool.AppendCertsFromPEM(pem) {
					return fmt.Errorf("--ca-cert %s contains no certificates", caCertFile)
				}
				tlsCfg.RootCAs = pool
			}
			httpClient := &http.Client{
				Timeout:   timeout,
				Transport: &http.Transport{TLSClientConfig: tlsCfg},
			}

			provider := &csi.Provider{
				Audience:           audience,
				AuthMethod:         authMethod,
				DefaultGocaAddress: gocaAddress,
				HTTPClient:         httpClient,
				RuntimeVersion:     Version,
				Log:                log,
			}

			if err := os.MkdirAll(socketDir, 0o750); err != nil {
				return fmt.Errorf("create socket directory %s: %w", socketDir, err)
			}
			sockPath := filepath.Join(socketDir, providerName+".sock")
			// A previous crashed run can leave a stale socket file behind;
			// net.Listen refuses to bind over one.
			if err := os.Remove(sockPath); err != nil && !os.IsNotExist(err) {
				return fmt.Errorf("remove stale socket %s: %w", sockPath, err)
			}
			lis, err := net.Listen("unix", sockPath)
			if err != nil {
				return fmt.Errorf("listen on %s: %w", sockPath, err)
			}
			defer lis.Close()
			if err := os.Chmod(sockPath, 0o660); err != nil {
				return fmt.Errorf("chmod %s: %w", sockPath, err)
			}

			grpcServer := grpc.NewServer()
			v1alpha1.RegisterCSIDriverProviderServer(grpcServer, provider)

			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			go func() {
				<-ctx.Done()
				log.Info("shutting down", "socket", sockPath)
				grpcServer.GracefulStop()
			}()

			log.Info("goca csi provider listening", "socket", sockPath, "audience", audience, "auth_method", authMethod, "goca_address", gocaAddress)
			return grpcServer.Serve(lis)
		},
	}
	fl := cmd.Flags()
	fl.StringVar(&socketDir, "socket-dir", "/etc/kubernetes/secrets-store-csi-providers",
		"directory the driver looks for provider sockets in")
	fl.StringVar(&providerName, "provider-name", "goca", "this provider's name (must match ^[a-zA-Z0-9_-]{0,30}$)")
	fl.StringVar(&audience, "audience", "goca-csi",
		"token audience to request from pods and forward to the goca server (must match the CSIDriver's tokenRequests audience and the server's csi.audience)")
	fl.StringVar(&authMethod, "auth-method", "",
		"CSI trust domain (k8s auth method) this provider runs in - typically the cluster's name; sent as X-Goca-Auth-Method so the server scopes secret bindings to it (empty = default)")
	fl.StringVar(&gocaAddress, "goca-address", "",
		"default goca server URL, used when a SecretProviderClass omits its own gocaAddress parameter")
	fl.StringVar(&caCertFile, "ca-cert", "", "trust this CA when connecting to the goca server (PEM file)")
	fl.BoolVar(&insecureSkipVerify, "insecure-skip-verify", false,
		"skip TLS verification connecting to the goca server (lab use only)")
	fl.DurationVar(&timeout, "timeout", 10*time.Second, "HTTP timeout talking to the goca server")
	return cmd
}

func newInstallCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "install",
		Short: "Install goca as an operating system service",
	}
	cmd.AddCommand(newInstallWebCmd())
	return cmd
}

func newInstallWebCmd() *cobra.Command {
	var (
		port        int
		listen      string
		runAs       string
		binaryPath  string
		serviceName string
		userScope   bool
		now         bool
		printOnly   bool
		tlsCert     string
		tlsKey      string
	)
	cmd := &cobra.Command{
		Use:   "web",
		Short: "Install a systemd (Linux) or launchd (macOS) unit for the web portal",
		Long: strings.TrimSpace(`
Generates a service unit that runs this exact binary, from its current
location, as the user invoking the command (or --user), pointed at the config
file goca is using.

On Linux the unit is written to /etc/systemd/system/<name>.service, or to
~/.config/systemd/user/ with --user-scope. On macOS a launchd plist is written
to /Library/LaunchDaemons, or ~/Library/LaunchAgents with --user-scope.

Writing to a system location needs root, so run this under sudo. Use
--print to review the unit without writing anything.`),
		Example: strings.TrimSpace(`
  sudo goca install web --port=8080
  sudo goca install web --port=8080 --now
  goca install web --port=8080 --user-scope --now
  goca install web --port=8080 --print`),
		RunE: func(cmd *cobra.Command, _ []string) error {
			a, err := open()
			if err != nil {
				return err
			}
			defer a.Close()

			if port == 0 {
				port = a.cfg.Server.Port
			}

			args := []string{"run", "web", fmt.Sprintf("--port=%d", port)}
			if listen != "" {
				args = append(args, "--listen="+listen)
			}
			if a.cfg.Path != "" {
				args = append(args, "--config="+a.cfg.Path)
			}
			if tlsCert != "" {
				args = append(args, "--tls-cert="+tlsCert, "--tls-key="+tlsKey)
			}

			p := service.Params{
				Name:       serviceName,
				BinaryPath: binaryPath,
				ConfigPath: a.cfg.Path,
				Args:       args,
				User:       runAs,
				DataDir:    a.cfg.DataDir,
				Port:       port,
				UserScope:  userScope,
			}
			if err := p.Defaults(); err != nil {
				return err
			}

			manager, available := service.Detect()
			unit, err := p.Render()
			if err != nil {
				return err
			}

			if printOnly {
				fmt.Print(unit)
				return nil
			}

			section("Service installation")
			kv("manager", manager)
			kv("service name", p.Name)
			kv("binary", p.BinaryPath)
			kv("runs as user", p.User)
			kv("config", p.ConfigPath)
			kv("data directory", p.DataDir)
			kv("command", p.BinaryPath+" "+strings.Join(p.Args, " "))

			if !available {
				warn("%s does not appear to be available on this host", manager)
			}
			// Writing under /etc or /Library needs root; say so before failing.
			target, err := p.UnitPath()
			if err != nil {
				return err
			}
			if !userScope && os.Geteuid() != 0 && needsRoot(target) {
				return fmt.Errorf("writing %s requires root; re-run with sudo, "+
					"or use --user-scope to install into your own %s instance",
					target, manager)
			}

			path, err := p.Install()
			if err != nil {
				return err
			}
			ok("unit written to %s", path)

			if now {
				if err := p.Enable(); err != nil {
					warn("could not start the service automatically: %v", err)
					printCommands(p)
					return nil
				}
				ok("service enabled and started")
				host := listen
				if host == "" {
					host = a.cfg.Server.Listen
				}
				if host == "0.0.0.0" || host == "" || host == "::" {
					host = "localhost"
				}
				info("portal: http://%s:%d", host, port)
				return nil
			}
			printCommands(p)
			return nil
		},
	}

	fl := cmd.Flags()
	fl.IntVar(&port, "port", 0, "port the service listens on (default: the configured port)")
	fl.StringVar(&listen, "listen", "", "address the service binds to")
	fl.StringVar(&runAs, "user", "", "unix user to run as (default: the current user)")
	fl.StringVar(&binaryPath, "binary", "", "path to the goca binary (default: this executable)")
	fl.StringVar(&serviceName, "name", "goca-web", "service unit name")
	fl.BoolVar(&userScope, "user-scope", false, "install into the current user's service manager instead of the system one")
	fl.BoolVar(&now, "now", false, "reload the manager, then enable and start the service")
	fl.BoolVar(&printOnly, "print", false, "print the unit file instead of installing it")
	fl.StringVar(&tlsCert, "tls-cert", "", "serve HTTPS with this certificate")
	fl.StringVar(&tlsKey, "tls-key", "", "private key for --tls-cert")
	return cmd
}

func newUninstallCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "uninstall",
		Short: "Remove an installed goca service",
	}
	var (
		serviceName string
		userScope   bool
	)
	webCmd := &cobra.Command{
		Use:   "web",
		Short: "Stop and remove the web portal service unit",
		RunE: func(cmd *cobra.Command, _ []string) error {
			p := service.Params{Name: serviceName, UserScope: userScope}
			if err := p.Defaults(); err != nil {
				return err
			}
			target, err := p.UnitPath()
			if err != nil {
				return err
			}
			if !userScope && os.Geteuid() != 0 && needsRoot(target) {
				return fmt.Errorf("removing %s requires root; re-run with sudo", target)
			}
			path, err := p.Uninstall()
			if err != nil {
				return err
			}
			ok("removed %s", path)
			return nil
		},
	}
	webCmd.Flags().StringVar(&serviceName, "name", "goca-web", "service unit name")
	webCmd.Flags().BoolVar(&userScope, "user-scope", false, "remove from the current user's service manager")
	cmd.AddCommand(webCmd)
	return cmd
}

func printCommands(p service.Params) {
	cmds := p.Commands()
	if len(cmds) == 0 {
		return
	}
	fmt.Println()
	fmt.Println("  Finish with:")
	for _, c := range cmds {
		fmt.Println("    " + c)
	}
	fmt.Println()
	fmt.Println("  Or re-run this command with --now to do it automatically.")
}

// needsRoot reports whether writing to a path is likely to require root.
func needsRoot(path string) bool {
	if runtime.GOOS == "windows" {
		return false
	}
	dir := filepath.Dir(path)
	for _, prefix := range []string{"/etc", "/Library", "/usr", "/opt", "/var"} {
		if strings.HasPrefix(dir, prefix) {
			return true
		}
	}
	return false
}
