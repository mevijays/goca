package service

import (
	"strings"
	"testing"
)

func testParams() Params {
	return Params{
		Name:        "goca-web",
		Description: "goca certificate authority web portal",
		BinaryPath:  "/usr/local/bin/goca",
		ConfigPath:  "/etc/goca/config.yaml",
		Args:        []string{"run", "web", "--port=8080", "--config=/etc/goca/config.yaml"},
		User:        "goca",
		Group:       "goca",
		WorkingDir:  "/var/lib/goca",
		DataDir:     "/var/lib/goca",
		Port:        8080,
	}
}

func TestSystemdUnitContainsEssentials(t *testing.T) {
	unit := testParams().SystemdUnit()

	for _, want := range []string{
		"[Unit]",
		"[Service]",
		"[Install]",
		"User=goca",
		"Group=goca",
		"WorkingDirectory=/var/lib/goca",
		"Environment=GOCA_CONFIG=/etc/goca/config.yaml",
		"ExecStart=/usr/local/bin/goca run web --port=8080 --config=/etc/goca/config.yaml",
		"Restart=on-failure",
		"NoNewPrivileges=true",
		"ReadWritePaths=/var/lib/goca",
		"WantedBy=multi-user.target",
	} {
		if !strings.Contains(unit, want) {
			t.Errorf("systemd unit is missing %q\n---\n%s", want, unit)
		}
	}
	// A high port needs no capability grant.
	if strings.Contains(unit, "CAP_NET_BIND_SERVICE") {
		t.Error("port 8080 should not request CAP_NET_BIND_SERVICE")
	}
}

func TestSystemdUnitGrantsBindCapabilityForLowPorts(t *testing.T) {
	p := testParams()
	p.Port = 443
	unit := p.SystemdUnit()
	if !strings.Contains(unit, "AmbientCapabilities=CAP_NET_BIND_SERVICE") {
		t.Error("port 443 should request CAP_NET_BIND_SERVICE instead of running as root")
	}
}

func TestUserScopedUnitOmitsUserDirective(t *testing.T) {
	p := testParams()
	p.UserScope = true
	unit := p.SystemdUnit()
	if strings.Contains(unit, "\nUser=") {
		t.Error("a --user unit must not set User=, systemd rejects it")
	}
	if !strings.Contains(unit, "WantedBy=default.target") {
		t.Error("a --user unit should install into default.target")
	}
}

func TestLaunchdPlistIsWellFormed(t *testing.T) {
	plist := testParams().LaunchdPlist()
	for _, want := range []string{
		`<?xml version="1.0"`,
		"<key>Label</key>",
		"<string>com.goca.web</string>",
		"<string>/usr/local/bin/goca</string>",
		"<string>run</string>",
		"<string>web</string>",
		"<string>--port=8080</string>",
		"<key>RunAtLoad</key>",
		"<key>KeepAlive</key>",
		"</plist>",
	} {
		if !strings.Contains(plist, want) {
			t.Errorf("launchd plist is missing %q\n---\n%s", want, plist)
		}
	}
	if o, c := strings.Count(plist, "<dict>"), strings.Count(plist, "</dict>"); o != c {
		t.Errorf("unbalanced <dict> tags: %d open, %d close", o, c)
	}
	if o, c := strings.Count(plist, "<array>"), strings.Count(plist, "</array>"); o != c {
		t.Errorf("unbalanced <array> tags: %d open, %d close", o, c)
	}
}

// TestDefaultsUsesRunningBinary is what makes `goca install web` point the unit
// at this exact executable and the invoking user.
func TestDefaultsUsesRunningBinary(t *testing.T) {
	var p Params
	if err := p.Defaults(); err != nil {
		t.Fatalf("Defaults: %v", err)
	}
	if p.Name != "goca-web" {
		t.Errorf("default name is %q", p.Name)
	}
	if p.BinaryPath == "" || !strings.HasPrefix(p.BinaryPath, "/") {
		t.Errorf("binary path %q is not absolute", p.BinaryPath)
	}
	if p.User == "" {
		t.Error("no user was resolved")
	}
	if p.WorkingDir == "" {
		t.Error("no working directory was resolved")
	}
}

func TestUnitPathIsPlatformAppropriate(t *testing.T) {
	p := testParams()
	path, err := p.UnitPath()
	if err != nil {
		t.Skipf("service installation is unsupported here: %v", err)
	}
	if !strings.HasSuffix(path, ".service") && !strings.HasSuffix(path, ".plist") {
		t.Errorf("unexpected unit path %q", path)
	}
	if len(p.Commands()) == 0 {
		t.Error("no follow-up commands were suggested to the operator")
	}
}
