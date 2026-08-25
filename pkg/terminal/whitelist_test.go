/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package terminal

import (
	"errors"
	"testing"
)

func TestValidateCommand(t *testing.T) {
	tests := []struct {
		name        string
		cmd         *ParsedCommand
		wantErr     bool
		expectedErr error
	}{
		{
			name: "valid kubectl get",
			cmd: &ParsedCommand{
				Command:      "kubectl",
				Subcommand:   "get",
				Args:         []string{"pods"},
				Flags:        map[string]string{},
				BooleanFlags: []string{},
			},
			wantErr:     false,
			expectedErr: nil,
		},
		{
			name: "valid oc get",
			cmd: &ParsedCommand{
				Command:      "oc",
				Subcommand:   "get",
				Args:         []string{"routes"},
				Flags:        map[string]string{},
				BooleanFlags: []string{},
			},
			wantErr:     false,
			expectedErr: nil,
		},
		{
			name: "valid kubectl describe",
			cmd: &ParsedCommand{
				Command:      "kubectl",
				Subcommand:   "describe",
				Args:         []string{"pod", "nginx"},
				Flags:        map[string]string{"namespace": "default"},
				BooleanFlags: []string{},
			},
			wantErr:     false,
			expectedErr: nil,
		},
		{
			name: "valid kubectl logs",
			cmd: &ParsedCommand{
				Command:      "kubectl",
				Subcommand:   "logs",
				Args:         []string{"nginx"},
				Flags:        map[string]string{"tail": "100"},
				BooleanFlags: []string{"timestamps"},
			},
			wantErr:     false,
			expectedErr: nil,
		},
		{
			name: "valid kubectl top",
			cmd: &ParsedCommand{
				Command:      "kubectl",
				Subcommand:   "top",
				Args:         []string{"nodes"},
				Flags:        map[string]string{},
				BooleanFlags: []string{},
			},
			wantErr:     false,
			expectedErr: nil,
		},
		{
			name: "valid kubectl explain",
			cmd: &ParsedCommand{
				Command:      "kubectl",
				Subcommand:   "explain",
				Args:         []string{"pods"},
				Flags:        map[string]string{},
				BooleanFlags: []string{},
			},
			wantErr:     false,
			expectedErr: nil,
		},
		{
			name: "valid kubectl version",
			cmd: &ParsedCommand{
				Command:      "kubectl",
				Subcommand:   "version",
				Args:         []string{},
				Flags:        map[string]string{},
				BooleanFlags: []string{},
			},
			wantErr:     false,
			expectedErr: nil,
		},
		{
			name: "invalid command - not kubectl or oc",
			cmd: &ParsedCommand{
				Command:      "bash",
				Subcommand:   "get",
				Args:         []string{},
				Flags:        map[string]string{},
				BooleanFlags: []string{},
			},
			wantErr:     true,
			expectedErr: ErrCommandNotFound,
		},
		{
			name: "invalid subcommand - write operation",
			cmd: &ParsedCommand{
				Command:      "kubectl",
				Subcommand:   "delete",
				Args:         []string{"pod", "nginx"},
				Flags:        map[string]string{},
				BooleanFlags: []string{},
			},
			wantErr:     true,
			expectedErr: ErrCommandNotPermitted,
		},
		{
			name: "invalid subcommand - apply",
			cmd: &ParsedCommand{
				Command:      "kubectl",
				Subcommand:   "apply",
				Args:         []string{},
				Flags:        map[string]string{"filename": "deploy.yaml"},
				BooleanFlags: []string{},
			},
			wantErr:     true,
			expectedErr: ErrCommandNotPermitted,
		},
		{
			name: "invalid subcommand - create",
			cmd: &ParsedCommand{
				Command:      "kubectl",
				Subcommand:   "create",
				Args:         []string{},
				Flags:        map[string]string{},
				BooleanFlags: []string{},
			},
			wantErr:     true,
			expectedErr: ErrCommandNotPermitted,
		},
		{
			name: "blocked flag - watch",
			cmd: &ParsedCommand{
				Command:      "kubectl",
				Subcommand:   "get",
				Args:         []string{"pods"},
				Flags:        map[string]string{},
				BooleanFlags: []string{"watch"},
			},
			wantErr:     true,
			expectedErr: ErrCommandNotPermitted,
		},
		{
			name: "blocked flag - w (short)",
			cmd: &ParsedCommand{
				Command:      "kubectl",
				Subcommand:   "get",
				Args:         []string{"pods"},
				Flags:        map[string]string{},
				BooleanFlags: []string{"w"},
			},
			wantErr:     true,
			expectedErr: ErrCommandNotPermitted,
		},
		{
			name: "blocked flag - follow",
			cmd: &ParsedCommand{
				Command:      "kubectl",
				Subcommand:   "logs",
				Args:         []string{"nginx"},
				Flags:        map[string]string{},
				BooleanFlags: []string{"follow"},
			},
			wantErr:     true,
			expectedErr: ErrCommandNotPermitted,
		},
		{
			name: "blocked flag - f (short)",
			cmd: &ParsedCommand{
				Command:      "kubectl",
				Subcommand:   "logs",
				Args:         []string{"nginx"},
				Flags:        map[string]string{},
				BooleanFlags: []string{"f"},
			},
			wantErr:     true,
			expectedErr: ErrCommandNotPermitted,
		},
		{
			name: "blocked flag - watch with value",
			cmd: &ParsedCommand{
				Command:      "kubectl",
				Subcommand:   "get",
				Args:         []string{"pods"},
				Flags:        map[string]string{"watch": "true"},
				BooleanFlags: []string{},
			},
			wantErr:     true,
			expectedErr: ErrCommandNotPermitted,
		},
		{
			name: "blocked flag - watch-only",
			cmd: &ParsedCommand{
				Command:      "kubectl",
				Subcommand:   "get",
				Args:         []string{"pods"},
				Flags:        map[string]string{},
				BooleanFlags: []string{"watch-only"},
			},
			wantErr:     true,
			expectedErr: ErrCommandNotPermitted,
		},
		{
			name: "valid command with allowed flags",
			cmd: &ParsedCommand{
				Command:      "kubectl",
				Subcommand:   "get",
				Args:         []string{"pods"},
				Flags:        map[string]string{"namespace": "default", "output": "yaml"},
				BooleanFlags: []string{"show-labels", "all-namespaces"},
			},
			wantErr:     false,
			expectedErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateCommand(tt.cmd)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateCommand() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr && !errors.Is(err, tt.expectedErr) {
				t.Errorf("ValidateCommand() error = %v, want %v", err, tt.expectedErr)
			}
		})
	}
}

func TestIsStreamingFlag(t *testing.T) {
	tests := []struct {
		name     string
		flagName string
		want     bool
	}{
		{"watch flag", "watch", true},
		{"w flag", "w", true},
		{"follow flag", "follow", true},
		{"f flag", "f", true},
		{"watch-only flag", "watch-only", true},
		{"namespace flag", "namespace", false},
		{"output flag", "output", false},
		{"all-namespaces flag", "all-namespaces", false},
		{"show-labels flag", "show-labels", false},
		{"with dashes", "--watch", true},
		{"with single dash", "-w", true},
		{"uppercase", "WATCH", true},
		{"mixed case", "Follow", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsStreamingFlag(tt.flagName); got != tt.want {
				t.Errorf("IsStreamingFlag(%q) = %v, want %v", tt.flagName, got, tt.want)
			}
		})
	}
}

// TestValidateCommand_FlagAllowlist verifies that flag validation is
// default-deny and that identity, transport, credential, raw-API and
// verbosity flags cannot reach the data provider.
//
// Regression test for the impersonation escalation: ValidateCommand previously
// checked only the binary, the subcommand and five streaming flags, so
// "kubectl get secrets -A --as=system:admin --as-group=system:masters" was
// forwarded verbatim to kubectl and executed with the stored kubeconfig
// identity's impersonate rights.
func TestValidateCommand_FlagAllowlist(t *testing.T) {
	tests := []struct {
		name    string
		cmd     *ParsedCommand
		wantErr bool
	}{
		{
			name: "impersonation via valued flags is rejected",
			cmd: &ParsedCommand{
				Command:      "kubectl",
				Subcommand:   "get",
				Args:         []string{"secrets"},
				Flags:        map[string]string{"as": "system:admin", "as-group": "system:masters"},
				BooleanFlags: []string{"A"},
			},
			wantErr: true,
		},
		{
			// "--as --as-group=x" parses "as" as a boolean flag, so a check that
			// only inspected Flags would miss it.
			name: "impersonation via boolean flag is rejected",
			cmd: &ParsedCommand{
				Command:      "kubectl",
				Subcommand:   "get",
				Args:         []string{"pods"},
				Flags:        map[string]string{},
				BooleanFlags: []string{"as"},
			},
			wantErr: true,
		},
		{
			name: "as-uid is rejected",
			cmd: &ParsedCommand{
				Command:      "kubectl",
				Subcommand:   "get",
				Args:         []string{"pods"},
				Flags:        map[string]string{"as-uid": "0"},
				BooleanFlags: []string{},
			},
			wantErr: true,
		},
		{
			name: "server redirection is rejected",
			cmd: &ParsedCommand{
				Command:      "kubectl",
				Subcommand:   "get",
				Args:         []string{"pods"},
				Flags:        map[string]string{"server": "https://attacker.example"},
				BooleanFlags: []string{},
			},
			wantErr: true,
		},
		{
			name: "short form server redirection is rejected",
			cmd: &ParsedCommand{
				Command:      "kubectl",
				Subcommand:   "get",
				Args:         []string{"pods"},
				Flags:        map[string]string{"s": "https://attacker.example"},
				BooleanFlags: []string{},
			},
			wantErr: true,
		},
		{
			name: "token injection is rejected",
			cmd: &ParsedCommand{
				Command:      "kubectl",
				Subcommand:   "get",
				Args:         []string{"pods"},
				Flags:        map[string]string{"token": "eyJhbGciOi"},
				BooleanFlags: []string{},
			},
			wantErr: true,
		},
		{
			name: "kubeconfig override is rejected",
			cmd: &ParsedCommand{
				Command:      "kubectl",
				Subcommand:   "get",
				Args:         []string{"pods"},
				Flags:        map[string]string{"kubeconfig": "/proc/self/root/etc/kubeconfig"},
				BooleanFlags: []string{},
			},
			wantErr: true,
		},
		{
			name: "context switching is rejected",
			cmd: &ParsedCommand{
				Command:      "kubectl",
				Subcommand:   "get",
				Args:         []string{"pods"},
				Flags:        map[string]string{"context": "admin"},
				BooleanFlags: []string{},
			},
			wantErr: true,
		},
		{
			// --raw bypasses the subcommand allowlist: "get" no longer constrains
			// which API path is reached.
			name: "raw API access is rejected",
			cmd: &ParsedCommand{
				Command:      "kubectl",
				Subcommand:   "get",
				Args:         []string{},
				Flags:        map[string]string{"raw": "/api/v1/namespaces/kube-system/secrets"},
				BooleanFlags: []string{},
			},
			wantErr: true,
		},
		{
			// stderr is returned to the caller and -v>=6 echoes the
			// Authorization header, leaking the stored kubeconfig's token.
			name: "verbosity flag is rejected",
			cmd: &ParsedCommand{
				Command:      "kubectl",
				Subcommand:   "get",
				Args:         []string{"pods"},
				Flags:        map[string]string{"v": "9"},
				BooleanFlags: []string{},
			},
			wantErr: true,
		},
		{
			name: "insecure-skip-tls-verify is rejected",
			cmd: &ParsedCommand{
				Command:      "kubectl",
				Subcommand:   "get",
				Args:         []string{"pods"},
				Flags:        map[string]string{},
				BooleanFlags: []string{"insecure-skip-tls-verify"},
			},
			wantErr: true,
		},
		{
			name: "unknown flag is rejected by default-deny",
			cmd: &ParsedCommand{
				Command:      "kubectl",
				Subcommand:   "get",
				Args:         []string{"pods"},
				Flags:        map[string]string{"some-future-kubectl-flag": "x"},
				BooleanFlags: []string{},
			},
			wantErr: true,
		},
		{
			name: "empty flag name is rejected",
			cmd: &ParsedCommand{
				Command:      "kubectl",
				Subcommand:   "get",
				Args:         []string{"pods"},
				Flags:        map[string]string{},
				BooleanFlags: []string{""},
			},
			wantErr: true,
		},
		{
			name: "legitimate get with scope and formatting flags is allowed",
			cmd: &ParsedCommand{
				Command:      "kubectl",
				Subcommand:   "get",
				Args:         []string{"pods"},
				Flags:        map[string]string{"n": "default", "o": "yaml", "l": "app=nginx"},
				BooleanFlags: []string{"show-labels", "no-headers"},
			},
			wantErr: false,
		},
		{
			name: "legitimate logs with all log flags is allowed",
			cmd: &ParsedCommand{
				Command:      "kubectl",
				Subcommand:   "logs",
				Args:         []string{"nginx"},
				Flags:        map[string]string{"c": "app", "tail": "100", "since": "5m"},
				BooleanFlags: []string{"timestamps", "previous"},
			},
			wantErr: false,
		},
		{
			name: "legitimate oc get across all namespaces is allowed",
			cmd: &ParsedCommand{
				Command:      "oc",
				Subcommand:   "get",
				Args:         []string{"routes"},
				Flags:        map[string]string{"field-selector": "metadata.name=web"},
				BooleanFlags: []string{"all-namespaces"},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateCommand(tt.cmd)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateCommand() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr && !errors.Is(err, ErrCommandNotPermitted) {
				t.Errorf("ValidateCommand() error = %v, want %v", err, ErrCommandNotPermitted)
			}
		})
	}
}

// TestFlagSpecsAreDisjoint guards the two flag lists against drift: a flag must
// never appear in both, or the intent of the allowlist becomes ambiguous.
func TestFlagSpecsAreDisjoint(t *testing.T) {
	for _, denied := range DeniedFlagsSpec {
		if IsFlagAllowed(denied.Name) {
			t.Errorf("flag %q appears in both AllowedFlagsSpec and DeniedFlagsSpec", denied.Name)
		}
	}

	// The v1 streaming blocks must not be reachable through the allowlist either.
	for _, blocked := range BlockedFlags {
		if IsFlagAllowed(blocked) {
			t.Errorf("streaming flag %q must not appear in AllowedFlagsSpec", blocked)
		}
	}
}

// TestValidateCommand_ValueSmuggling covers flag-shaped values.
//
// An allowlist on flag names alone is insufficient: the data provider emits a
// flag and its value as separate argv elements, and kubectl boolean flags do
// not consume the following token, so the value is parsed as its own flag.
// Verified against kubectl v1.36.1:
//
//	kubectl get pods --show-labels --as=system:admin
//	  -> curl -H "Impersonate-User: system:admin" ...
func TestValidateCommand_ValueSmuggling(t *testing.T) {
	tests := []struct {
		name    string
		flags   map[string]string
		args    []string
		wantErr bool
	}{
		{
			name:    "impersonation smuggled through an allowed boolean flag",
			flags:   map[string]string{"show-labels": "--as=system:admin"},
			wantErr: true,
		},
		{
			name:    "impersonation smuggled through all-namespaces",
			flags:   map[string]string{"all-namespaces": "--as-group=system:masters"},
			wantErr: true,
		},
		{
			name:    "token smuggled through timestamps",
			flags:   map[string]string{"timestamps": "--token=stolen"},
			wantErr: true,
		},
		{
			name:    "raw smuggled through no-headers",
			flags:   map[string]string{"no-headers": "--raw=/api/v1/secrets"},
			wantErr: true,
		},
		{
			name:    "short flag smuggled as a value",
			flags:   map[string]string{"show-labels": "-s"},
			wantErr: true,
		},
		{
			name:    "bare double dash as a value",
			flags:   map[string]string{"show-labels": "--"},
			wantErr: true,
		},
		{
			name:    "flag-shaped positional argument",
			args:    []string{"pods", "--as=system:admin"},
			wantErr: true,
		},
		{
			// pflag consumes the token after a value-taking flag unconditionally,
			// and --tail=-1 (all lines) must keep working.
			name:    "negative number value is allowed",
			flags:   map[string]string{"tail": "-1"},
			wantErr: false,
		},
		{
			name:    "ordinary values are allowed",
			flags:   map[string]string{"n": "default", "o": "jsonpath={.items[*].metadata.name}", "l": "app=nginx"},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := tt.args
			if args == nil {
				args = []string{"pods"}
			}
			cmd := &ParsedCommand{
				Command:      "kubectl",
				Subcommand:   "get",
				Args:         args,
				Flags:        tt.flags,
				BooleanFlags: []string{},
			}
			if cmd.Flags == nil {
				cmd.Flags = map[string]string{}
			}

			err := ValidateCommand(cmd)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateCommand() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr && !errors.Is(err, ErrCommandNotPermitted) {
				t.Errorf("ValidateCommand() error = %v, want %v", err, ErrCommandNotPermitted)
			}
		})
	}
}

// TestValidateCommand_RawCommandStrings exercises the full path a request
// actually takes -- ParseCommand then ValidateCommand -- rather than
// hand-constructing ParsedCommand. Struct-level tests alone cannot show that
// the parser routes a hostile string into the fields the validator inspects.
func TestValidateCommand_RawCommandStrings(t *testing.T) {
	rejected := []string{
		"kubectl get secrets -A --as=system:admin --as-group=system:masters",
		"kubectl get secrets --as system:admin",
		"kubectl get pods --as --as-group=system:masters",
		"kubectl get pods -v=9",
		"kubectl get pods -v 9",
		"kubectl get --raw=/api/v1/namespaces/kube-system/secrets",
		"kubectl get pods --server=https://attacker.example --token=abc",
		"kubectl get pods -s https://attacker.example",
		"kubectl get pods --context=admin",
		"kubectl get pods --user=admin",
		"kubectl get pods --insecure-skip-tls-verify",
		"kubectl get pods --kubeconfig=/etc/shadow",
		`kubectl get pods --as="system:admin"`,
		"kubectl get pods --show-labels=--as=system:admin",
		"kubectl get pods --all-namespaces=--as-group=system:masters",
		"kubectl get pods --namespace=--as=admin",
		"kubectl get pods --",
		"kubectl delete pod nginx",
		"kubectl get pods --watch",
	}
	for _, cmdString := range rejected {
		t.Run("reject/"+cmdString, func(t *testing.T) {
			cmd, err := ParseCommand(cmdString)
			if err != nil {
				return // rejected at the parser, equally safe
			}
			if err := ValidateCommand(cmd); err == nil {
				t.Errorf("ValidateCommand(%q) = nil, want rejection (flags=%v boolean=%v args=%v)",
					cmdString, cmd.Flags, cmd.BooleanFlags, cmd.Args)
			}
		})
	}

	allowed := []string{
		"kubectl",
		"kubectl get pods",
		"kubectl get pods -n default --output=yaml",
		"kubectl get pods --all-namespaces --show-labels",
		"kubectl get pods --field-selector=status.phase=Running",
		"kubectl logs nginx --tail=100 --timestamps",
		"kubectl logs nginx --tail=-1",
		"kubectl logs nginx -c app --since=5m --previous",
		"kubectl describe pod nginx -n default",
		"kubectl top nodes",
		"kubectl version --client",
		"kubectl api-resources --namespaced --verbs=get",
		"oc get routes -l app=web -o json",
		`kubectl get pod "my pod"`,
	}
	for _, cmdString := range allowed {
		t.Run("allow/"+cmdString, func(t *testing.T) {
			cmd, err := ParseCommand(cmdString)
			if err != nil {
				t.Fatalf("ParseCommand(%q) failed: %v", cmdString, err)
			}
			if err := ValidateCommand(cmd); err != nil {
				t.Errorf("ValidateCommand(%q) = %v, want nil (flags=%v boolean=%v)",
					cmdString, err, cmd.Flags, cmd.BooleanFlags)
			}
		})
	}
}
