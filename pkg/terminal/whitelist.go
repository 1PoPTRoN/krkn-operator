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

// Package terminal provides command validation and whitelisting for kubectl/oc commands
package terminal

import (
	"errors"
	"strings"
)

// Custom error types for better error handling
var (
	// ErrCommandNotFound is returned when command is not kubectl or oc
	ErrCommandNotFound = errors.New("command_not_found")

	// ErrCommandNotPermitted is returned when subcommand or flag is not allowed
	ErrCommandNotPermitted = errors.New("command_not_permitted")
)

// BlockedFlags defines flags that enable streaming or watch modes
// These are blocked in v1 because they require WebSocket/SSE support
// NOTE: This is kept for backward compatibility, use BlockedFlagsSpec for the canonical list
var BlockedFlags = []string{
	"watch",
	"w",
	"follow",
	"f",
	"watch-only",
}

// ValidateCommand validates that a command is safe to execute (read-only)
// Returns an error if the command is not permitted
func ValidateCommand(cmd *ParsedCommand) error {
	// Validate command is in allowed list (kubectl or oc)
	if !IsCommandAllowed(cmd.Command) {
		return ErrCommandNotFound
	}

	// Empty subcommand is allowed (shows help output)
	if cmd.Subcommand != "" {
		// Validate subcommand is in whitelist for this command
		if !IsSubcommandAllowed(cmd.Command, cmd.Subcommand) {
			return ErrCommandNotPermitted
		}
	}

	// Check for blocked streaming flags
	for _, blockedFlag := range BlockedFlags {
		// Check boolean flags
		for _, flag := range cmd.BooleanFlags {
			if flag == blockedFlag {
				return ErrCommandNotPermitted
			}
		}

		// Check valued flags (in case user passes --watch=true)
		if _, exists := cmd.Flags[blockedFlag]; exists {
			return ErrCommandNotPermitted
		}
	}

	// Validate every flag against the allowlist.
	//
	// Both collections must be checked: ParseCommand routes the same flag name
	// into Flags or BooleanFlags depending on what follows it, so "--as admin"
	// lands in Flags while "--as --as-group=x" makes "as" a BooleanFlag.
	// Checking only one leaves the other as a bypass.
	for _, flag := range cmd.BooleanFlags {
		if err := validateFlag(flag); err != nil {
			return err
		}
	}
	for flag, value := range cmd.Flags {
		if err := validateFlag(flag); err != nil {
			return err
		}

		// An allowed name is not sufficient. The data provider emits the flag
		// and its value as two separate argv elements, and kubectl's boolean
		// flags do not consume the token that follows them, so a flag-shaped
		// value becomes a flag in its own right:
		//
		//   --show-labels=--as=system:admin
		//     -> Flags["show-labels"] = "--as=system:admin"
		//     -> argv [... "--show-labels" "--as=system:admin" ...]
		//     -> kubectl sends Impersonate-User: system:admin
		//
		// Rejecting flag-shaped values closes this for every allowed flag,
		// including any added later.
		if isFlagLikeValue(value) {
			return ErrCommandNotPermitted
		}
	}

	// Positional arguments are reassembled into argv the same way. ParseCommand
	// currently routes every dash-prefixed token to the flag branches, so this
	// is a guard against that changing rather than a reachable bypass today.
	for _, arg := range cmd.Args {
		if isFlagLikeValue(arg) {
			return ErrCommandNotPermitted
		}
	}

	return nil
}

// isFlagLikeValue reports whether a value would be interpreted as a flag by
// kubectl if it reached the command line as a standalone argv element.
//
// Negative numbers are deliberately excluded: "--tail=-1" is a legitimate
// kubectl invocation, and pflag only resolves a token to a flag when a name
// follows the leading dashes.
func isFlagLikeValue(value string) bool {
	if len(value) < 2 || value[0] != '-' {
		return false
	}

	name := strings.TrimLeft(value, "-")
	if name == "" {
		// "--" ends flag parsing and would unhide any token after it.
		return true
	}

	c := name[0]
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

// validateFlag applies the deny-then-allow decision to a single flag name.
//
// The explicit denylist is consulted first so that a high-risk flag added to
// AllowedFlagsSpec by mistake still cannot reach kubectl. The default-deny
// branch is what actually closes the escalation path: anything not named in
// AllowedFlagsSpec is rejected rather than forwarded to the data provider.
func validateFlag(flag string) error {
	if IsFlagDenied(flag) {
		return ErrCommandNotPermitted
	}

	if !IsFlagAllowed(flag) {
		return ErrCommandNotPermitted
	}

	return nil
}

// IsStreamingFlag checks if a flag name indicates streaming behavior
func IsStreamingFlag(flagName string) bool {
	// Remove all leading dashes and convert to lowercase
	normalized := strings.ToLower(strings.TrimLeft(flagName, "-"))
	for _, blocked := range BlockedFlags {
		if normalized == blocked {
			return true
		}
	}
	return false
}
