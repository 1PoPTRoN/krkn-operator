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

// SubcommandSpec defines a permitted subcommand
type SubcommandSpec struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

// CommandSpec defines a permitted command and its allowed subcommands
type CommandSpec struct {
	Name               string           `json:"name"`
	Description        string           `json:"description"`
	AllowedSubcommands []SubcommandSpec `json:"subcommands"`
}

// BlockedFlagSpec defines a blocked flag
type BlockedFlagSpec struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

// FlagSpec defines a flag and the reason it is permitted or denied.
// Flag names are stored without leading dashes, matching how ParseCommand
// normalizes them, and are matched case-sensitively because kubectl treats
// -A (all-namespaces) and -a as distinct flags.
type FlagSpec struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

// AvailableCommands defines all permitted commands and their subcommands
// This is the single source of truth for terminal command validation
var AvailableCommands = map[string]CommandSpec{
	"kubectl": {
		Name:        "kubectl",
		Description: "Kubernetes command-line tool",
		AllowedSubcommands: []SubcommandSpec{
			{Name: "get", Description: "Display one or many resources"},
			{Name: "describe", Description: "Show details of a specific resource"},
			{Name: "logs", Description: "Print container logs"},
			{Name: "top", Description: "Display resource usage (CPU/Memory)"},
			{Name: "explain", Description: "Get documentation for a resource"},
			{Name: "version", Description: "Print client and server version information"},
			{Name: "api-resources", Description: "Print supported API resources"},
			{Name: "api-versions", Description: "Print supported API versions"},
			{Name: "cluster-info", Description: "Display cluster information"},
		},
	},
	"oc": {
		Name:        "oc",
		Description: "OpenShift command-line tool",
		AllowedSubcommands: []SubcommandSpec{
			{Name: "get", Description: "Display one or many resources"},
			{Name: "describe", Description: "Show details of a specific resource"},
			{Name: "logs", Description: "Print container logs"},
			{Name: "top", Description: "Display resource usage (CPU/Memory)"},
			{Name: "explain", Description: "Get documentation for a resource"},
			{Name: "version", Description: "Print client and server version information"},
			{Name: "api-resources", Description: "Print supported API resources"},
			{Name: "api-versions", Description: "Print supported API versions"},
			{Name: "cluster-info", Description: "Display cluster information"},
		},
	},
}

// BlockedFlagsSpec defines all blocked flags and why they're blocked
var BlockedFlagsSpec = []BlockedFlagSpec{
	{Name: "watch", Description: "Streaming flag blocked in v1 - requires WebSocket/SSE"},
	{Name: "w", Description: "Short form of --watch"},
	{Name: "follow", Description: "Streaming flag blocked in v1 - requires WebSocket/SSE"},
	{Name: "f", Description: "Short form of --follow"},
	{Name: "watch-only", Description: "Streaming flag blocked in v1 - requires WebSocket/SSE"},
}

// AllowedFlagsSpec is the exhaustive allowlist of flags the terminal accepts.
//
// Flag validation is default-deny: a flag absent from this list is rejected.
// This is deliberate. The data provider reassembles Command, Subcommand, Args,
// Flags and BooleanFlags into the argv it hands to kubectl and performs no
// validation of its own, so any flag that reaches it is executed verbatim
// against the target cluster using the stored kubeconfig identity.
//
// Every entry below is read-only: it selects, filters or formats output.
// Adding a flag that alters identity (--as), transport (--server), credentials
// (--token), the API path (--raw) or client-side debug output (-v) reopens the
// privilege-escalation path this list exists to close. Widening this list is a
// security change and should be reviewed as one.
var AllowedFlagsSpec = []FlagSpec{
	// Scope
	{Name: "n", Description: "Short form of --namespace"},
	{Name: "namespace", Description: "Restrict the request to a single namespace"},
	{Name: "A", Description: "Short form of --all-namespaces"},
	{Name: "all-namespaces", Description: "List the requested resource across all namespaces"},

	// Filtering
	{Name: "l", Description: "Short form of --selector"},
	{Name: "selector", Description: "Filter by label selector"},
	{Name: "field-selector", Description: "Filter by field selector"},
	{Name: "ignore-not-found", Description: "Exit 0 when the requested resource is absent"},

	// Output formatting
	{Name: "o", Description: "Short form of --output"},
	{Name: "output", Description: "Output format (json, yaml, wide, jsonpath, ...)"},
	{Name: "no-headers", Description: "Omit the table header row"},
	{Name: "show-labels", Description: "Append a labels column to table output"},
	{Name: "show-kind", Description: "Prefix table rows with the resource kind"},
	{Name: "sort-by", Description: "Sort table output by a JSONPath expression"},
	{Name: "L", Description: "Short form of --label-columns"},
	{Name: "label-columns", Description: "Render the given labels as table columns"},

	// Logs
	{Name: "c", Description: "Short form of --container"},
	{Name: "container", Description: "Select a container within the pod"},
	{Name: "tail", Description: "Return only the last N lines of the log"},
	{Name: "since", Description: "Return logs newer than a relative duration"},
	{Name: "since-time", Description: "Return logs newer than an RFC3339 timestamp"},
	{Name: "limit-bytes", Description: "Cap the number of log bytes returned"},
	{Name: "p", Description: "Short form of --previous"},
	{Name: "previous", Description: "Return logs from the previous container instance"},
	{Name: "timestamps", Description: "Prefix each log line with a timestamp"},
	{Name: "prefix", Description: "Prefix each log line with its source"},

	// Subcommand-specific, read-only
	{Name: "containers", Description: "Break resource usage down per container (top)"},
	{Name: "recursive", Description: "Describe fields recursively (explain)"},
	{Name: "api-version", Description: "Select the API version to explain (explain)"},
	{Name: "namespaced", Description: "Filter by namespaced scope (api-resources)"},
	{Name: "api-group", Description: "Filter by API group (api-resources)"},
	{Name: "verbs", Description: "Filter by supported verbs (api-resources)"},
	{Name: "client", Description: "Print client version only (version)"},
	{Name: "short", Description: "Print abbreviated version output (version)"},
}

// DeniedFlagsSpec enumerates flags that must never reach kubectl, with the
// capability each one would hand the caller.
//
// The allowlist above already rejects every one of these by default. This list
// is a second, independent gate checked *before* the allowlist so that a flag
// mistakenly added to AllowedFlagsSpec in future cannot silently become
// reachable. It also documents the threat model for reviewers.
var DeniedFlagsSpec = []FlagSpec{
	// Identity — the reported escalation path
	{Name: "as", Description: "Impersonate another user"},
	{Name: "as-group", Description: "Impersonate a group, e.g. system:masters"},
	{Name: "as-uid", Description: "Impersonate a UID"},

	// Credentials and transport — redirect the request or swap the identity
	{Name: "token", Description: "Supply an arbitrary bearer token"},
	{Name: "s", Description: "Short form of --server"},
	{Name: "server", Description: "Redirect the request to an arbitrary API server"},
	{Name: "kubeconfig", Description: "Load an arbitrary kubeconfig from the container filesystem"},
	{Name: "client-certificate", Description: "Authenticate with an arbitrary client certificate"},
	{Name: "client-key", Description: "Authenticate with an arbitrary client key"},
	{Name: "certificate-authority", Description: "Trust an arbitrary certificate authority"},
	{Name: "tls-server-name", Description: "Override the TLS server name"},
	{Name: "insecure-skip-tls-verify", Description: "Disable TLS verification"},
	{Name: "username", Description: "Supply basic-auth credentials"},
	{Name: "password", Description: "Supply basic-auth credentials"},

	// Kubeconfig selection — the stored kubeconfig may hold several identities
	{Name: "user", Description: "Select a different user from the kubeconfig"},
	{Name: "cluster", Description: "Select a different cluster from the kubeconfig"},
	{Name: "context", Description: "Select a different context from the kubeconfig"},

	// API escape — bypasses the subcommand allowlist entirely
	{Name: "raw", Description: "Issue a raw request to an arbitrary API path"},

	// Verbosity — client-go masks the Authorization header, so this is not a
	// credential leak, but -v>=6 still returns request URLs, headers and bodies
	// to the caller via stderr and is not read-only output formatting.
	{Name: "v", Description: "Client debug verbosity; exposes request URLs, headers and bodies"},
	{Name: "vmodule", Description: "Per-module client verbosity"},
	{Name: "log-file", Description: "Write client logs to an arbitrary path"},
	{Name: "log-backtrace-at", Description: "klog flag with filesystem side effects"},
	{Name: "logtostderr", Description: "Redirect klog output"},
	{Name: "alsologtostderr", Description: "Redirect klog output"},
	{Name: "stderrthreshold", Description: "Lower the klog stderr threshold"},

	// Local filesystem side effects
	{Name: "cache-dir", Description: "Write the discovery cache to an arbitrary path"},
	{Name: "profile", Description: "Enable client profiling"},
	{Name: "profile-output", Description: "Write a profile to an arbitrary path"},
}

// allowedFlagLookup and deniedFlagLookup are O(1) indexes over the specs above.
// The specs remain the single source of truth; these are derived at init.
var (
	allowedFlagLookup = buildFlagLookup(AllowedFlagsSpec)
	deniedFlagLookup  = buildFlagLookup(DeniedFlagsSpec)
)

// buildFlagLookup indexes a flag spec list by name for constant-time lookup
func buildFlagLookup(specs []FlagSpec) map[string]struct{} {
	lookup := make(map[string]struct{}, len(specs))
	for _, spec := range specs {
		lookup[spec.Name] = struct{}{}
	}
	return lookup
}

// IsCommandAllowed checks if a command name is in the allowed list
func IsCommandAllowed(command string) bool {
	_, exists := AvailableCommands[command]
	return exists
}

// IsSubcommandAllowed checks if a subcommand is allowed for a given command
func IsSubcommandAllowed(command, subcommand string) bool {
	cmdSpec, exists := AvailableCommands[command]
	if !exists {
		return false
	}

	for _, sc := range cmdSpec.AllowedSubcommands {
		if sc.Name == subcommand {
			return true
		}
	}
	return false
}

// IsFlagAllowed checks if a flag name is in the allowlist.
// The name must already be normalized (no leading dashes), as produced by
// ParseCommand. Matching is case-sensitive: kubectl distinguishes -A from -a.
func IsFlagAllowed(flag string) bool {
	_, exists := allowedFlagLookup[flag]
	return exists
}

// IsFlagDenied checks if a flag name is explicitly denied.
// Denied flags are rejected regardless of the allowlist.
func IsFlagDenied(flag string) bool {
	_, exists := deniedFlagLookup[flag]
	return exists
}

// GetAllowedCommands returns the list of all allowed commands
func GetAllowedCommands() []CommandSpec {
	commands := make([]CommandSpec, 0, len(AvailableCommands))
	for _, cmd := range AvailableCommands {
		commands = append(commands, cmd)
	}
	return commands
}

// GetBlockedFlags returns the list of all blocked flags
func GetBlockedFlags() []BlockedFlagSpec {
	return BlockedFlagsSpec
}

// GetAllowedFlags returns the list of all flags permitted by the terminal
func GetAllowedFlags() []FlagSpec {
	return AllowedFlagsSpec
}

// GetDeniedFlags returns the list of all explicitly denied flags
func GetDeniedFlags() []FlagSpec {
	return DeniedFlagsSpec
}
