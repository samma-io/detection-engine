// Package source maps a log-source name to the per-source behaviour the engine
// needs. It exists so that adding a source is a data change in one place.
package source

import (
	"fmt"
	"sort"
	"strings"
)

// Source is everything the engine varies per log source.
//
// Today that is only the sigma-go config file name, because every lane carries
// gzipped NDJSON written by the same Vector sink. It is a struct rather than a
// bare string so that a lane needing its own decoder later does not change
// every call site.
type Source struct {
	// Name is the key, and doubles as the rules prefix segment and the
	// filtered bucket's leading key segment.
	Name string

	// ConfigFile is the sigma-go Config (field mappings, logsource rewrites)
	// loaded from the source's rules prefix. Every rule in the prefix is
	// compiled against it.
	ConfigFile string
}

// KeyPrefix is the leading segment of every object key for this source in the
// filtered bucket. It is the contract with the pipeline: the S3 notification
// for a lane filters on exactly this prefix, and the rules bucket uses the
// same segment (<lane>/) for that lane's ruleset. See
// samma-io/aws-siem docs/contracts/filtered-object-layout.md.
//
// It is asserted against each incoming key. A github deployment handed an
// "aws/" object means the queue is subscribed to the wrong notification, and
// evaluating GitHub rules against CloudTrail would produce confident nonsense
// -- so the engine refuses rather than guesses.
func (s Source) KeyPrefix() string { return s.Name + "/" }

// registry is deliberately a map, not a switch.
//
// A closed switch over source names is a silent-data-loss hazard: a lane added
// to the deployment but not to the dispatcher falls through to a default, and the
// engine drains the queue while matching nothing. A map plus Lookup's explicit
// error means an unknown source cannot start at all, and
// TestRegistry_HasAnEntryForEveryDetectionSource fails in CI when the two
// drift.
var registry = map[string]Source{
	"aws":       {Name: "aws", ConfigFile: "sigma-config.yml"},
	"gcp":       {Name: "gcp", ConfigFile: "sigma-config.yml"},
	"github":    {Name: "github", ConfigFile: "sigma-config.yml"},
	"workspace": {Name: "workspace", ConfigFile: "sigma-config.yml"},
	"slack":     {Name: "slack", ConfigFile: "sigma-config.yml"},

	// onepassword carries three feeds on one prefix -- itemusages,
	// signinattempts and auditevents -- told apart by Vector's .feed rather
	// than by separate queues, because they share a bucket and a notification.
	"onepassword": {Name: "onepassword", ConfigFile: "sigma-config.yml"},

	// dns and alb were part of the aws lane until Vector gave them their own
	// prefixes and queues. They are separate here for the same
	// reason they are separate indexes: they carry different timestamp fields
	// and different shapes, and a rule written for one is meaningless against
	// the other.
	//
	// alb is CONNECTION logs -- one record per TLS connection, carrying the
	// handshake and client certificate. Not access logs; nothing here has a
	// URL or a status code.
	"dns": {Name: "dns", ConfigFile: "sigma-config.yml"},
	"alb": {Name: "alb", ConfigFile: "sigma-config.yml"},

	// cloudflare is written by the ingester's cloudflare lane and carries
	// seven feeds on one prefix -- access, audit, devices, firewall and the
	// three gateway_* aggregates -- told apart by .feed (the ingester's
	// _partition), the same way onepassword is.
	"cloudflare": {Name: "cloudflare", ConfigFile: "sigma-config.yml"},

	// k8s and scanner exist only on the NATS transport (ENGINE_TRANSPORT=nats);
	// nothing writes them to the filtered bucket, so aws-siem creates no queue
	// for them. See aws-siem docs/contracts/nats-transport.md.
	//
	// k8s is Kubernetes audit events (audit.k8s.io/v1), one per message on
	// samma.logs.k8s. scanner is the Samma scanners' schema v2 messages
	// (finding and run), relayed unchanged to samma.logs.scanner. wazuh is
	// Wazuh alerts from alerts.json, one per message on samma.logs.wazuh.
	// osquery is osquery-client scheduled-query results, one result row per
	// message on samma.logs.osquery (published by osquery-gateway).
	// traefik is Traefik JSON access logs from labelled pods, one request per
	// message on samma.logs.svc.traefik in stream SIEM_SERVICES (published by
	// k8s-log-router); set ENGINE_NATS_STREAM and ENGINE_NATS_SUBJECT for it.
	"k8s":     {Name: "k8s", ConfigFile: "sigma-config.yml"},
	"scanner": {Name: "scanner", ConfigFile: "sigma-config.yml"},
	"wazuh":   {Name: "wazuh", ConfigFile: "sigma-config.yml"},
	"osquery": {Name: "osquery", ConfigFile: "sigma-config.yml"},
	"traefik": {Name: "traefik", ConfigFile: "sigma-config.yml"},

	// Security tools, all on SIEM_SERVICES through k8s-log-router (see each
	// lane's sigma-config.yml). falco, gatekeeper and openappsec are pod logs
	// from labelled pods (samma.logs.svc.<lane>, feed k8s); trivy is
	// trivy-operator reports pushed to the router over HTTP (feed push).
	"falco":      {Name: "falco", ConfigFile: "sigma-config.yml"},
	"trivy":      {Name: "trivy", ConfigFile: "sigma-config.yml"},
	"gatekeeper": {Name: "gatekeeper", ConfigFile: "sigma-config.yml"},
	"openappsec": {Name: "openappsec", ConfigFile: "sigma-config.yml"},
}

// Lookup resolves a source name, naming every valid one when it fails.
//
// The error text lists the alternatives because this is read from an env var
// set by Terraform; the operator seeing it is looking at a task that will not
// start and needs to know what to put there.
func Lookup(name string) (Source, error) {
	key := strings.ToLower(strings.TrimSpace(name))
	if key == "" {
		return Source{}, fmt.Errorf("log source is not set; expected one of %s", strings.Join(Names(), ", "))
	}
	s, ok := registry[key]
	if !ok {
		return Source{}, fmt.Errorf("log source %q is not known; expected one of %s", name, strings.Join(Names(), ", "))
	}
	return s, nil
}

// Names returns every registered source, sorted so error messages and logs are
// stable across runs.
func Names() []string {
	out := make([]string, 0, len(registry))
	for name := range registry {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}
