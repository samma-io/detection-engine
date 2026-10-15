// Package config loads the engine's runtime settings from the environment.
//
// Everything here is something you would change between the four per-source
// ECS services, localstack, or a test. Nothing behaviour-affecting lives in
// code.
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/samma-io/detection-engine/internal/source"
)

// Defaults that are also documented in the repo README and the Terraform.
const (
	DefaultWorkers            = 4
	DefaultMaxObjectBytes     = 256 << 20 // 256 MiB
	DefaultMaxDecodeErrorRate = 0.01
	DefaultVisibilityBeat     = 100 * time.Second
	DefaultVisibilityTimeout  = 300 * time.Second
	DefaultMaxObjectDuration  = 45 * time.Minute
	DefaultMaxAlertsPerObject = 10_000
	DefaultMetricsAddr        = ":9090"

	TransportSQS  = "sqs"
	TransportNATS = "nats"

	DefaultNATSStream = "SIEM_LOGS"
)

type Config struct {
	// Source is the resolved log source. It selects both the rules prefix and,
	// as a constant metrics label, everything this task reports.
	Source source.Source

	// Transport is "sqs" (S3 notifications, the AWS deployment) or "nats"
	// (records carried on JetStream, the Kubernetes deployment).
	Transport string

	QueueURL      string
	AlertQueueURL string

	// NATS transport only. The subjects default to samma.logs.<lane> and
	// samma.alerts.<lane>; see aws-siem docs/contracts/detection-alert-v1.md.
	NATSURL      string
	NATSStream   string
	NATSConsumer string
	NATSSubject  string
	AlertSubject string

	// Exactly one of RulesDir and RulesBucket is set. RulesDir is the tree
	// baked into the image (the default); RulesBucket is the override for an
	// installation that ships its own rules.
	RulesDir    string
	RulesBucket string
	RulesPrefix string

	AWSRegion      string
	S3EndpointURL  string // localstack only; empty in the account
	SQSEndpointURL string // localstack only; empty in the account

	Workers            int
	MaxObjectBytes     int64
	MaxDecodeErrorRate float64
	MaxAlertsPerObject int
	MaxObjectDuration  time.Duration
	VisibilityBeat     time.Duration
	VisibilityTimeout  time.Duration

	MetricsAddr string
	LogLevel    string
}

// RulePrefix is where this task's rules live: an S3 key prefix in the rules
// bucket, or a relative path under RulesDir. The shape is the same in both.
func (c Config) RulePrefix() string {
	return c.RulesPrefix + c.Source.Name + "/"
}

// RulesSource names where the rules come from, for the startup log.
func (c Config) RulesSource() string {
	if c.RulesDir != "" {
		return "dir"
	}
	return "bucket"
}

// FromEnv reads and validates configuration.
//
// getenv is a parameter rather than a call to os.Getenv so tests never mutate
// process state, which would leak between them.
//
// Every required value is an error rather than a default. An engine that
// starts, drains its queue and evaluates nothing looks healthy on every
// dashboard there is -- the queue depth even goes *down* -- so refusing to
// start is the only cheap defence. The same reasoning applies to the rule
// loader's zero-rules check.
func FromEnv(getenv func(string) string) (Config, error) {
	get := func(k, def string) string {
		if v := strings.TrimSpace(getenv(k)); v != "" {
			return v
		}
		return def
	}

	c := Config{
		Transport:      get("ENGINE_TRANSPORT", TransportSQS),
		NATSURL:        get("ENGINE_NATS_URL", ""),
		NATSStream:     get("ENGINE_NATS_STREAM", DefaultNATSStream),
		NATSConsumer:   get("ENGINE_NATS_CONSUMER", ""),
		NATSSubject:    get("ENGINE_NATS_SUBJECT", ""),
		AlertSubject:   get("ENGINE_ALERT_SUBJECT", ""),
		QueueURL:       get("ENGINE_QUEUE_URL", ""),
		AlertQueueURL:  get("ENGINE_ALERT_QUEUE_URL", ""),
		RulesDir:       get("ENGINE_RULES_DIR", ""),
		RulesBucket:    get("ENGINE_RULES_BUCKET", ""),
		RulesPrefix:    get("ENGINE_RULES_PREFIX", ""),
		AWSRegion:      get("AWS_REGION", ""),
		S3EndpointURL:  get("ENGINE_S3_ENDPOINT_URL", ""),
		SQSEndpointURL: get("ENGINE_SQS_ENDPOINT_URL", ""),
		MetricsAddr:    get("ENGINE_METRICS_ADDR", DefaultMetricsAddr),
		LogLevel:       get("ENGINE_LOG_LEVEL", "info"),
	}

	// A trailing slash on the prefix is easy to get wrong in Terraform and
	// silently yields "rulesaws/" instead of "rules/aws/". Normalise rather
	// than reject: the intent is never ambiguous.
	if c.RulesPrefix != "" && !strings.HasSuffix(c.RulesPrefix, "/") {
		c.RulesPrefix += "/"
	}

	// Collect every problem before returning. A task that fails four times,
	// each naming one missing variable, wastes four deploys.
	var problems []string

	src, err := source.Lookup(getenv("ENGINE_LOG_SOURCE"))
	if err != nil {
		problems = append(problems, "ENGINE_LOG_SOURCE: "+err.Error())
	}
	c.Source = src

	required := map[string]string{}
	switch c.Transport {
	case TransportSQS:
		required["ENGINE_QUEUE_URL"] = c.QueueURL
		required["ENGINE_ALERT_QUEUE_URL"] = c.AlertQueueURL
		required["AWS_REGION"] = c.AWSRegion
	case TransportNATS:
		if c.NATSConsumer == "" && err == nil {
			c.NATSConsumer = "detection-engine-" + src.Name
		}
		if c.NATSSubject == "" && err == nil {
			c.NATSSubject = "samma.logs." + src.Name
		}
		if c.AlertSubject == "" && err == nil {
			c.AlertSubject = "samma.alerts." + src.Name
		}
		required["ENGINE_NATS_URL"] = c.NATSURL
		// Rules from a bucket still need AWS; the baked-in tree does not.
		if c.RulesBucket != "" {
			required["AWS_REGION"] = c.AWSRegion
		}
	default:
		problems = append(problems, fmt.Sprintf("ENGINE_TRANSPORT must be %q or %q, got %q",
			TransportSQS, TransportNATS, c.Transport))
	}
	for name, value := range required {
		if value == "" {
			problems = append(problems, name+" is required and not set")
		}
	}

	// The rules come from exactly one place. Both set is rejected rather than
	// given a precedence: a task definition that sets the bucket on top of
	// the image's ENGINE_RULES_DIR default almost certainly meant the bucket,
	// but "almost certainly" is not how a detection engine should pick its
	// ruleset. The Terraform unsets the one it does not use.
	switch {
	case c.RulesDir == "" && c.RulesBucket == "":
		problems = append(problems, "one of ENGINE_RULES_DIR or ENGINE_RULES_BUCKET is required and neither is set")
	case c.RulesDir != "" && c.RulesBucket != "":
		problems = append(problems, "ENGINE_RULES_DIR and ENGINE_RULES_BUCKET are both set; set exactly one")
	}

	c.Workers, err = getint(getenv, "ENGINE_WORKERS", DefaultWorkers)
	if err != nil {
		problems = append(problems, err.Error())
	} else if c.Workers < 1 {
		problems = append(problems, "ENGINE_WORKERS must be at least 1")
	}

	maxBytes, err := getint(getenv, "ENGINE_MAX_OBJECT_BYTES", DefaultMaxObjectBytes)
	if err != nil {
		problems = append(problems, err.Error())
	} else if maxBytes < 1 {
		problems = append(problems, "ENGINE_MAX_OBJECT_BYTES must be positive")
	}
	c.MaxObjectBytes = int64(maxBytes)

	c.MaxDecodeErrorRate, err = getfloat(getenv, "ENGINE_MAX_DECODE_ERROR_RATIO", DefaultMaxDecodeErrorRate)
	if err != nil {
		problems = append(problems, err.Error())
	} else if c.MaxDecodeErrorRate < 0 || c.MaxDecodeErrorRate > 1 {
		problems = append(problems, "ENGINE_MAX_DECODE_ERROR_RATIO must be between 0 and 1")
	}

	c.VisibilityBeat, err = getdur(getenv, "ENGINE_VISIBILITY_HEARTBEAT", DefaultVisibilityBeat)
	if err != nil {
		problems = append(problems, err.Error())
	} else if c.VisibilityBeat < time.Second {
		problems = append(problems, "ENGINE_VISIBILITY_HEARTBEAT must be at least 1s")
	}

	c.VisibilityTimeout, err = getdur(getenv, "ENGINE_VISIBILITY_TIMEOUT", DefaultVisibilityTimeout)
	if err != nil {
		problems = append(problems, err.Error())
	}

	c.MaxObjectDuration, err = getdur(getenv, "ENGINE_MAX_OBJECT_DURATION", DefaultMaxObjectDuration)
	if err != nil {
		problems = append(problems, err.Error())
	} else if c.MaxObjectDuration < time.Second {
		problems = append(problems, "ENGINE_MAX_OBJECT_DURATION must be at least 1s")
	}

	c.MaxAlertsPerObject, err = getint(getenv, "ENGINE_MAX_ALERTS_PER_OBJECT", DefaultMaxAlertsPerObject)
	if err != nil {
		problems = append(problems, err.Error())
	} else if c.MaxAlertsPerObject < 1 {
		problems = append(problems, "ENGINE_MAX_ALERTS_PER_OBJECT must be at least 1")
	}

	// A heartbeat at or past the visibility timeout means the message goes
	// visible between extensions, and two tasks process the same object.
	if c.VisibilityBeat > 0 && c.VisibilityTimeout > 0 && c.VisibilityBeat >= c.VisibilityTimeout {
		problems = append(problems, fmt.Sprintf(
			"ENGINE_VISIBILITY_HEARTBEAT (%s) must be shorter than ENGINE_VISIBILITY_TIMEOUT (%s)",
			c.VisibilityBeat, c.VisibilityTimeout))
	}

	if len(problems) > 0 {
		return Config{}, fmt.Errorf("invalid configuration:\n  - %s", strings.Join(problems, "\n  - "))
	}
	return c, nil
}

// FromOSEnv is the production entry point.
func FromOSEnv() (Config, error) { return FromEnv(os.Getenv) }

// getint returns an error rather than falling back to the default on a
// malformed value. Silently ignoring ENGINE_WORKERS=eight would run one
// worker and look deliberate.
func getint(getenv func(string) string, key string, def int) (int, error) {
	raw := strings.TrimSpace(getenv(key))
	if raw == "" {
		return def, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("%s %q is not an integer", key, raw)
	}
	return n, nil
}

func getfloat(getenv func(string) string, key string, def float64) (float64, error) {
	raw := strings.TrimSpace(getenv(key))
	if raw == "" {
		return def, nil
	}
	f, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		return 0, fmt.Errorf("%s %q is not a number", key, raw)
	}
	return f, nil
}

func getdur(getenv func(string) string, key string, def time.Duration) (time.Duration, error) {
	raw := strings.TrimSpace(getenv(key))
	if raw == "" {
		return def, nil
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("%s %q is not a duration", key, raw)
	}
	return d, nil
}
