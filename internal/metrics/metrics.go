// Package metrics declares the engine's Prometheus collectors.
//
// Two rules hold here, and the tests enforce both.
//
// First, every collector declared in this file must have an increment site in
// the code. A sibling service in this workspace registered five metrics it
// never touched; they rendered as flat zero lines, and a flat zero is
// indistinguishable from a healthy quiet period -- which is precisely the
// failure a detection engine cannot afford.
// TestMetrics_EveryCollectorHasAnIncrementSite is the guard.
//
// Second, no collector carries the log source as a label. The source is
// constant for the life of a task, so it is attached once at registration
// through prometheus.WrapRegistererWith in main. Putting it on each metric
// would mean threading it through every call site for no gain.
//
// Label cardinality ceiling: rule_id is bounded by the ruleset size, in the
// hundreds. Do not add the S3 key, the event index, or anything else
// unbounded -- that is the natural next request and it would be a mistake.
package metrics

import "github.com/prometheus/client_golang/prometheus"

var (
	// --- ruleset ---------------------------------------------------------

	RulesLoaded = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "detection_rules_loaded",
		Help: "Compiled rules currently loaded, by severity level.",
	}, []string{"level"})

	// --- queue -----------------------------------------------------------

	MessagesReceived = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "detection_messages_received_total",
		Help: "SQS messages received.",
	})

	MessageDisposition = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "detection_message_disposition_total",
		Help: "Messages by outcome: accepted, skipped, poison, transient.",
	}, []string{"disposition"})

	// ReceiveCount observes ApproximateReceiveCount.
	//
	// This is how you see messages walking toward the DLQ before they arrive.
	// A message being visibility-heartbeated for half an hour still reports a
	// receive count of 1, so depth alone does not show it.
	ReceiveCount = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "detection_message_receive_count",
		Help:    "ApproximateReceiveCount of received messages.",
		Buckets: []float64{1, 2, 3, 4, 5, 10},
	})

	TestEvents = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "detection_test_events_total",
		Help: "s3:TestEvent control messages seen.",
	})

	DeleteErrors = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "detection_delete_errors_total",
		Help: "Failures deleting a message whose alerts were already published.",
	})

	VisibilityExtensions = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "detection_visibility_extensions_total",
		Help: "Successful ChangeMessageVisibility heartbeats.",
	})

	VisibilityErrors = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "detection_visibility_errors_total",
		Help: "Failed heartbeats, each of which abandons its message.",
	})

	// --- objects and events ----------------------------------------------

	ObjectsProcessed = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "detection_objects_processed_total",
		Help: "S3 objects read to completion.",
	})

	ObjectBytes = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "detection_object_bytes",
		Help:    "Compressed size of processed objects.",
		Buckets: prometheus.ExponentialBuckets(1024, 4, 10),
	})

	ObjectDuration = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "detection_object_duration_seconds",
		Help:    "Wall time to process one object.",
		Buckets: []float64{0.1, 0.5, 1, 5, 15, 60, 300, 900, 2700},
	})

	Events = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "detection_events_total",
		Help: "Records decoded and evaluated.",
	})

	EventsUndecodable = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "detection_events_undecodable_total",
		Help: "Records that could not be decoded and were skipped.",
	})

	// --- detection --------------------------------------------------------

	Matches = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "detection_matches_total",
		Help: "Rule matches.",
	}, []string{"rule_id", "level"})

	// RuleErrors should always be zero. Compile rejects every load-time
	// detectable cause and the decoder normalises the number types that break
	// sigma-go's comparators, so a non-zero value is a bug or a dependency
	// regression. Alarm on it.
	RuleErrors = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "detection_rule_errors_total",
		Help: "Rules that errored or panicked while evaluating an event.",
	}, []string{"rule_id"})

	AlertsPublished = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "detection_alerts_published_total",
		Help: "Alerts confirmed durable on the alert queue.",
	})

	AlertsOversize = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "detection_alerts_oversize_total",
		Help: "Alerts whose event body was dropped to fit the SQS message limit.",
	})

	AlertsRejected = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "detection_alerts_rejected_total",
		Help: "Alerts SQS refused permanently, by error code.",
	}, []string{"code"})

	PublishErrors = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "detection_publish_errors_total",
		Help: "Alert publish failures, by reason.",
	}, []string{"reason"})

	// --- faults -----------------------------------------------------------

	Poison = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "detection_poison_total",
		Help: "Permanently unprocessable messages, by reason.",
	}, []string{"reason"})

	// Panics should never be non-zero. sigma-go panics rather than erroring on
	// several inputs, and an unrecovered panic here would crash-loop the task
	// with detection off for the whole source. Alarm on it.
	Panics = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "detection_panics_total",
		Help: "Recovered panics while processing a message.",
	})

	BuildInfo = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "detection_build_info",
		Help: "Always 1; labels carry the running version.",
	}, []string{"version", "commit"})
)

// collectors is the registration list. Keep it in sync with the vars above;
// TestMetrics_EveryCollectorIsRegistered enforces it.
func collectors() []prometheus.Collector {
	return []prometheus.Collector{
		RulesLoaded, MessagesReceived, MessageDisposition, ReceiveCount, TestEvents,
		DeleteErrors, VisibilityExtensions, VisibilityErrors,
		ObjectsProcessed, ObjectBytes, ObjectDuration, Events, EventsUndecodable,
		Matches, RuleErrors, AlertsPublished, AlertsOversize, AlertsRejected, PublishErrors,
		Poison, Panics, BuildInfo,
	}
}

// Register attaches every collector.
//
// The caller wraps the registerer with the log_source label, so the source
// appears on all of them without being threaded through call sites.
func Register(reg prometheus.Registerer) error {
	for _, c := range collectors() {
		if err := reg.Register(c); err != nil {
			return err
		}
	}
	return nil
}
