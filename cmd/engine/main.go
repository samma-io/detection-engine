// Command engine is the Sigma detection engine.
//
// One image serves every log source. ENGINE_LOG_SOURCE selects which queue to
// drain and which rules prefix to load, so the four ECS services differ only
// in their environment.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/samma-io/detection-engine/internal/alert"
	"github.com/samma-io/detection-engine/internal/awsadapt"
	"github.com/samma-io/detection-engine/internal/config"
	"github.com/samma-io/detection-engine/internal/decode"
	"github.com/samma-io/detection-engine/internal/engine"
	"github.com/samma-io/detection-engine/internal/health"
	"github.com/samma-io/detection-engine/internal/metrics"
	"github.com/samma-io/detection-engine/internal/publisher"
	"github.com/samma-io/detection-engine/internal/rules"
	"github.com/samma-io/detection-engine/internal/runtime/logging"
)

// Injected at build time with -ldflags.
var (
	version = "dev"
	commit  = "none"
)

func main() {
	if err := run(); err != nil {
		// The logger may not exist yet, so report plainly.
		fmt.Fprintln(os.Stderr, "fatal:", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.FromOSEnv()
	if err != nil {
		return err
	}

	log := logging.New(os.Stdout, logging.ParseLevel(cfg.LogLevel))
	slog.SetDefault(log)
	log = log.With("log_source", cfg.Source.Name)

	// The rules come from the tree baked into the image unless the task is
	// pointed at a bucket. Both go through the same Store interface, so the
	// loader and everything after it do not know which.
	var (
		rulesStore rules.Store
		rulesAt    string
	)
	if cfg.RulesDir != "" {
		rulesStore = rules.FSStore{Root: cfg.RulesDir}
		rulesAt = cfg.RulesDir + "/" + cfg.RulePrefix()
	} else {
		rulesAt = "s3://" + cfg.RulesBucket + "/" + cfg.RulePrefix()
	}

	log.Info("starting",
		"version", version, "commit", commit,
		"queue", cfg.QueueURL, "alert_queue", cfg.AlertQueueURL,
		"rules_source", cfg.RulesSource(), "rules", rulesAt,
		"workers", cfg.Workers)

	// SIGTERM is what ECS sends before SIGKILL. Fargate's stopTimeout caps
	// how long we get, so shutdown abandons in-flight work rather than trying
	// to finish it.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// The log source is a constant for the life of the task, so it is
	// attached once here rather than threaded through every call site.
	registry := prometheus.NewRegistry()
	registry.MustRegister(collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	if err := metrics.Register(prometheus.WrapRegistererWith(
		prometheus.Labels{"log_source": cfg.Source.Name}, registry)); err != nil {
		return fmt.Errorf("registering metrics: %w", err)
	}
	metrics.BuildInfo.WithLabelValues(version, commit).Set(1)

	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(cfg.AWSRegion))
	if err != nil {
		return fmt.Errorf("aws config: %w", err)
	}

	s3Client := s3.NewFromConfig(awsCfg, func(o *s3.Options) {
		if cfg.S3EndpointURL != "" {
			o.BaseEndpoint = &cfg.S3EndpointURL
			// localstack does not serve virtual-hosted-style buckets.
			o.UsePathStyle = true
		}
	})
	sqsClient := sqs.NewFromConfig(awsCfg, func(o *sqs.Options) {
		if cfg.SQSEndpointURL != "" {
			o.BaseEndpoint = &cfg.SQSEndpointURL
		}
	})

	objects := &awsadapt.Objects{Client: s3Client}
	if rulesStore == nil {
		rulesStore = objects
	}

	// The admin server comes up before the rules load, so /readyz can report
	// "not ready" while loading and ECS sees a task that started but is not
	// taking traffic, rather than a task that never started at all.
	healthSrv := &health.Server{}
	mux := http.NewServeMux()
	healthSrv.Register(mux)
	mux.Handle("/metrics", promhttp.HandlerFor(registry, promhttp.HandlerOpts{}))

	admin := &http.Server{Addr: cfg.MetricsAddr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		log.Info("admin server listening", "addr", cfg.MetricsAddr)
		if err := admin.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Error("admin server", "err", err)
		}
	}()

	loaded, err := rules.Load(ctx, rulesStore, cfg.RulesBucket, cfg.RulePrefix(), cfg.Source.ConfigFile, log)
	if err != nil {
		// Fail closed. An engine with no rules drains its queue, matches
		// nothing, deletes every message and makes queue depth go DOWN --
		// there is no dashboard that tells that apart from a quiet week.
		return fmt.Errorf("loading rules: %w", err)
	}
	loaded.LogLoaded(log)
	for level, n := range loaded.LevelCounts() {
		metrics.RulesLoaded.WithLabelValues(level).Set(float64(n))
	}

	// Served after loading so the payload is never a half-built ruleset. This
	// is what answers "is this task running the ruleset that is in git?"
	// without a redeploy.
	mux.HandleFunc("/rules", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"log_source": cfg.Source.Name,
			"count":      loaded.Set.Len(),
			"rules":      loaded.Set.All(),
		})
	})

	proc := &engine.Processor{
		Source:  cfg.Source,
		Objects: objects,
		Rules:   loaded.Set,
		NewSink: func() engine.AlertSink {
			return &publisher.Batcher{
				Sender: &awsadapt.AlertQueue{Client: sqsClient, QueueURL: cfg.AlertQueueURL},
				Log:    log,
				OnOversize: func(alert.Alert) {
					metrics.AlertsOversize.Inc()
				},
				OnPermanentReject: func(_ context.Context, out publisher.Outbound, r publisher.Rejection) error {
					// Nowhere durable to put it, so it is recorded in the log
					// and counted. The alert is lost; the counter is what
					// makes that visible rather than silent.
					metrics.AlertsRejected.WithLabelValues(r.Code).Inc()
					log.Error("alert permanently rejected and dropped",
						"alert_id", out.AlertID, "code", r.Code, "message", r.Message)
					return nil
				},
			}
		},
		Limits: engine.Limits{
			MaxObjectBytes:     cfg.MaxObjectBytes,
			MaxObjectDuration:  cfg.MaxObjectDuration,
			MaxLineBytes:       decode.DefaultMaxLineBytes,
			MaxDecodeErrorRate: cfg.MaxDecodeErrorRate,
			MaxAlertsPerObject: cfg.MaxAlertsPerObject,
		},
		Now: time.Now,
		Log: log,
	}

	healthSrv.SetReady(true)

	runCfg := engine.RunConfig{
		WaitSeconds:       20, // long polling; the queue is configured for it
		VisibilityTimeout: cfg.VisibilityTimeout,
		HeartbeatInterval: cfg.VisibilityBeat,
	}

	var wg sync.WaitGroup
	for i := 0; i < cfg.Workers; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			wlog := log.With("worker", n)
			if err := engine.Run(ctx, &awsadapt.Queue{Client: sqsClient, QueueURL: cfg.QueueURL}, proc, runCfg, wlog); err != nil {
				wlog.Error("worker exited", "err", err)
			}
		}(i)
	}

	<-ctx.Done()
	log.Info("shutdown signal received")
	healthSrv.SetReady(false)

	wg.Wait()

	shutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := admin.Shutdown(shutCtx); err != nil {
		log.Error("admin shutdown", "err", err)
	}
	log.Info("exited")
	return nil
}
