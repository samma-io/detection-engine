package natsadapt_test

import (
	"context"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/samma-io/detection-engine/internal/natsadapt"
	"github.com/samma-io/detection-engine/internal/publisher"
)

// jetStream starts an in-process JetStream server with the two streams from
// the transport contract.
func jetStream(t *testing.T) jetstream.JetStream {
	t.Helper()
	srv, err := server.NewServer(&server.Options{Port: -1, JetStream: true, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	go srv.Start()
	if !srv.ReadyForConnections(5 * time.Second) {
		t.Fatal("nats server did not start")
	}
	t.Cleanup(srv.Shutdown)

	nc, err := nats.Connect(srv.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(nc.Close)
	js, err := jetstream.New(nc)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for name, subj := range map[string]string{"SIEM_LOGS": "samma.logs.>", "SIEM_ALERTS": "samma.alerts.>"} {
		if _, err := js.CreateStream(ctx, jetstream.StreamConfig{Name: name, Subjects: []string{subj}}); err != nil {
			t.Fatal(err)
		}
	}
	return js
}

func TestLogs_ReceiveCarriesStreamProvenanceAndDeleteAcks(t *testing.T) {
	js := jetStream(t)
	ctx := context.Background()

	if _, err := js.Publish(ctx, "samma.logs.workspace", []byte(`{"a":1}`)); err != nil {
		t.Fatal(err)
	}
	cons, err := js.CreateConsumer(ctx, "SIEM_LOGS", jetstream.ConsumerConfig{
		Durable: "detection-engine-workspace", FilterSubject: "samma.logs.workspace",
		AckPolicy: jetstream.AckExplicitPolicy,
	})
	if err != nil {
		t.Fatal(err)
	}

	q := &natsadapt.Logs{Consumer: cons, Stream: "SIEM_LOGS"}
	msgs, err := q.Receive(ctx, 1, 1)
	if err != nil || len(msgs) != 1 {
		t.Fatalf("Receive = %d msgs, %v", len(msgs), err)
	}
	m := msgs[0]
	if m.Inline == nil || m.Inline.Ref.Bucket != "nats:SIEM_LOGS" || m.Inline.Ref.Key != "samma.logs.workspace/1" {
		t.Fatalf("inline = %+v", m.Inline)
	}
	if string(m.Inline.Body) != `{"a":1}` {
		t.Errorf("body = %q", m.Inline.Body)
	}
	if err := q.ExtendVisibility(ctx, m.ReceiptHandle, 300); err != nil {
		t.Errorf("ExtendVisibility: %v", err)
	}
	if err := q.Delete(ctx, m.ReceiptHandle); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	info, err := cons.Info(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if info.NumAckPending != 0 || info.NumPending != 0 {
		t.Errorf("after ack: ack pending %d, pending %d", info.NumAckPending, info.NumPending)
	}
}

func TestAlerts_RepublishedAlertIsDeduplicatedByTheServer(t *testing.T) {
	js := jetStream(t)
	ctx := context.Background()
	a := &natsadapt.Alerts{JS: js, Subject: "samma.alerts.workspace"}

	out := []publisher.Outbound{{ID: "0", Body: `{"id":"abc"}`, AlertID: "abc"}}
	for i := 0; i < 2; i++ {
		rej, err := a.SendBatch(ctx, out)
		if err != nil || len(rej) != 0 {
			t.Fatalf("SendBatch: %v %v", rej, err)
		}
	}

	s, err := js.Stream(ctx, "SIEM_ALERTS")
	if err != nil {
		t.Fatal(err)
	}
	info, err := s.Info(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if info.State.Msgs != 1 {
		t.Errorf("alerts in stream = %d, want 1", info.State.Msgs)
	}
}
