package decode_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/samma-io/detection-engine/internal/decode"
)

func gz(t *testing.T, s string) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	if _, err := w.Write([]byte(s)); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// collect runs Records and gathers the outcome, skipping bad records the way
// the engine's lenient path does.
func collect(t *testing.T, body []byte) (events []map[string]any, bad int, err error) {
	t.Helper()
	err = decode.Records(context.Background(), bytes.NewReader(body), 0,
		func(_ int, e map[string]any) error { events = append(events, e); return nil },
		func(_ int, _ error) error { bad++; return nil },
	)
	return events, bad, err
}

// ---------------------------------------------------------------- notification

func TestParseNotification_TestEventIsRecognised(t *testing.T) {
	// S3 sends this once when a notification is configured. Treating it as a
	// malformed body would park it in the DLQ on day one of every new lane.
	body := `{"Service":"Amazon S3","Event":"s3:TestEvent","Time":"2026-09-02T10:00:00.000Z",
	          "Bucket":"filtered-logs","RequestId":"X","HostId":"Y"}`
	n, err := decode.ParseNotification([]byte(body))
	if err != nil {
		t.Fatalf("ParseNotification: %v", err)
	}
	if !n.TestEvent {
		t.Error("TestEvent = false, want true")
	}
	if len(n.Objects) != 0 {
		t.Errorf("Objects = %v, want none", n.Objects)
	}
}

func TestParseNotification_URLEncodedKeyIsDecoded(t *testing.T) {
	// Every key in the filtered bucket contains "date=", which S3 delivers as
	// "date%3D". A service that forgot to unescape would 404 on every object.
	body := `{"Records":[{"eventName":"ObjectCreated:Put","s3":{
	           "bucket":{"name":"filtered-1-us-east-1"},
	           "object":{"key":"aws/date%3D2026-09-02/my+file.ndjson.gz","size":42}}}]}`
	n, err := decode.ParseNotification([]byte(body))
	if err != nil {
		t.Fatalf("ParseNotification: %v", err)
	}
	if len(n.Objects) != 1 {
		t.Fatalf("Objects = %d, want 1", len(n.Objects))
	}
	// "+" is a literal space in S3's form encoding, not a plus.
	if got, want := n.Objects[0].Key, "aws/date=2026-09-02/my file.ndjson.gz"; got != want {
		t.Errorf("Key = %q, want %q", got, want)
	}
	if n.Objects[0].Size != 42 {
		t.Errorf("Size = %d, want 42", n.Objects[0].Size)
	}
}

func TestParseNotification_MalformedBodyIsAnErrorNotAnEmptyResult(t *testing.T) {
	// Returning an empty notification would let the caller delete the message
	// and lose the object reference with nothing recording it.
	for _, body := range []string{"", "   ", "{ not json", `{"Foo":1}`} {
		if _, err := decode.ParseNotification([]byte(body)); err == nil {
			t.Errorf("body %q should be an error", body)
		}
	}
}

func TestParseNotification_RecordWithoutKeyIsAnError(t *testing.T) {
	body := `{"Records":[{"s3":{"bucket":{"name":"b"},"object":{"size":1}}}]}`
	if _, err := decode.ParseNotification([]byte(body)); err == nil {
		t.Fatal("a record with no key must be an error")
	}
}

func TestParseNotification_MultipleRecordsAreAllReturned(t *testing.T) {
	body := `{"Records":[
	  {"s3":{"bucket":{"name":"b"},"object":{"key":"aws/date%3D2026-09-02/a.gz","size":1}}},
	  {"s3":{"bucket":{"name":"b"},"object":{"key":"aws/date%3D2026-09-02/b.gz","size":2}}}]}`
	n, err := decode.ParseNotification([]byte(body))
	if err != nil {
		t.Fatalf("ParseNotification: %v", err)
	}
	if len(n.Objects) != 2 {
		t.Fatalf("Objects = %d, want 2", len(n.Objects))
	}
}

// ---------------------------------------------------------------- records

func TestRecords_GzipIsDetectedByMagicBytesNotSuffix(t *testing.T) {
	// The key is chosen by Vector. Sniffing the format means a Vector config
	// change turns into a working decode, not a wall of decode errors.
	events, bad, err := collect(t, gz(t, `{"eventName":"ConsoleLogin"}`+"\n"))
	if err != nil {
		t.Fatalf("Records: %v", err)
	}
	if bad != 0 || len(events) != 1 {
		t.Fatalf("events=%d bad=%d, want 1/0", len(events), bad)
	}
	if events[0]["eventName"] != "ConsoleLogin" {
		t.Errorf("eventName = %v", events[0]["eventName"])
	}
}

func TestRecords_UncompressedNDJSONAlsoDecodes(t *testing.T) {
	events, bad, err := collect(t, []byte("{\"a\":1}\n{\"a\":2}\n"))
	if err != nil {
		t.Fatalf("Records: %v", err)
	}
	if len(events) != 2 || bad != 0 {
		t.Fatalf("events=%d bad=%d, want 2/0", len(events), bad)
	}
}

func TestRecords_JSONArrayFramingAlsoDecodes(t *testing.T) {
	// Guards against a change to Vector's framing setting.
	events, bad, err := collect(t, []byte(`[{"a":1},{"a":2},{"a":3}]`))
	if err != nil {
		t.Fatalf("Records: %v", err)
	}
	if len(events) != 3 || bad != 0 {
		t.Fatalf("events=%d bad=%d, want 3/0", len(events), bad)
	}
}

func TestRecords_OneBadLineDoesNotAbandonTheObject(t *testing.T) {
	// The whole point: a single corrupt line must not cost the other records.
	// Failing the object here would park thousands of good records in a DLQ.
	body := gz(t, "{\"a\":1}\n{ not json\n{\"a\":3}\n")
	events, bad, err := collect(t, body)
	if err != nil {
		t.Fatalf("Records: %v", err)
	}
	if len(events) != 2 {
		t.Errorf("events = %d, want 2 good records", len(events))
	}
	if bad != 1 {
		t.Errorf("bad = %d, want 1", bad)
	}
}

func TestRecords_BadRecordFuncCanFailTheWholeObject(t *testing.T) {
	// This is the seam the engine uses to enforce the decode error ratio.
	stop := errors.New("too many bad records")
	var seen int
	err := decode.Records(context.Background(), bytes.NewReader([]byte("{ bad\n{\"a\":1}\n")), 0,
		func(int, map[string]any) error { seen++; return nil },
		func(int, error) error { return stop },
	)
	if !errors.Is(err, stop) {
		t.Fatalf("err = %v, want %v", err, stop)
	}
	if seen != 0 {
		t.Errorf("decoding should have stopped before the good record, saw %d", seen)
	}
}

func TestRecords_IndexIsTheRecordPositionInTheObject(t *testing.T) {
	// The index is part of the deterministic alert id, so an off-by-one here
	// would break dedup across redelivery.
	var idx []int
	err := decode.Records(context.Background(),
		bytes.NewReader([]byte("{\"a\":0}\n{ bad\n{\"a\":2}\n")), 0,
		func(i int, _ map[string]any) error { idx = append(idx, i); return nil },
		func(int, error) error { return nil },
	)
	if err != nil {
		t.Fatalf("Records: %v", err)
	}
	if len(idx) != 2 || idx[0] != 0 || idx[1] != 2 {
		t.Errorf("indexes = %v, want [0 2]", idx)
	}
}

func TestRecords_EmptyObjectIsNotAnError(t *testing.T) {
	// Vector rolls an object on its batch timeout even with nothing in it.
	events, bad, err := collect(t, gz(t, ""))
	if err != nil {
		t.Fatalf("Records: %v", err)
	}
	if len(events) != 0 || bad != 0 {
		t.Errorf("events=%d bad=%d, want 0/0", len(events), bad)
	}

	if _, _, err := collect(t, nil); err != nil {
		t.Errorf("zero-byte object: %v", err)
	}
}

func TestRecords_BlankLinesAreNotRecords(t *testing.T) {
	events, bad, err := collect(t, []byte("{\"a\":1}\n\n\n{\"a\":2}\n"))
	if err != nil {
		t.Fatalf("Records: %v", err)
	}
	if len(events) != 2 || bad != 0 {
		t.Errorf("events=%d bad=%d, want 2/0", len(events), bad)
	}
}

func TestRecords_FinalLineWithoutNewlineIsStillDecoded(t *testing.T) {
	events, _, err := collect(t, []byte("{\"a\":1}\n{\"a\":2}"))
	if err != nil {
		t.Fatalf("Records: %v", err)
	}
	if len(events) != 2 {
		t.Errorf("events = %d, want 2 -- a truncated final line still carries a record", len(events))
	}
}

func TestRecords_JSONNullLineIsABadRecordNotACleanEvaluation(t *testing.T) {
	// "null" unmarshals into a nil map without error, which would then match
	// no rule and look like a successful evaluation.
	events, bad, err := collect(t, []byte("null\n{\"a\":1}\n"))
	if err != nil {
		t.Fatalf("Records: %v", err)
	}
	if len(events) != 1 || bad != 1 {
		t.Errorf("events=%d bad=%d, want 1/1", len(events), bad)
	}
}

func TestRecords_OverlongLineIsOneBadRecordAndDecodingContinues(t *testing.T) {
	// bufio.Scanner cannot continue past ErrTooLong, which is why this decoder
	// does not use it: one pathological line would discard every record after
	// it in the object.
	long := "{\"pad\":\"" + strings.Repeat("x", 4096) + "\"}"
	body := []byte("{\"a\":1}\n" + long + "\n{\"a\":3}\n")
	var events []map[string]any
	var bad int
	err := decode.Records(context.Background(), bytes.NewReader(body), 1024,
		func(_ int, e map[string]any) error { events = append(events, e); return nil },
		func(_ int, err error) error {
			if !errors.Is(err, decode.ErrLineTooLong) {
				t.Errorf("bad record err = %v, want ErrLineTooLong", err)
			}
			bad++
			return nil
		},
	)
	if err != nil {
		t.Fatalf("Records: %v", err)
	}
	if len(events) != 2 {
		t.Errorf("events = %d, want 2 (the records either side of the long line)", len(events))
	}
	if bad != 1 {
		t.Errorf("bad = %d, want 1", bad)
	}
}

func TestRecords_LargeRecordUnderTheCapIsFine(t *testing.T) {
	// A CloudTrail record with a big requestParameters is normal traffic, and
	// bufio's default 4 KiB slice must not truncate it.
	big := "{\"requestParameters\":\"" + strings.Repeat("y", 200_000) + "\"}"
	events, bad, err := collect(t, gz(t, big+"\n"))
	if err != nil {
		t.Fatalf("Records: %v", err)
	}
	if len(events) != 1 || bad != 0 {
		t.Fatalf("events=%d bad=%d, want 1/0", len(events), bad)
	}
}

func TestRecords_CancelledContextStopsMidObject(t *testing.T) {
	// On SIGTERM the engine must stop within a record, not after a 500 MB
	// object.
	ctx, cancel := context.WithCancel(context.Background())
	body := []byte(strings.Repeat("{\"a\":1}\n", 100))
	var seen int
	err := decode.Records(ctx, bytes.NewReader(body), 0,
		func(int, map[string]any) error {
			seen++
			if seen == 3 {
				cancel()
			}
			return nil
		},
		func(int, error) error { return nil },
	)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if seen != 3 {
		t.Errorf("seen = %d, want to stop right after the third record", seen)
	}
}

func TestRecords_CorruptGzipIsAnObjectLevelError(t *testing.T) {
	// Unlike a bad line, a broken gzip header means nothing in the object can
	// be read, so it must fail the object rather than silently yield zero
	// records.
	body := append([]byte{0x1f, 0x8b}, []byte("garbage")...)
	if _, _, err := collect(t, body); err == nil {
		t.Fatal("a corrupt gzip stream must fail the object")
	}
}
