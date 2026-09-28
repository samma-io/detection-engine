package decode

import (
	"bufio"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// DefaultMaxLineBytes caps one record.
//
// A CloudTrail record with a large requestParameters can be hundreds of
// kilobytes, so the cap has to be generous; it exists only so that a
// corrupted object without newlines cannot be read into memory in full.
const DefaultMaxLineBytes = 8 << 20 // 8 MiB

// gzipMagic is the first two bytes of every gzip member.
var gzipMagic = []byte{0x1f, 0x8b}

// ErrLineTooLong marks a record past the line cap. It is a per-record decode
// error, not an object failure.
var ErrLineTooLong = errors.New("record exceeds the maximum line length")

// RecordFunc receives each decoded record with its zero-based index within the
// object. Returning an error stops the decode and is returned to the caller.
type RecordFunc func(index int, event map[string]any) error

// BadRecordFunc receives records that could not be decoded. Returning an error
// stops the decode; returning nil continues, which is how the caller
// implements "skip one bad line, fail on a flood".
type BadRecordFunc func(index int, err error) error

// Records streams an object body.
//
// Vector's filtered sinks are configured as compression: gzip, codec: json,
// framing: newline_delimited, so the expected shape is gzipped NDJSON. Both
// the compression and the framing are sniffed rather than assumed, because a
// change to the Vector config would otherwise turn every object into a decode
// failure with a misleading error.
//
// Nothing here buffers the whole object. A 500 MB object costs one line of
// memory at a time, which is what makes the size guard in the engine a
// safeguard against unbounded *time* rather than unbounded memory.
func Records(ctx context.Context, r io.Reader, maxLine int, onRecord RecordFunc, onBad BadRecordFunc) error {
	if maxLine <= 0 {
		maxLine = DefaultMaxLineBytes
	}

	br := bufio.NewReaderSize(r, 64<<10)

	// Sniff the gzip magic bytes rather than trusting the ".gz" suffix. The
	// key is chosen by Vector, not by us, and a suffix is a naming convention
	// while the magic bytes are the actual format.
	magic, err := br.Peek(2)
	switch {
	case errors.Is(err, io.EOF):
		// An empty object is not an error. Vector can roll an object on its
		// batch timeout with nothing in it.
		return nil
	case err != nil:
		return fmt.Errorf("reading object header: %w", err)
	}

	var body io.Reader = br
	if len(magic) == 2 && magic[0] == gzipMagic[0] && magic[1] == gzipMagic[1] {
		gz, err := gzip.NewReader(br)
		if err != nil {
			return fmt.Errorf("opening gzip stream: %w", err)
		}
		defer func() { _ = gz.Close() }()
		// Multistream is on by default and is what we want: Vector can
		// concatenate gzip members within one object.
		body = gz
	}

	inner := bufio.NewReaderSize(body, 64<<10)

	// Sniff the framing. A leading "[" means the encoder emitted one JSON
	// array instead of newline-delimited objects, which is what a change to
	// Vector's framing setting would produce.
	if first, err := peekFirstNonSpace(inner); err == nil && first == '[' {
		return jsonArray(ctx, inner, onRecord, onBad)
	} else if err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("sniffing framing: %w", err)
	}

	return ndjson(ctx, inner, maxLine, onRecord, onBad)
}

// ndjson decodes newline-delimited JSON, the production path.
func ndjson(ctx context.Context, r *bufio.Reader, maxLine int, onRecord RecordFunc, onBad BadRecordFunc) error {
	index := -1
	for {
		// Checked per record rather than per object: on SIGTERM we want to
		// stop within one record, not after a 500 MB object.
		if err := ctx.Err(); err != nil {
			return err
		}

		line, tooLong, readErr := readLine(r, maxLine)

		switch {
		case tooLong:
			index++
			if err := onBad(index, ErrLineTooLong); err != nil {
				return err
			}
		case len(line) > 0:
			// A truncated final line still carries a record, so it is
			// decoded before the EOF below is honoured.
			index++
			if err := handle(index, line, onRecord, onBad); err != nil {
				return err
			}
		}

		switch {
		case readErr == nil:
			continue
		case errors.Is(readErr, io.EOF):
			return nil
		default:
			return fmt.Errorf("reading record %d: %w", index+1, readErr)
		}
	}
}

// jsonArray decodes a single top-level JSON array by streaming its elements,
// so a large array is not held in memory as one value.
func jsonArray(ctx context.Context, r io.Reader, onRecord RecordFunc, onBad BadRecordFunc) error {
	dec := json.NewDecoder(r)
	if _, err := dec.Token(); err != nil { // consume '['
		return fmt.Errorf("reading array start: %w", err)
	}
	index := -1
	for dec.More() {
		if err := ctx.Err(); err != nil {
			return err
		}
		index++
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			// A malformed element leaves the decoder's position unusable, so
			// unlike NDJSON this cannot skip and continue.
			return fmt.Errorf("reading array element %d: %w", index, err)
		}
		if err := handle(index, raw, onRecord, onBad); err != nil {
			return err
		}
	}
	return nil
}

func handle(index int, raw []byte, onRecord RecordFunc, onBad BadRecordFunc) error {
	event, err := unmarshalEvent(raw)
	if err != nil {
		// A literal "null" line decodes without error into a nil map, which
		// would then match no rule and look like a clean evaluation, so
		// unmarshalEvent rejects anything that is not an object.
		return onBad(index, fmt.Errorf("record is not a JSON object: %w", err))
	}
	return onRecord(index, event)
}

// readLine returns one line without its terminator, capping the length.
//
// bufio.Scanner is not used because it cannot continue after
// bufio.ErrTooLong: one pathological line would abandon every record after it
// in the object. Here an over-long line is reported via tooLong and the reader
// is left positioned at the start of the next line, so decoding continues.
//
// The bytes of an over-long line are discarded as they are read rather than
// accumulated, which is what keeps a newline-free object from being read into
// memory in full.
func readLine(r *bufio.Reader, maxLine int) (line []byte, tooLong bool, err error) {
	for {
		chunk, rerr := r.ReadSlice('\n')

		if !tooLong && len(line)+len(chunk) > maxLine {
			// Drop what we have; from here we are only scanning for the
			// terminator. ReadSlice has already consumed this chunk, so there
			// is nothing to skip separately -- an earlier version drained to
			// the next newline here and ate the following good record.
			tooLong = true
			line = nil
		}
		if !tooLong {
			line = append(line, chunk...)
		}

		if rerr == nil { // consumed through the newline
			return trimEOL(line), tooLong, nil
		}
		if errors.Is(rerr, bufio.ErrBufferFull) {
			continue
		}
		return trimEOL(line), tooLong, rerr
	}
}

func trimEOL(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r') {
		b = b[:len(b)-1]
	}
	// Blank lines are common at the end of a rolled object and are not
	// records; the caller sees them as zero-length and skips them.
	if len(b) == 0 {
		return nil
	}
	return b
}

func peekFirstNonSpace(r *bufio.Reader) (byte, error) {
	for n := 1; n <= 512; n++ {
		buf, err := r.Peek(n)
		if err != nil && len(buf) < n {
			if len(buf) == 0 {
				return 0, err
			}
		}
		c := buf[len(buf)-1]
		if c != ' ' && c != '\t' && c != '\n' && c != '\r' {
			return c, nil
		}
		if err != nil {
			return 0, err
		}
	}
	return 0, errors.New("object begins with more than 512 bytes of whitespace")
}

// errNotAnObject marks a record that decoded but is not a JSON object.
var errNotAnObject = errors.New("record is not a JSON object")
