package export

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/thelemail/export-tool/internal/api"
	"github.com/thelemail/export-tool/internal/attframe"
	"github.com/thelemail/export-tool/internal/crypto"
)

const (
	checkpointVersion = 2
	maxPointerRefresh = 5
)

var ErrIncomplete = errors.New("export incomplete")

type Exporter struct {
	Client              *api.Client
	Vault               *crypto.Vault
	OutDir              string
	Session             string
	EncryptedPrivateKey string
}

type folder struct {
	name   string
	params url.Values
}

func folders() []folder {
	mk := func(kv ...string) url.Values {
		v := url.Values{}
		for i := 0; i+1 < len(kv); i += 2 {
			v.Set(kv[i], kv[i+1])
		}
		v.Set("sort", "oldest")
		v.Set("limit", "50")
		return v
	}
	return []folder{
		{"inbox", mk("mailbox", "inbox", "direction", "received")},
		{"sent", mk("direction", "sent")},
		{"archive", mk("mailbox", "archive")},
		{"spam", mk("mailbox", "spam")},
		{"trash", mk("mailbox", "trash")},
		{"starred", mk("starred", "true")},
	}
}

type checkpoint struct {
	Version int                     `json:"version"`
	Cursors map[string]string       `json:"cursors"`
	Done    map[string]bool         `json:"done"`
	Offsets map[string]int64        `json:"offsets"`
	Totals  map[string]folderTotals `json:"totals"`
	Pending map[string][]failure    `json:"pending"`
	Labels  map[string]labelRecord  `json:"labels,omitempty"`
	Lost    []failure               `json:"lost"`
}

func (e *Exporter) Run(ctx context.Context) error {
	if err := os.MkdirAll(e.OutDir, 0o700); err != nil {
		return err
	}
	cp := e.loadCheckpoint()
	stop := e.startHeartbeat(ctx)
	defer stop()

	org, err := e.loadOrganization(ctx)
	if err != nil {
		return fmt.Errorf("load folders and labels: %w", err)
	}
	all := append(folders(), customFolders(org)...)

	worthAnotherSweep := map[string]bool{}
	for _, f := range all {
		if !cp.Done[f.name] {
			fmt.Printf("Exporting %s...\n", f.name)
			if err := e.exportFolder(ctx, f, cp); err != nil {
				return fmt.Errorf("export %s: %w", f.name, err)
			}
		}
		recovered, err := e.retryPending(ctx, f, cp)
		if err != nil {
			return fmt.Errorf("retry %s: %w", f.name, err)
		}
		worthAnotherSweep[f.name] = recovered > 0
		totals := cp.Totals[f.name]
		fmt.Printf("  %s: %d messages, %d attachments\n", f.name, totals.Messages, totals.Attachments)
	}

	for _, f := range all {
		if len(cp.Pending[f.name]) == 0 || !worthAnotherSweep[f.name] {
			continue
		}
		if _, err := e.retryPending(ctx, f, cp); err != nil {
			return fmt.Errorf("retry %s: %w", f.name, err)
		}
	}

	if err := e.writeKeyMaterial(); err != nil {
		return err
	}
	if err := e.writeSettings(ctx); err != nil {
		return err
	}
	if err := e.writeOrganization(org, cp); err != nil {
		return err
	}

	r := buildReport(cp, all, time.Now().UTC())
	if err := writeReport(e.OutDir, r); err != nil {
		return err
	}
	if !r.Complete {
		e.printIncomplete(r)
		return ErrIncomplete
	}
	if e.Session != "" {
		if err := e.Client.ExportComplete(ctx, e.Session); err != nil {
			fmt.Fprintf(os.Stderr, "warning: could not close the export session: %v\n", err)
		}
	}
	fmt.Printf("Done. Files written to %s\n", e.OutDir)
	return nil
}

func (e *Exporter) printIncomplete(r report) {
	fmt.Println()
	fmt.Printf("Incomplete. %d could not be fetched, %d could not be read.\n", len(r.Pending), len(r.Lost))
	printFailures("could not fetch", r.Pending)
	printFailures("could not read", r.Lost)
	fmt.Printf("\nAll of it is listed in %s.\n", filepath.Join(e.OutDir, "export-report.json"))
	if len(r.Pending) > 0 {
		fmt.Println("Re-run the same command with the same --out to retry those.")
	}
	fmt.Println("The export session is still open, so a scheduled deletion stays on hold.")
}

func printFailures(label string, items []failure) {
	const shown = 10
	for i, f := range items {
		if i == shown {
			fmt.Printf("  ... and %d more\n", len(items)-shown)
			break
		}
		where := f.MessageID
		if f.AttachmentID != "" {
			where += " " + f.Stage + " " + f.AttachmentID
		} else {
			where += " " + f.Stage
		}
		fmt.Printf("  %s %s/%s: %s\n", label, f.Folder, where, f.Error)
	}
}

func (e *Exporter) openFolder(f folder, cp *checkpoint) (*os.File, error) {
	path := filepath.Join(e.OutDir, f.name+".mbox")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	offset, known := cp.Offsets[f.name]
	if known {
		if err := file.Truncate(offset); err != nil {
			_ = file.Close()
			return nil, err
		}
	}
	if _, err := file.Seek(0, io.SeekEnd); err != nil {
		_ = file.Close()
		return nil, err
	}
	return file, nil
}

func (e *Exporter) exportFolder(ctx context.Context, f folder, cp *checkpoint) error {
	file, err := e.openFolder(f, cp)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()

	cursor := cp.Cursors[f.name]
	for {
		params := url.Values{}
		for k, vs := range f.params {
			params[k] = vs
		}
		if cursor != "" {
			params.Set("cursor", cursor)
		}
		list, err := e.Client.ListMessages(ctx, params.Encode())
		if err != nil {
			return err
		}
		for _, m := range list.Items {
			if err := ctx.Err(); err != nil {
				return err
			}
			if len(m.LabelIDs) > 0 {
				cp.Labels[m.ID] = labelRecord{LabelIDs: m.LabelIDs}
			}
			if err := e.exportOne(ctx, f.name, m.ID, file, cp); err != nil {
				return err
			}
		}
		pos, err := fileSize(file)
		if err != nil {
			return err
		}
		cursor = list.NextCursor
		cp.Offsets[f.name] = pos
		cp.Cursors[f.name] = cursor
		cp.Done[f.name] = cursor == ""
		e.saveCheckpoint(cp)
		if cursor == "" {
			return nil
		}
	}
}

func (e *Exporter) exportOne(ctx context.Context, folderName, messageID string, file *os.File, cp *checkpoint) error {
	built, err := e.buildMessage(ctx, folderName, messageID)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		if api.Retryable(err) {
			recordPending(cp, failure{
				Folder:    folderName,
				MessageID: messageID,
				Stage:     stageOf(err),
				Attempts:  1,
				Error:     err.Error(),
			})
			return nil
		}
		recordLost(cp, failure{
			Folder:    folderName,
			MessageID: messageID,
			Stage:     stageOf(err),
			Attempts:  1,
			Error:     err.Error(),
		})
		return nil
	}
	if err := writeMboxEntry(file, built.sender, built.date, built.rfc822); err != nil {
		return err
	}
	noteMessageIDHeader(cp, messageID, built.rfc822)
	for _, l := range built.lost {
		recordLost(cp, l)
	}
	totals := cp.Totals[folderName]
	totals.Messages++
	totals.Attachments += built.attachments
	cp.Totals[folderName] = totals
	return nil
}

func (e *Exporter) retryPending(ctx context.Context, f folder, cp *checkpoint) (int, error) {
	queue := cp.Pending[f.name]
	if len(queue) == 0 {
		return 0, nil
	}
	file, err := e.openFolder(f, cp)
	if err != nil {
		return 0, err
	}
	defer func() { _ = file.Close() }()

	recovered := 0
	remaining := make([]failure, 0, len(queue))
	for _, item := range queue {
		if err := ctx.Err(); err != nil {
			return recovered, err
		}
		built, berr := e.buildMessage(ctx, f.name, item.MessageID)
		if berr != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return recovered, ctxErr
			}
			item.Attempts++
			item.Stage = stageOf(berr)
			item.Error = berr.Error()
			if api.Retryable(berr) {
				remaining = append(remaining, item)
			} else {
				recordLost(cp, item)
			}
			continue
		}
		if err := writeMboxEntry(file, built.sender, built.date, built.rfc822); err != nil {
			return recovered, err
		}
		noteMessageIDHeader(cp, item.MessageID, built.rfc822)
		for _, l := range built.lost {
			recordLost(cp, l)
		}
		totals := cp.Totals[f.name]
		totals.Messages++
		totals.Attachments += built.attachments
		cp.Totals[f.name] = totals
		recovered++
	}
	if len(remaining) == 0 {
		delete(cp.Pending, f.name)
	} else {
		cp.Pending[f.name] = remaining
	}
	pos, err := fileSize(file)
	if err != nil {
		return recovered, err
	}
	cp.Offsets[f.name] = pos
	e.saveCheckpoint(cp)
	return recovered, nil
}

func fileSize(file *os.File) (int64, error) {
	st, err := file.Stat()
	if err != nil {
		return 0, err
	}
	return st.Size(), nil
}

type builtMessage struct {
	rfc822      string
	sender      string
	date        time.Time
	attachments int
	lost        []failure
}

type stagedError struct {
	stage string
	err   error
}

func (s *stagedError) Error() string { return s.err.Error() }
func (s *stagedError) Unwrap() error { return s.err }

func stageOf(err error) string {
	var se *stagedError
	if errors.As(err, &se) {
		return se.stage
	}
	return "message"
}

func staged(stage string, err error) error {
	return &stagedError{stage: stage, err: err}
}

func (e *Exporter) buildMessage(ctx context.Context, folderName, messageID string) (builtMessage, error) {
	mf := &messageFetch{client: e.Client, id: messageID}
	if err := mf.load(ctx); err != nil {
		return builtMessage{}, staged("detail", err)
	}

	cipher, err := mf.fetch(ctx, "")
	if err != nil {
		return builtMessage{}, staged("body", err)
	}
	plain, err := e.Vault.Decrypt(cipher)
	if err != nil {
		return builtMessage{}, staged("body", err)
	}
	mimeStr := unwrapPgpMime(e.Vault, string(plain))

	attachments := append([]api.AttachmentDetail(nil), mf.detail.Attachments...)
	sort.Slice(attachments, func(i, j int) bool { return attachments[i].Ordinal < attachments[j].Ordinal })

	parts := make([]attachedPart, 0, len(attachments))
	var lostParts []lostPart
	var lost []failure
	for _, a := range attachments {
		var header attframe.Header
		var payload []byte
		raw, err := mf.fetch(ctx, a.ID)
		if err == nil {
			header, payload, err = e.openAttachment(raw)
		}
		if err != nil {
			if api.Retryable(err) {
				return builtMessage{}, staged("attachment", err)
			}
			lostParts = append(lostParts, lostPart{
				ordinal:     a.Ordinal,
				filename:    header.Filename,
				contentType: header.ContentType,
				sizeBytes:   header.PlaintextSize,
				reason:      err.Error(),
			})
			lost = append(lost, failure{
				Folder:       folderName,
				MessageID:    messageID,
				Stage:        "attachment",
				AttachmentID: a.ID,
				Filename:     header.Filename,
				Attempts:     1,
				Error:        err.Error(),
			})
			continue
		}
		parts = append(parts, attachedPart{header: header, payload: payload})
	}

	assembled := attachToMIME(messageID, mimeStr, parts, lostParts)
	date := time.Now().UTC()
	if t, ok := messageDate(assembled); ok {
		date = t
	}
	return builtMessage{
		rfc822:      assembled,
		sender:      senderAddress(assembled),
		date:        date,
		attachments: len(parts),
		lost:        lost,
	}, nil
}

func (e *Exporter) openAttachment(raw []byte) (attframe.Header, []byte, error) {
	plain, err := e.Vault.Decrypt(raw)
	if err != nil {
		return attframe.Header{}, nil, err
	}
	header, payload, err := attframe.Parse(plain)
	if err == nil {
		return header, payload, nil
	}
	if partial, herr := attframe.ParseHeader(plain); herr == nil {
		return partial, nil, err
	}
	return attframe.Header{}, nil, err
}

type messageFetch struct {
	client    *api.Client
	id        string
	detail    api.MessageDetail
	refreshes int
}

func (m *messageFetch) load(ctx context.Context) error {
	detail, err := m.client.GetMessage(ctx, m.id)
	if err != nil {
		return err
	}
	m.detail = detail
	return nil
}

func (m *messageFetch) pointer(attachmentID string) (api.PresignedPointer, bool) {
	if attachmentID == "" {
		return m.detail.Body, true
	}
	for _, a := range m.detail.Attachments {
		if a.ID == attachmentID {
			return a.Pointer, true
		}
	}
	return api.PresignedPointer{}, false
}

func (m *messageFetch) fetch(ctx context.Context, attachmentID string) ([]byte, error) {
	ptr, ok := m.pointer(attachmentID)
	if !ok {
		return nil, fmt.Errorf("attachment %s vanished from the message", attachmentID)
	}
	raw, err := m.client.GetBlob(ctx, ptr.URL)
	if err == nil {
		return raw, verifyCiphertext(ptr, raw)
	}
	if !api.IsExpiredPointer(err) || m.refreshes >= maxPointerRefresh {
		return nil, err
	}
	m.refreshes++
	if lerr := m.load(ctx); lerr != nil {
		return nil, lerr
	}
	ptr, ok = m.pointer(attachmentID)
	if !ok {
		return nil, err
	}
	raw, err = m.client.GetBlob(ctx, ptr.URL)
	if err != nil {
		return nil, err
	}
	return raw, verifyCiphertext(ptr, raw)
}

func verifyCiphertext(ptr api.PresignedPointer, raw []byte) error {
	if len(ptr.SHA256) == 0 {
		return nil
	}
	sum := sha256.Sum256(raw)
	if subtle.ConstantTimeCompare(sum[:], ptr.SHA256) != 1 {
		return errors.New("ciphertext checksum does not match the server's record")
	}
	return nil
}

func recordPending(cp *checkpoint, f failure) {
	for i, existing := range cp.Pending[f.Folder] {
		if existing.MessageID == f.MessageID {
			f.Attempts += existing.Attempts
			cp.Pending[f.Folder][i] = f
			return
		}
	}
	cp.Pending[f.Folder] = append(cp.Pending[f.Folder], f)
}

func recordLost(cp *checkpoint, f failure) {
	for i, existing := range cp.Lost {
		if existing.MessageID == f.MessageID && existing.AttachmentID == f.AttachmentID {
			cp.Lost[i] = f
			return
		}
	}
	cp.Lost = append(cp.Lost, f)
}

func (e *Exporter) writeKeyMaterial() error {
	if e.EncryptedPrivateKey != "" {
		if err := os.WriteFile(filepath.Join(e.OutDir, "private-key-encrypted.asc"), []byte(e.EncryptedPrivateKey), 0o600); err != nil {
			return err
		}
	}
	return nil
}

func (e *Exporter) writeSettings(ctx context.Context) error {
	settings, _ := e.Client.AccountSettings(ctx)
	addresses, _ := e.Client.Addresses(ctx)
	out := map[string]json.RawMessage{}
	if len(settings) > 0 {
		out["settings"] = settings
	}
	if len(addresses) > 0 {
		out["addresses"] = addresses
	}
	raw, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(e.OutDir, "settings.json"), raw, 0o600)
}

func (e *Exporter) checkpointPath() string { return filepath.Join(e.OutDir, ".export-checkpoint.json") }

func (e *Exporter) loadCheckpoint() *checkpoint {
	cp := &checkpoint{Version: checkpointVersion}
	raw, err := os.ReadFile(e.checkpointPath())
	if err == nil {
		_ = json.Unmarshal(raw, cp)
	}
	cp.Version = checkpointVersion
	if cp.Cursors == nil {
		cp.Cursors = map[string]string{}
	}
	if cp.Done == nil {
		cp.Done = map[string]bool{}
	}
	if cp.Offsets == nil {
		cp.Offsets = map[string]int64{}
	}
	if cp.Totals == nil {
		cp.Totals = map[string]folderTotals{}
	}
	if cp.Pending == nil {
		cp.Pending = map[string][]failure{}
	}
	if cp.Labels == nil {
		cp.Labels = map[string]labelRecord{}
	}
	return cp
}

func (e *Exporter) saveCheckpoint(cp *checkpoint) {
	raw, err := json.MarshalIndent(cp, "", "  ")
	if err != nil {
		return
	}
	_ = os.WriteFile(e.checkpointPath(), raw, 0o600)
}

func (e *Exporter) startHeartbeat(ctx context.Context) func() {
	if e.Session == "" {
		return func() {}
	}
	done := make(chan struct{})
	go func() {
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-done:
				return
			case <-t.C:
				_, _ = e.Client.ExportHeartbeat(ctx, e.Session)
			}
		}
	}()
	return func() { close(done) }
}
