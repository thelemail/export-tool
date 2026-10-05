package export

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/thelemail/export-tool/internal/api"
	"github.com/thelemail/export-tool/internal/attframe"
)

type fakeAttachment struct {
	id       string
	ordinal  int
	key      string
	isInline bool
}

type fakeMessage struct {
	id          string
	bodyKey     string
	attachments []fakeAttachment
	labelIDs    []string
}

type fakeAPI struct {
	t *testing.T

	mu          sync.Mutex
	srv         *httptest.Server
	blobs       map[string][]byte
	blobStatus  map[string]int
	pages       map[string][][]fakeMessage
	messages    map[string]fakeMessage
	listStatus  map[string]int
	collections []map[string]any
	epoch       int
	bumpOnFetch bool
	completed   bool
}

func newFakeAPI(t *testing.T) *fakeAPI {
	f := &fakeAPI{
		t:          t,
		blobs:      map[string][]byte{},
		blobStatus: map[string]int{},
		pages:      map[string][][]fakeMessage{},
		messages:   map[string]fakeMessage{},
		listStatus: map[string]int{},
		epoch:      1,
	}
	f.srv = httptest.NewServer(http.HandlerFunc(f.route))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeAPI) put(key string, cipher []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.blobs[key] = cipher
}

func (f *fakeAPI) fail(key string, status int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.blobStatus[key] = status
}

func (f *fakeAPI) heal(key string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.blobStatus, key)
}

func (f *fakeAPI) add(folder string, pages ...[]fakeMessage) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pages[folder] = pages
	for _, page := range pages {
		for _, m := range page {
			f.messages[m.id] = m
		}
	}
}

func (f *fakeAPI) route(w http.ResponseWriter, r *http.Request) {
	switch {
	case strings.HasPrefix(r.URL.Path, "/blob/"):
		f.serveBlob(w, r)
	case r.URL.Path == "/v1/messages":
		f.serveList(w, r)
	case strings.HasPrefix(r.URL.Path, "/v1/messages/"):
		f.serveDetail(w, r)
	case r.URL.Path == "/v1/mail/collections":
		f.mu.Lock()
		cols := append([]map[string]any{}, f.collections...)
		f.mu.Unlock()
		writeJSON(w, map[string]any{"collections": cols})
	case r.URL.Path == "/v1/account/settings":
		writeJSON(w, map[string]string{"theme": "pine"})
	case r.URL.Path == "/v1/me/addresses":
		writeJSON(w, []string{"me@thelemail.com"})
	case r.URL.Path == "/v1/lifecycle/export/heartbeat":
		writeJSON(w, map[string]string{"sessionId": "sess-1", "expiresAt": time.Now().Format(time.RFC3339)})
	case r.URL.Path == "/v1/lifecycle/export/complete":
		f.mu.Lock()
		f.completed = true
		f.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	default:
		http.NotFound(w, r)
	}
}

func (f *fakeAPI) serveBlob(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	key := strings.TrimPrefix(r.URL.Path, "/blob/")
	status := f.blobStatus[key]
	blob, ok := f.blobs[key]
	stale := r.URL.Query().Get("epoch") != fmt.Sprint(f.epoch)
	f.mu.Unlock()

	if status != 0 {
		w.WriteHeader(status)
		return
	}
	if stale {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	_, _ = w.Write(blob)
}

func folderOf(q url.Values) string {
	switch {
	case q.Get("starred") == "true":
		return "starred"
	case q.Get("mailbox") == "folder":
		return "folder:" + q.Get("folderId")
	case q.Get("mailbox") != "":
		return q.Get("mailbox")
	case q.Get("direction") == "sent":
		return "sent"
	}
	return ""
}

func (f *fakeAPI) serveList(w http.ResponseWriter, r *http.Request) {
	folder := folderOf(r.URL.Query())
	f.mu.Lock()
	if status := f.listStatus[folder]; status != 0 {
		f.mu.Unlock()
		w.WriteHeader(status)
		return
	}
	pages := f.pages[folder]
	f.mu.Unlock()

	index := 0
	if c := r.URL.Query().Get("cursor"); c != "" {
		_, _ = fmt.Sscanf(c, "page-%d", &index)
	}
	items := []map[string]any{}
	next := ""
	if index < len(pages) {
		for _, m := range pages[index] {
			items = append(items, map[string]any{"id": m.id, "labelIds": m.labelIDs})
		}
		if index+1 < len(pages) {
			next = fmt.Sprintf("page-%d", index+1)
		}
	}
	writeJSON(w, map[string]any{"items": items, "nextCursor": next})
}

func (f *fakeAPI) serveDetail(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/v1/messages/")
	f.mu.Lock()
	m, ok := f.messages[id]
	if f.bumpOnFetch {
		f.epoch++
		f.bumpOnFetch = false
	}
	epoch := f.epoch
	f.mu.Unlock()
	if !ok {
		http.NotFound(w, r)
		return
	}
	pointer := func(key string) map[string]any {
		return map[string]any{
			"url":       fmt.Sprintf("%s/blob/%s?epoch=%d", f.srv.URL, key, epoch),
			"expiresAt": time.Now().Add(time.Minute).Format(time.RFC3339),
			"sizeBytes": 0,
		}
	}
	atts := []map[string]any{}
	for _, a := range m.attachments {
		atts = append(atts, map[string]any{
			"id":       a.id,
			"ordinal":  a.ordinal,
			"pointer":  pointer(a.key),
			"isInline": a.isInline,
		})
	}
	writeJSON(w, map[string]any{
		"id":          m.id,
		"source":      "internal",
		"encrypted":   false,
		"body":        pointer(m.bodyKey),
		"attachments": atts,
	})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func buildFrame(t *testing.T, h attframe.Header, payload []byte) []byte {
	t.Helper()
	h.Version = 1
	h.PlaintextSize = int64(len(payload))
	raw, err := json.Marshal(h)
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	out := append([]byte("TMA1"), 0x01)
	out = binary.BigEndian.AppendUint32(out, uint32(len(raw)))
	out = append(out, raw...)
	return append(out, payload...)
}

func newExporter(t *testing.T, f *fakeAPI, key *testKey, dir string) *Exporter {
	t.Helper()
	client := api.New(f.srv.URL, "http://localhost")
	client.MaxAttempts = 2
	client.Backoff = time.Millisecond
	client.SetSession("token", "account")
	return &Exporter{Client: client, Vault: key.vault, OutDir: dir, Session: "sess-1"}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return normalize(string(raw))
}

func readReport(t *testing.T, dir string) report {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, "export-report.json"))
	if err != nil {
		t.Fatalf("read report: %v", err)
	}
	var r report
	if err := json.Unmarshal(raw, &r); err != nil {
		t.Fatalf("decode report: %v", err)
	}
	return r
}

func countEntries(mbox string) int {
	n := 0
	for _, line := range strings.Split(mbox, "\n") {
		if strings.HasPrefix(line, "From ") {
			n++
		}
	}
	return n
}

const plainBody = "From: Alice <alice@example.com>\r\n" +
	"To: me@thelemail.com\r\n" +
	"Subject: Invoice attached\r\n" +
	"Date: Tue, 04 Mar 2026 10:11:12 +0000\r\n" +
	"Content-Type: text/plain; charset=utf-8\r\n\r\n" +
	"see attached\r\n"

func seedOneMessageWithAttachment(t *testing.T, f *fakeAPI, key *testKey) {
	t.Helper()
	f.put("body-1", key.encrypt(t, []byte(plainBody)))
	frame := buildFrame(t, attframe.Header{
		Filename:    "invoice.pdf",
		ContentType: "application/pdf",
		Disposition: attframe.DispositionAttachment,
	}, []byte("PDF-BYTES"))
	f.put("att-1", key.encrypt(t, frame))
	f.add("inbox", []fakeMessage{{
		id:          "m1",
		bodyKey:     "body-1",
		attachments: []fakeAttachment{{id: "a1", ordinal: 0, key: "att-1"}},
	}})
}

func TestRunWritesAttachmentsIntoTheMbox(t *testing.T) {
	f := newFakeAPI(t)
	key := newTestKey(t)
	seedOneMessageWithAttachment(t, f, key)
	dir := t.TempDir()

	if err := newExporter(t, f, key, dir).Run(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}

	mbox := readFile(t, filepath.Join(dir, "inbox.mbox"))
	if !strings.Contains(mbox, "Subject: Invoice attached") {
		t.Fatalf("message missing:\n%s", mbox)
	}
	part, ok := findPart(flatten(t, strings.SplitN(mbox, "\n", 2)[1]), "invoice.pdf")
	if !ok {
		t.Fatalf("attachment missing:\n%s", mbox)
	}
	if string(part.body) != "PDF-BYTES" {
		t.Fatalf("payload = %q", part.body)
	}

	r := readReport(t, dir)
	if !r.Complete {
		t.Fatalf("report not complete: %+v", r)
	}
	for _, fr := range r.Folders {
		if fr.Name == "inbox" && (fr.Messages != 1 || fr.Attachments != 1) {
			t.Fatalf("inbox totals = %+v", fr)
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.completed {
		t.Fatal("export session was not completed")
	}
}

func TestRunHoldsBackMessagesWithTransientFailures(t *testing.T) {
	f := newFakeAPI(t)
	key := newTestKey(t)
	seedOneMessageWithAttachment(t, f, key)
	f.fail("att-1", http.StatusServiceUnavailable)
	dir := t.TempDir()

	err := newExporter(t, f, key, dir).Run(context.Background())
	if !errors.Is(err, ErrIncomplete) {
		t.Fatalf("run err = %v", err)
	}
	mbox := readFile(t, filepath.Join(dir, "inbox.mbox"))
	if strings.Contains(mbox, "Invoice attached") {
		t.Fatalf("half-written message reached the mbox:\n%s", mbox)
	}
	r := readReport(t, dir)
	if len(r.Pending) != 1 || r.Pending[0].MessageID != "m1" || r.Pending[0].Stage != "attachment" {
		t.Fatalf("pending = %+v", r.Pending)
	}
	if len(r.Lost) != 0 {
		t.Fatalf("lost = %+v", r.Lost)
	}
	f.mu.Lock()
	completed := f.completed
	f.mu.Unlock()
	if completed {
		t.Fatal("an incomplete export reported completion")
	}

	f.heal("att-1")
	if err := newExporter(t, f, key, dir).Run(context.Background()); err != nil {
		t.Fatalf("re-run: %v", err)
	}
	mbox = readFile(t, filepath.Join(dir, "inbox.mbox"))
	if countEntries(mbox) != 1 {
		t.Fatalf("expected one entry after retry:\n%s", mbox)
	}
	if _, ok := findPart(flatten(t, strings.SplitN(mbox, "\n", 2)[1]), "invoice.pdf"); !ok {
		t.Fatalf("attachment missing after retry:\n%s", mbox)
	}
	r = readReport(t, dir)
	if !r.Complete {
		t.Fatalf("report still incomplete: %+v", r)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.completed {
		t.Fatal("export session was not completed after the retry")
	}
}

func TestRunRefreshesExpiredPointers(t *testing.T) {
	f := newFakeAPI(t)
	key := newTestKey(t)
	seedOneMessageWithAttachment(t, f, key)
	f.mu.Lock()
	f.bumpOnFetch = true
	f.mu.Unlock()
	dir := t.TempDir()

	if err := newExporter(t, f, key, dir).Run(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}
	mbox := readFile(t, filepath.Join(dir, "inbox.mbox"))
	if _, ok := findPart(flatten(t, strings.SplitN(mbox, "\n", 2)[1]), "invoice.pdf"); !ok {
		t.Fatalf("attachment missing:\n%s", mbox)
	}
}

func TestRunWritesPlaceholderForUnreadableAttachment(t *testing.T) {
	f := newFakeAPI(t)
	key := newTestKey(t)
	seedOneMessageWithAttachment(t, f, key)
	f.put("att-1", key.encrypt(t, []byte("not a frame")))
	dir := t.TempDir()

	err := newExporter(t, f, key, dir).Run(context.Background())
	if !errors.Is(err, ErrIncomplete) {
		t.Fatalf("run err = %v", err)
	}
	mbox := readFile(t, filepath.Join(dir, "inbox.mbox"))
	if !strings.Contains(mbox, "Subject: Invoice attached") {
		t.Fatalf("message was dropped:\n%s", mbox)
	}
	if !strings.Contains(mbox, "could not be recovered") {
		t.Fatalf("placeholder missing:\n%s", mbox)
	}
	r := readReport(t, dir)
	if len(r.Lost) != 1 || r.Lost[0].AttachmentID != "a1" {
		t.Fatalf("lost = %+v", r.Lost)
	}
	if len(r.Pending) != 0 {
		t.Fatalf("pending = %+v", r.Pending)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.completed {
		t.Fatal("an incomplete export reported completion")
	}
}

func TestRunResumesWithoutDuplicates(t *testing.T) {
	f := newFakeAPI(t)
	key := newTestKey(t)
	for _, id := range []string{"m1", "m2"} {
		f.put("body-"+id, key.encrypt(t, []byte(plainBody)))
	}
	f.add("inbox",
		[]fakeMessage{{id: "m1", bodyKey: "body-m1"}},
		[]fakeMessage{{id: "m2", bodyKey: "body-m2"}},
	)
	dir := t.TempDir()

	f.mu.Lock()
	f.messages["m2"] = fakeMessage{id: "m2", bodyKey: "missing"}
	f.mu.Unlock()
	f.fail("missing", http.StatusInternalServerError)

	if err := newExporter(t, f, key, dir).Run(context.Background()); !errors.Is(err, ErrIncomplete) {
		t.Fatalf("run err = %v", err)
	}
	path := filepath.Join(dir, "inbox.mbox")
	if got := countEntries(readFile(t, path)); got != 1 {
		t.Fatalf("expected one entry, got %d", got)
	}

	file, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatalf("open mbox: %v", err)
	}
	if _, err := file.WriteString("From junk@example.com Tue Mar  4 10:11:12 2026\nhalf written\n\n"); err != nil {
		t.Fatalf("write junk: %v", err)
	}
	_ = file.Close()

	f.mu.Lock()
	f.messages["m2"] = fakeMessage{id: "m2", bodyKey: "body-m2"}
	f.mu.Unlock()

	if err := newExporter(t, f, key, dir).Run(context.Background()); err != nil {
		t.Fatalf("re-run: %v", err)
	}
	mbox := readFile(t, path)
	if strings.Contains(mbox, "half written") {
		t.Fatalf("uncommitted bytes survived the resume:\n%s", mbox)
	}
	if got := countEntries(mbox); got != 2 {
		t.Fatalf("expected two entries, got %d:\n%s", got, mbox)
	}
}

func TestRunDoesNotDuplicateAttachmentsAlreadyInTheBody(t *testing.T) {
	f := newFakeAPI(t)
	key := newTestKey(t)
	body := "From: Alice <alice@example.com>\r\n" +
		"Subject: Inbound with attachment\r\n" +
		"Date: Tue, 04 Mar 2026 10:11:12 +0000\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: multipart/mixed; boundary=\"mix\"\r\n\r\n" +
		"--mix\r\nContent-Type: text/plain\r\n\r\nsee attached\r\n" +
		"--mix\r\nContent-Type: application/pdf; name=\"invoice.pdf\"\r\n" +
		"Content-Transfer-Encoding: base64\r\n" +
		"Content-Disposition: attachment; filename=\"invoice.pdf\"\r\n\r\n" +
		"UERGLUJZVEVT\r\n" +
		"--mix--\r\n"
	f.put("body-1", key.encrypt(t, []byte(body)))
	frame := buildFrame(t, attframe.Header{
		Filename:    "invoice.pdf",
		ContentType: "application/pdf",
		Disposition: attframe.DispositionAttachment,
	}, []byte("PDF-BYTES"))
	f.put("att-1", key.encrypt(t, frame))
	f.add("inbox", []fakeMessage{{
		id:          "m1",
		bodyKey:     "body-1",
		attachments: []fakeAttachment{{id: "a1", ordinal: 0, key: "att-1"}},
	}})
	dir := t.TempDir()

	if err := newExporter(t, f, key, dir).Run(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}
	mbox := readFile(t, filepath.Join(dir, "inbox.mbox"))
	count := 0
	for _, p := range flatten(t, strings.SplitN(mbox, "\n", 2)[1]) {
		if p.filename == "invoice.pdf" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("attachment appears %d times:\n%s", count, mbox)
	}
}

func TestRunSurfacesNonRetryableListFailures(t *testing.T) {
	f := newFakeAPI(t)
	key := newTestKey(t)
	seedOneMessageWithAttachment(t, f, key)
	f.mu.Lock()
	f.listStatus["inbox"] = http.StatusBadRequest
	f.mu.Unlock()

	err := newExporter(t, f, key, t.TempDir()).Run(context.Background())
	if err == nil || errors.Is(err, ErrIncomplete) {
		t.Fatalf("run err = %v", err)
	}
}

func TestFolderIsMarkedDoneInTheSameCheckpointWrite(t *testing.T) {
	f := newFakeAPI(t)
	key := newTestKey(t)
	f.put("body-1", key.encrypt(t, []byte(plainBody)))
	f.add("inbox", []fakeMessage{{id: "m1", bodyKey: "body-1"}})
	dir := t.TempDir()

	if err := newExporter(t, f, key, dir).Run(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, ".export-checkpoint.json"))
	if err != nil {
		t.Fatalf("read checkpoint: %v", err)
	}
	var cp checkpoint
	if err := json.Unmarshal(raw, &cp); err != nil {
		t.Fatalf("decode checkpoint: %v", err)
	}
	if !cp.Done["inbox"] {
		t.Fatal("inbox was not marked done")
	}
	if cp.Cursors["inbox"] != "" {
		t.Fatalf("cursor = %q", cp.Cursors["inbox"])
	}
	if cp.Offsets["inbox"] == 0 {
		t.Fatal("offset was not recorded")
	}
	if cp.Version != checkpointVersion {
		t.Fatalf("version = %d", cp.Version)
	}
}

func TestOldCheckpointsWithoutOffsetsStillResume(t *testing.T) {
	f := newFakeAPI(t)
	key := newTestKey(t)
	f.put("body-1", key.encrypt(t, []byte(plainBody)))
	f.add("inbox", []fakeMessage{{id: "m1", bodyKey: "body-1"}})
	dir := t.TempDir()

	legacy := `{"cursors":{"inbox":""},"done":{"inbox":true}}`
	if err := os.WriteFile(filepath.Join(dir, ".export-checkpoint.json"), []byte(legacy), 0o600); err != nil {
		t.Fatalf("seed checkpoint: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "inbox.mbox"), []byte("From a@b Tue Mar  4 10:11:12 2026\nold\n\n"), 0o600); err != nil {
		t.Fatalf("seed mbox: %v", err)
	}
	if err := newExporter(t, f, key, dir).Run(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}
	mbox := readFile(t, filepath.Join(dir, "inbox.mbox"))
	if !strings.Contains(mbox, "old") {
		t.Fatalf("earlier run's output was discarded:\n%s", mbox)
	}
	if countEntries(mbox) != 1 {
		t.Fatalf("expected one entry, got %d:\n%s", countEntries(mbox), mbox)
	}
}

func (f *fakeAPI) collection(t *testing.T, key *testKey, id, kind, parentID, meta string, deleted bool) {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	f.collections = append(f.collections, map[string]any{
		"id":         id,
		"kind":       kind,
		"parentId":   parentID,
		"position":   1024,
		"sealedMeta": key.encrypt(t, []byte(meta)),
		"deleted":    deleted,
	})
}

const labelledBody = "From: Alice <alice@example.com>\r\n" +
	"To: me@thelemail.com\r\n" +
	"Subject: Acme contract\r\n" +
	"Message-ID: <contract-1@example.com>\r\n" +
	"Date: Tue, 04 Mar 2026 10:11:12 +0000\r\n" +
	"Content-Type: text/plain; charset=utf-8\r\n\r\n" +
	"signed copy\r\n"

func TestRunExportsCustomFoldersAndTheirLabels(t *testing.T) {
	f := newFakeAPI(t)
	key := newTestKey(t)
	f.collection(t, key, "11111111-aaaa", "folder", "", `{"n":"Clients","c":null}`, false)
	f.collection(t, key, "22222222-bbbb", "folder", "11111111-aaaa", `{"n":"Acme / Co","c":"pine"}`, false)
	f.collection(t, key, "33333333-cccc", "folder", "", `{"n":"Gone","c":null}`, true)
	f.collection(t, key, "44444444-dddd", "label", "", `{"n":"Tax 2026","c":"brass"}`, false)
	f.put("body-1", key.encrypt(t, []byte(labelledBody)))
	f.add("folder:22222222-bbbb", []fakeMessage{{id: "m1", bodyKey: "body-1", labelIDs: []string{"44444444-dddd"}}})
	dir := t.TempDir()

	if err := newExporter(t, f, key, dir).Run(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}

	mbox := readFile(t, filepath.Join(dir, "folder Clients - Acme - Co 22222222.mbox"))
	if countEntries(mbox) != 1 || !strings.Contains(mbox, "Subject: Acme contract") {
		t.Fatalf("custom folder mbox:\n%s", mbox)
	}
	if _, err := os.Stat(filepath.Join(dir, "folder Gone 33333333.mbox")); !os.IsNotExist(err) {
		t.Fatalf("a deleted folder was exported: %v", err)
	}

	var org organization
	if err := json.Unmarshal([]byte(readFile(t, filepath.Join(dir, "organization.json"))), &org); err != nil {
		t.Fatalf("decode organization: %v", err)
	}
	if len(org.Folders) != 2 || org.Folders[1].Path != "Clients / Acme / Co" || org.Folders[1].Color != "pine" {
		t.Fatalf("folders = %+v", org.Folders)
	}
	if len(org.Labels) != 1 || org.Labels[0].Name != "Tax 2026" {
		t.Fatalf("labels = %+v", org.Labels)
	}
	if len(org.Messages) != 1 || org.Messages[0].MessageIDHeader != "<contract-1@example.com>" ||
		len(org.Messages[0].LabelIDs) != 1 || org.Messages[0].LabelIDs[0] != "44444444-dddd" {
		t.Fatalf("messages = %+v", org.Messages)
	}

	r := readReport(t, dir)
	var reported bool
	for _, fr := range r.Folders {
		if fr.Name == "folder Clients - Acme - Co 22222222" && fr.Messages == 1 {
			reported = true
		}
	}
	if !r.Complete || !reported {
		t.Fatalf("report = %+v", r)
	}
}
