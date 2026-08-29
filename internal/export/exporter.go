package export

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/thelemail/export-tool/internal/api"
	"github.com/thelemail/export-tool/internal/crypto"
)

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
	Cursors map[string]string `json:"cursors"`
	Done    map[string]bool   `json:"done"`
}

func (e *Exporter) Run(ctx context.Context) error {
	if err := os.MkdirAll(e.OutDir, 0o700); err != nil {
		return err
	}
	cp := e.loadCheckpoint()
	stop := e.startHeartbeat(ctx)
	defer stop()

	for _, f := range folders() {
		if cp.Done[f.name] {
			continue
		}
		fmt.Printf("Exporting %s...\n", f.name)
		if err := e.exportFolder(ctx, f, cp); err != nil {
			return fmt.Errorf("export %s: %w", f.name, err)
		}
		cp.Done[f.name] = true
		e.saveCheckpoint(cp)
	}
	if err := e.writeKeyMaterial(); err != nil {
		return err
	}
	if err := e.writeSettings(ctx); err != nil {
		return err
	}
	if e.Session != "" {
		_ = e.Client.ExportComplete(ctx, e.Session)
	}
	fmt.Printf("Done. Files written to %s\n", e.OutDir)
	return nil
}

func (e *Exporter) exportFolder(ctx context.Context, f folder, cp *checkpoint) error {
	path := filepath.Join(e.OutDir, f.name+".mbox")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()

	cursor := cp.Cursors[f.name]
	total := 0
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
			rfc822, sender, date, derr := e.decryptMessage(ctx, m.ID)
			if derr != nil {
				fmt.Printf("  skip %s: %v\n", m.ID, derr)
				continue
			}
			if err := writeMboxEntry(file, sender, date, rfc822); err != nil {
				return err
			}
			total++
		}
		cursor = list.NextCursor
		cp.Cursors[f.name] = cursor
		e.saveCheckpoint(cp)
		if cursor == "" {
			break
		}
	}
	fmt.Printf("  %s: %d messages\n", f.name, total)
	return nil
}

func (e *Exporter) decryptMessage(ctx context.Context, id string) (string, string, time.Time, error) {
	detail, err := e.Client.GetMessage(ctx, id)
	if err != nil {
		return "", "", time.Time{}, err
	}
	cipher, err := e.Client.GetBlob(ctx, detail.Body.URL)
	if err != nil {
		return "", "", time.Time{}, err
	}
	plain, err := e.Vault.Decrypt(cipher)
	if err != nil {
		return "", "", time.Time{}, err
	}
	mimeStr := unwrapPgpMime(e.Vault, string(plain))
	date := time.Now()
	if raw := headerValue(mimeStr, "Date"); raw != "" {
		if t, perr := time.Parse(time.RFC1123Z, raw); perr == nil {
			date = t
		}
	}
	return mimeStr, senderAddress(mimeStr), date, nil
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
	cp := &checkpoint{Cursors: map[string]string{}, Done: map[string]bool{}}
	raw, err := os.ReadFile(e.checkpointPath())
	if err != nil {
		return cp
	}
	_ = json.Unmarshal(raw, cp)
	if cp.Cursors == nil {
		cp.Cursors = map[string]string{}
	}
	if cp.Done == nil {
		cp.Done = map[string]bool{}
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
