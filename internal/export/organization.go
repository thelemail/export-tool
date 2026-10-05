package export

import (
	"context"
	"encoding/json"
	"net/mail"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode"
)

type collectionMeta struct {
	Name  string  `json:"n"`
	Color *string `json:"c"`
}

type orgEntry struct {
	ID       string `json:"id"`
	ParentID string `json:"parentId,omitempty"`
	Name     string `json:"name,omitempty"`
	Path     string `json:"path,omitempty"`
	Color    string `json:"color,omitempty"`
	Locked   bool   `json:"locked,omitempty"`
	File     string `json:"file,omitempty"`
	position int64
}

type labelRecord struct {
	MessageIDHeader string   `json:"messageIdHeader,omitempty"`
	LabelIDs        []string `json:"labelIds"`
}

type labelledMessage struct {
	ID              string   `json:"id"`
	MessageIDHeader string   `json:"messageIdHeader,omitempty"`
	LabelIDs        []string `json:"labelIds"`
}

type organization struct {
	Folders  []orgEntry        `json:"folders"`
	Labels   []orgEntry        `json:"labels"`
	Messages []labelledMessage `json:"messages"`
}

func (e *Exporter) loadOrganization(ctx context.Context) (organization, error) {
	cols, err := e.Client.ListMailCollections(ctx)
	if err != nil {
		return organization{}, err
	}
	byKind := map[string][]orgEntry{}
	for _, c := range cols {
		if c.Deleted {
			continue
		}
		entry := orgEntry{ID: c.ID, ParentID: c.ParentID, position: c.Position}
		if meta, ok := e.openMeta(c.SealedMeta); ok {
			entry.Name = meta.Name
			if meta.Color != nil {
				entry.Color = *meta.Color
			}
		} else {
			entry.Locked = true
		}
		byKind[c.Kind] = append(byKind[c.Kind], entry)
	}
	org := organization{Folders: withPaths(byKind["folder"]), Labels: withPaths(byKind["label"])}
	for i := range org.Folders {
		org.Folders[i].File = folderFileName(org.Folders[i])
	}
	return org, nil
}

func (e *Exporter) openMeta(sealed []byte) (collectionMeta, bool) {
	if len(sealed) == 0 {
		return collectionMeta{}, false
	}
	plain, err := e.Vault.Decrypt(sealed)
	if err != nil {
		return collectionMeta{}, false
	}
	var meta collectionMeta
	if err := json.Unmarshal(plain, &meta); err != nil || strings.TrimSpace(meta.Name) == "" {
		return collectionMeta{}, false
	}
	return meta, true
}

func withPaths(entries []orgEntry) []orgEntry {
	byID := make(map[string]orgEntry, len(entries))
	for _, e := range entries {
		byID[e.ID] = e
	}
	for i, e := range entries {
		parts := []string{label(e)}
		seen := map[string]bool{e.ID: true}
		for parent, ok := byID[e.ParentID]; ok && !seen[parent.ID]; parent, ok = byID[parent.ParentID] {
			seen[parent.ID] = true
			parts = append([]string{label(parent)}, parts...)
		}
		entries[i].Path = strings.Join(parts, " / ")
	}
	sort.SliceStable(entries, func(a, b int) bool {
		if entries[a].Path != entries[b].Path {
			return entries[a].Path < entries[b].Path
		}
		return entries[a].position < entries[b].position
	})
	return entries
}

func label(e orgEntry) string {
	if e.Name != "" {
		return e.Name
	}
	return e.ID
}

const maxFolderFileName = 80

func folderFileName(e orgEntry) string {
	var b strings.Builder
	for _, r := range e.Path {
		switch {
		case unicode.IsLetter(r) || unicode.IsDigit(r) || r == ' ' || r == '-' || r == '_':
			b.WriteRune(r)
		case r == '/':
			b.WriteRune('-')
		default:
			b.WriteRune('_')
		}
	}
	name := strings.Join(strings.Fields(b.String()), " ")
	if runes := []rune(name); len(runes) > maxFolderFileName {
		name = string(runes[:maxFolderFileName])
	}
	short := e.ID
	if len(short) > 8 {
		short = short[:8]
	}
	return "folder " + name + " " + short
}

func customFolders(org organization) []folder {
	out := make([]folder, 0, len(org.Folders))
	for _, f := range org.Folders {
		params := url.Values{}
		params.Set("mailbox", "folder")
		params.Set("folderId", f.ID)
		params.Set("sort", "oldest")
		params.Set("limit", "50")
		out = append(out, folder{name: f.File, params: params})
	}
	return out
}

func noteMessageIDHeader(cp *checkpoint, messageID, rfc822 string) {
	rec, ok := cp.Labels[messageID]
	if !ok || rec.MessageIDHeader != "" {
		return
	}
	msg, err := mail.ReadMessage(strings.NewReader(rfc822))
	if err != nil {
		return
	}
	rec.MessageIDHeader = strings.TrimSpace(msg.Header.Get("Message-Id"))
	cp.Labels[messageID] = rec
}

func (e *Exporter) writeOrganization(org organization, cp *checkpoint) error {
	org.Messages = make([]labelledMessage, 0, len(cp.Labels))
	for id, rec := range cp.Labels {
		org.Messages = append(org.Messages, labelledMessage{
			ID:              id,
			MessageIDHeader: rec.MessageIDHeader,
			LabelIDs:        rec.LabelIDs,
		})
	}
	sort.Slice(org.Messages, func(a, b int) bool { return org.Messages[a].ID < org.Messages[b].ID })
	if org.Folders == nil {
		org.Folders = []orgEntry{}
	}
	if org.Labels == nil {
		org.Labels = []orgEntry{}
	}
	raw, err := json.MarshalIndent(org, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(e.OutDir, "organization.json"), append(raw, '\n'), 0o600)
}
