package export

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

type failure struct {
	Folder       string `json:"folder"`
	MessageID    string `json:"messageId"`
	Stage        string `json:"stage"`
	AttachmentID string `json:"attachmentId,omitempty"`
	Filename     string `json:"filename,omitempty"`
	Attempts     int    `json:"attempts"`
	Error        string `json:"error"`
}

type folderTotals struct {
	Messages    int `json:"messages"`
	Attachments int `json:"attachments"`
}

type reportFolder struct {
	Name        string `json:"name"`
	Messages    int    `json:"messages"`
	Attachments int    `json:"attachments"`
	Pending     int    `json:"pending"`
	Lost        int    `json:"lost"`
}

type report struct {
	GeneratedAt time.Time      `json:"generatedAt"`
	Complete    bool           `json:"complete"`
	Folders     []reportFolder `json:"folders"`
	Pending     []failure      `json:"pending"`
	Lost        []failure      `json:"lost"`
}

func buildReport(cp *checkpoint, list []folder, now time.Time) report {
	r := report{GeneratedAt: now, Pending: []failure{}, Lost: []failure{}}
	for _, f := range list {
		lost := 0
		for _, l := range cp.Lost {
			if l.Folder == f.name {
				lost++
			}
		}
		totals := cp.Totals[f.name]
		r.Folders = append(r.Folders, reportFolder{
			Name:        f.name,
			Messages:    totals.Messages,
			Attachments: totals.Attachments,
			Pending:     len(cp.Pending[f.name]),
			Lost:        lost,
		})
		r.Pending = append(r.Pending, cp.Pending[f.name]...)
	}
	r.Lost = append(r.Lost, cp.Lost...)
	r.Complete = len(r.Pending) == 0 && len(r.Lost) == 0
	return r
}

func writeReport(dir string, r report) error {
	raw, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "export-report.json"), append(raw, '\n'), 0o600)
}
