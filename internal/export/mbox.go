package export

import (
	"bufio"
	"fmt"
	"io"
	"strings"
	"time"
)

func writeMboxEntry(w io.Writer, sender string, date time.Time, rfc822 string) error {
	if sender == "" {
		sender = "MAILER-DAEMON"
	}
	if _, err := fmt.Fprintf(w, "From %s %s\n", sender, date.UTC().Format("Mon Jan _2 15:04:05 2006")); err != nil {
		return err
	}
	sc := bufio.NewScanner(strings.NewReader(rfc822))
	sc.Buffer(make([]byte, 0, 1<<20), 64<<20)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(strings.TrimLeft(line, ">"), "From ") {
			line = ">" + line
		}
		if _, err := io.WriteString(w, line+"\n"); err != nil {
			return err
		}
	}
	if err := sc.Err(); err != nil {
		return err
	}
	_, err := io.WriteString(w, "\n")
	return err
}
