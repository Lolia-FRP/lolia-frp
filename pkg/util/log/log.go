// Copyright 2016 fatedier, fatedier@gmail.com
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package log

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/log"
)

var (
	TraceLevel = log.DebugLevel
	DebugLevel = log.DebugLevel
	InfoLevel  = log.InfoLevel
	WarnLevel  = log.WarnLevel
	ErrorLevel = log.ErrorLevel
)

var Logger *log.Logger

func init() {
	Logger = log.NewWithOptions(os.Stderr, log.Options{
		ReportCaller:    true,
		ReportTimestamp: true,
		TimeFormat:      time.Kitchen,
		Prefix:          "LoliaFRP-CLI",
		CallerOffset:    1,
	})
	// 设置自定义样式以支持 Trace 级别
	styles := log.DefaultStyles()
	styles.Levels[TraceLevel] = lipgloss.NewStyle().
		SetString("TRACE").
		Bold(true).
		MaxWidth(5).
		Foreground(lipgloss.Color("61"))
	Logger.SetStyles(styles)
}

func InitLogger(logPath string, levelStr string, maxDays int, disableLogColor bool) {
	var output io.Writer
	var err error

	if logPath == "console" {
		output = os.Stdout
	} else {
		// Use rotating file writer
		output, err = NewRotateFileWriter(logPath, maxDays)
		if err != nil {
			// Fallback to console if file creation fails
			output = os.Stdout
		}
	}

	level, err := log.ParseLevel(levelStr)
	if err != nil {
		level = log.InfoLevel
	}

	Logger = log.NewWithOptions(output, log.Options{
		ReportCaller:    true,
		ReportTimestamp: true,
		TimeFormat:      time.Kitchen,
		Prefix:          "LoliaFRP-CLI",
		CallerOffset:    1,
		Level:           level,
	})
}

// NewRotateFileWriter creates a rotating file writer
func NewRotateFileWriter(filePath string, maxDays int) (*RotateFileWriter, error) {
	w := &RotateFileWriter{
		filePath:    filePath,
		maxDays:     maxDays,
		lastRotate:  time.Now(),
		currentDate: time.Now().Format("2006-01-02"),
	}

	if err := w.openFile(); err != nil {
		return nil, err
	}

	return w, nil
}

// RotateFileWriter implements io.Writer with daily rotation
type RotateFileWriter struct {
	filePath    string
	maxDays     int
	file        *os.File
	lastRotate  time.Time
	currentDate string
}

func (w *RotateFileWriter) openFile() error {
	var err error
	w.file, err = os.OpenFile(w.filePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	return err
}

func (w *RotateFileWriter) checkRotate() error {
	now := time.Now()
	currentDate := now.Format("2006-01-02")

	if currentDate != w.currentDate {
		// Close current file
		if w.file != nil {
			w.file.Close()
		}

		// Rename current file with date suffix
		oldPath := w.filePath
		newPath := w.filePath + "." + w.currentDate
		if _, err := os.Stat(oldPath); err == nil {
			if err := os.Rename(oldPath, newPath); err != nil {
				return err
			}
		}

		// Clean up old log files
		w.cleanupOldLogs(now)

		// Update current date and open new file
		w.currentDate = currentDate
		w.lastRotate = now
		return w.openFile()
	}

	return nil
}

func (w *RotateFileWriter) cleanupOldLogs(now time.Time) {
	if w.maxDays <= 0 {
		return
	}

	cutoffDate := now.AddDate(0, 0, -w.maxDays)

	// Find and remove old log files
	dir := filepath.Dir(w.filePath)
	base := filepath.Base(w.filePath)

	files, _ := os.ReadDir(dir)
	for _, f := range files {
		if f.IsDir() {
			continue
		}

		name := f.Name()
		if strings.HasPrefix(name, base+".") {
			// Extract date from filename (base.YYYY-MM-DD)
			dateStr := strings.TrimPrefix(name, base+".")
			if len(dateStr) == 10 {
				fileDate, err := time.Parse("2006-01-02", dateStr)
				if err == nil && fileDate.Before(cutoffDate) {
					os.Remove(filepath.Join(dir, name))
				}
			}
		}
	}
}

func (w *RotateFileWriter) Write(p []byte) (n int, err error) {
	if err := w.checkRotate(); err != nil {
		return 0, err
	}
	return w.file.Write(p)
}

func (w *RotateFileWriter) Close() error {
	if w.file != nil {
		return w.file.Close()
	}
	return nil
}

func Errorf(format string, v ...any) {
	Logger.Errorf(format, v...)
}

func Warnf(format string, v ...any) {
	Logger.Warnf(format, v...)
}

func Info(format string, v ...any) {
	Logger.Info(format, v...)
}

func Infof(format string, v ...any) {
	Logger.Infof(format, v...)
}

func Debugf(format string, v ...any) {
	Logger.Debugf(format, v...)
}

func Tracef(format string, v ...any) {
	Logger.Logf(TraceLevel, format, v...)
}

func Logf(level log.Level, offset int, format string, v ...any) {
	// charmbracelet/log doesn't support offset, so we ignore it
	Logger.Logf(level, format, v...)
}

type WriteLogger struct {
	level  log.Level
	offset int
}

func NewWriteLogger(level log.Level, offset int) *WriteLogger {
	return &WriteLogger{
		level:  level,
		offset: offset,
	}
}

func (w *WriteLogger) Write(p []byte) (n int, err error) {
	// charmbracelet/log doesn't support offset in Log
	msg := string(bytes.TrimRight(p, "\n"))
	Logger.Log(w.level, msg)
	return len(p), nil
}
