package container

import (
	"bytes"

	"github.com/pkg/errors"
	"go.uber.org/zap"
)

const maxCapacity = 4 * 1024

func newStreamLogger(log *zap.Logger) *streamLogger {
	return &streamLogger{
		log: log,
		buf: make([]byte, 0, maxCapacity),
	}
}

type streamLogger struct {
	log *zap.Logger
	buf []byte
}

func (sl *streamLogger) Write(data []byte) (int, error) {
	if len(data) == 0 {
		return 0, nil
	}

	var dataRecord, dataReminder []byte
	var newRecord bool
	pos := bytes.IndexByte(data, '\n')
	if pos < 0 {
		pos = len(data)
	} else {
		newRecord = true
	}

	if len(sl.buf)+pos > maxCapacity {
		pos = maxCapacity - len(sl.buf)
		newRecord = true
	}
	dataRecord = data[:pos]
	dataReminder = data[pos:]
	if len(dataReminder) > 0 && dataReminder[0] == '\n' {
		dataReminder = dataReminder[1:]
	}

	sl.buf = append(sl.buf, dataRecord...)

	if newRecord {
		sl.log.Info(string(sl.buf))
		sl.buf = sl.buf[:0]
	}

	if len(dataReminder) > 0 {
		if _, err := sl.Write(dataReminder); err != nil {
			return 0, errors.WithStack(err)
		}
	}

	return len(data), nil
}
