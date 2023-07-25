package log

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"time"

	rotatelogs "github.com/gwsee/go-common-utils/log/file-rotatelogs"
	"github.com/pkg/errors"
	"github.com/rifflock/lfshook"
	"github.com/sirupsen/logrus"
)

var global = logrus.New()

// Logger return global logger instance
func Logger() *logrus.Logger {
	return global
}

// Init initialize a logger instance with given
// level, filepath, filename, maxsize, maxage and rotationtime.
func Init(level string, filePath string, fileName string, maxSize int64, maxAge time.Duration, rotationTime time.Duration) {
	if err := os.MkdirAll(filePath, os.ModePerm); err != nil {
		panic(err)
	}

	formatter := &logrus.TextFormatter{
		FullTimestamp:   true,
		TimestampFormat: "15:04:05.000",
		CallerPrettyfier: func(f *runtime.Frame) (string, string) {
			_, filename := filepath.Split(f.File)
			return "", fmt.Sprintf("%12s:%-4d", filename, f.Line)
		},
	}
	global.SetFormatter(formatter)
	global.SetReportCaller(true)
	lvl, err := logrus.ParseLevel(level)
	if err != nil {
		lvl = logrus.ErrorLevel
	}
	global.SetLevel(lvl)
	global.SetOutput(os.Stdout)
	global.AddHook(newRotateHook(filePath, fileName, maxSize, maxAge, rotationTime))
}

func newRotateHook(logPath string, logFileName string, maxSize int64, maxAge time.Duration, rotationTime time.Duration) *lfshook.LfsHook {
	baseLogName := path.Join(logPath, logFileName)

	writer, err := rotatelogs.New(
		baseLogName+"%Y%m%d%H%M%S",
		rotatelogs.WithLinkName(baseLogName),
		rotatelogs.WithMaxAge(maxAge),
		rotatelogs.WithMaxSize(maxSize),
		rotatelogs.WithRotationTime(rotationTime),
	)
	if err != nil {
		logrus.Errorf("config local file system logger error. %+v", errors.WithStack(err))
		return nil
	}

	return lfshook.NewHook(lfshook.WriterMap{
		logrus.DebugLevel: writer,
		logrus.InfoLevel:  writer,
		logrus.WarnLevel:  writer,
		logrus.ErrorLevel: writer,
		logrus.FatalLevel: writer,
		logrus.PanicLevel: writer,
	}, &logrus.TextFormatter{
		FullTimestamp:   true,
		TimestampFormat: "15:04:05.000",
		CallerPrettyfier: func(f *runtime.Frame) (string, string) {
			_, filename := filepath.Split(f.File)
			return "", fmt.Sprintf("%12s:%-4d", filename, f.Line)
		}})
}
