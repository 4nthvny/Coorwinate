package main

import (
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	. "github.com/logrusorgru/aurora"
)

var (
	logger  *log.Logger
	logLock sync.Mutex // serialize log lines across host goroutines
)

func InitLogger() {
	logger = log.New(os.Stdout, "", 0)
}

func Time() string {
	return time.Now().Format("03:04:05PM")
}

// logf is the single choke point for all console output so that concurrent
// host goroutines never interleave partial lines.
func logf(format string, a ...interface{}) {
	logLock.Lock()
	defer logLock.Unlock()
	logger.Printf(format, a...)
}

func Summary(i instance) string {
	if i.Script == "" {
		return fmt.Sprintf("%d:%s:%s", Blue(i.ID), BrightRed(i.Username), BrightGreen(i.IP))
	}
	return fmt.Sprintf("%d@%s:%s:%s:%s/%s", Blue(i.ID), Time(), BrightRed(i.Username), BrightGreen(i.IP), BrightGreen(i.Hostname), BrightBlue(i.Script))
}

func Stdout(i instance, a ...interface{}) {
	logf("%s:%s%s\n%s", BrightCyan("[STDOUT"), Summary(i), BrightCyan("]"), White(fmt.Sprintln(a...)))
}

func Stderr(i instance, a ...interface{}) {
	logf("%s:%s%s\n%s", BrightRed("[STDERR"), Summary(i), BrightRed("]"), fmt.Sprintln(a...))
}

func Crit(i instance, a ...interface{}) {
	logf("%s:%s%s %s", Red("[CRIT"), Summary(i), Red("]"), fmt.Sprintln(a...))
}

func Err(a ...interface{}) {
	logf("%s %s", BrightRed("[ERROR]"), fmt.Sprintln(a...))
}

func ErrExtra(i instance, a ...interface{}) {
	logf("%s:%s%s %s", BrightRed("[ERROR"), Summary(i), BrightRed("]"), fmt.Sprintln(a...))
}

func Fatal(a ...interface{}) {
	logf("%s %s", BrightRed("[FATAL]"), fmt.Sprintln(a...))
	os.Exit(1)
}

func Warning(a ...interface{}) {
	logf("%s %s", Yellow("[WARN]"), fmt.Sprintln(a...))
}

func Info(a ...interface{}) {
	if !*quiet {
		logf("%s %s", BrightCyan("[INFO]"), fmt.Sprintln(a...))
	}
}

func InfoExtra(i instance, a ...interface{}) {
	if !*quiet {
		logf("%s:%s%s %s", BrightCyan("[INFO"), Summary(i), BrightCyan("]"), fmt.Sprintln(a...))
	}
}

func Debug(a ...interface{}) {
	if *debug {
		logf("%s %s", Cyan("[DEBUG]"), fmt.Sprintln(a...))
	}
}

func DebugExtra(i instance, a ...interface{}) {
	if *debug {
		logf("%s:%s%s %s", Cyan("[DEBUG"), Summary(i), Cyan("]"), fmt.Sprintln(a...))
	}
}
