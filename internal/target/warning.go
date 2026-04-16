package target

import (
	"errors"
	"fmt"
)

type WarningError struct {
	Message string
}

func (w *WarningError) Error() string {
	return w.Message
}

func Warningf(format string, args ...any) error {
	return &WarningError{Message: fmt.Sprintf(format, args...)}
}

func SplitWarnings(err error) ([]string, error) {
	if err == nil {
		return nil, nil
	}

	var warnings []string
	var hardErrs []error

	var walk func(error)
	walk = func(current error) {
		if current == nil {
			return
		}

		var warning *WarningError
		if errors.As(current, &warning) {
			warnings = append(warnings, warning.Message)
			return
		}

		type multiUnwrapper interface {
			Unwrap() []error
		}
		if joined, ok := current.(multiUnwrapper); ok {
			for _, inner := range joined.Unwrap() {
				walk(inner)
			}
			return
		}

		hardErrs = append(hardErrs, current)
	}

	walk(err)
	return warnings, errors.Join(hardErrs...)
}
