package yoohoo

import (
	"bytes"
	"errors"
	"fmt"
	"reflect"
	"testing"
)

// The assertion helpers the tests use. assert reports and carries on;
// require stops the test. Kept to what this package's tests call, so
// the module has no dependency outside the standard library.

type assertions struct{ fatal bool }

var (
	assert  = assertions{fatal: false}
	require = assertions{fatal: true}
)

func (a assertions) fail(t testing.TB, what string, msgAndArgs []any) bool {
	t.Helper()
	if len(msgAndArgs) > 0 {
		if format, ok := msgAndArgs[0].(string); ok {
			what += ": " + fmt.Sprintf(format, msgAndArgs[1:]...)
		} else {
			what += ": " + fmt.Sprint(msgAndArgs...)
		}
	}
	if a.fatal {
		t.Fatal(what)
	} else {
		t.Error(what)
	}
	return false
}

func (a assertions) Equal(t testing.TB, want, got any, msgAndArgs ...any) bool {
	t.Helper()
	if objectsEqual(want, got) {
		return true
	}
	return a.fail(t, fmt.Sprintf("not equal:\n  want: %#v\n  got:  %#v", want, got), msgAndArgs)
}

func (a assertions) Error(t testing.TB, err error, msgAndArgs ...any) bool {
	t.Helper()
	if err != nil {
		return true
	}
	return a.fail(t, "an error is expected", msgAndArgs)
}

func (a assertions) ErrorIs(t testing.TB, err, target error, msgAndArgs ...any) bool {
	t.Helper()
	if errors.Is(err, target) {
		return true
	}
	return a.fail(t, fmt.Sprintf("error %v is not %v", err, target), msgAndArgs)
}

func (a assertions) False(t testing.TB, v bool, msgAndArgs ...any) bool {
	t.Helper()
	if !v {
		return true
	}
	return a.fail(t, "should be false", msgAndArgs)
}

func (a assertions) Len(t testing.TB, v any, n int, msgAndArgs ...any) bool {
	t.Helper()
	if got := reflect.ValueOf(v).Len(); got != n {
		return a.fail(t, fmt.Sprintf("length %d, want %d: %#v", got, n, v), msgAndArgs)
	}
	return true
}

func (a assertions) NoError(t testing.TB, err error, msgAndArgs ...any) bool {
	t.Helper()
	if err == nil {
		return true
	}
	return a.fail(t, fmt.Sprintf("unexpected error: %v", err), msgAndArgs)
}

func (a assertions) NotNil(t testing.TB, v any, msgAndArgs ...any) bool {
	t.Helper()
	if !isNil(v) {
		return true
	}
	return a.fail(t, "should not be nil", msgAndArgs)
}

func (a assertions) True(t testing.TB, v bool, msgAndArgs ...any) bool {
	t.Helper()
	if v {
		return true
	}
	return a.fail(t, "should be true", msgAndArgs)
}

// objectsEqual is reflect.DeepEqual, except that two byte slices compare
// by content and nil-ness.
func objectsEqual(want, got any) bool {
	wb, ok := want.([]byte)
	if !ok {
		return reflect.DeepEqual(want, got)
	}
	gb, ok := got.([]byte)
	return ok && (wb == nil) == (gb == nil) && bytes.Equal(wb, gb)
}

func isNil(v any) bool {
	if v == nil {
		return true
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Pointer, reflect.Map, reflect.Slice, reflect.Chan, reflect.Func, reflect.Interface:
		return rv.IsNil()
	}
	return false
}
