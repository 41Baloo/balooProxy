package goconfig

import (
	"fmt"
	"reflect"
	"strconv"
)

// String will attempt to find the string type from the file presented
func (O *Options) String(p ...string) string {
	item, err := O.Get(reflect.String, p...)
	if err != nil {
		return ""
	}

	return fmt.Sprint(item)
}

// Int will attempt to find the int type from the file presented
func (O *Options) Ints(p ...string) int {
	var vectors []reflect.Kind = []reflect.Kind{
		reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64,
	}

	collection, err := O.GetFromVectors(vectors, p...)
	if err != nil {
		return 0
	}

	period, err := strconv.Atoi(fmt.Sprint(collection))
	if err != nil {
		return 0
	}

	return period
}

func (O *Options) Bool(p ...string) bool {
	item, err := O.Get(reflect.Bool, p...)
	if err != nil {
		return false
	}

	return item.(bool)
}

func (O *Options) Arrays(p ...string) []any {
	item, err := O.Get(reflect.Array, p...)
	if err != nil {
		return make([]any, 0)
	}

	return item.([]any)
}