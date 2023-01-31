/*
	MIT License

	Copyright (c) 2022 TheNosviak

	Permission is hereby granted, free of charge, to any person obtaining a copy
	of this software and associated documentation files (the "Software"), to deal
	in the Software without restriction, including without limitation the rights
	to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
	copies of the Software, and to permit persons to whom the Software is
	furnished to do so, subject to the following conditions:

	The above copyright notice and this permission notice shall be included in all
	copies or substantial portions of the Software.

	THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
	IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
	FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
	AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
	LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
	OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
	SOFTWARE.
*/

package goconfig

import (
	"encoding/json"
	"reflect"
)

// Marshal will convert the entire options map into a map, then attempt to convert into the corresponding type given
func (GC *Options) MarshalEntire(v any) error {
	return GC.toValue(GC.config.configs, v)
}

// MarshalFromPath allows you to marshal from a specific point inside the map
func (GC *Options) MarshalFromPath(v any, path ...string) error {
	item, err := GC.Get(reflect.Map, path...)
	if err != nil {
		return err
	}

	return GC.toValue(item.(map[string]any), v)
}

// Allows for the people using this package to use both the builtin get function and fill structures fields with this package.
func (GC *Options) toValue(scope map[string]any, v any) error {
	entire, err := json.Marshal(scope)
	if err != nil {
		return err
	}

	return json.Unmarshal(entire, &v)
}
