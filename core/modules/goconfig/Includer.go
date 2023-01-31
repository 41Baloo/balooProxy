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
	"errors"

	"github.com/BurntSushi/toml"
)

// Defaults represents all the default inclusions registered
var Defaults map[string]Inclusion = map[string]Inclusion{

	/* Json configuration files support*/
	".json": func(b []byte, p string, m map[string]any) error {
		return json.Unmarshal(b, &m)
	},

	/* Toml configuration files support */
	".toml": func(b []byte, p string, m map[string]any) error {
		return toml.Unmarshal(b, &m)
	},
}

// Inclusion allows for you to register your own functions
type Inclusion func([]byte, string, map[string]any) error

// NewInclusion attempts to register the inclusion into the support map
func (GC *GoConfig) NewInclusion(ext string, exec Inclusion) error {
	if e, ok := GC.inclusions[ext]; e != nil || ok {
		return errors.New("file type already included")
	}

	GC.inclusions[ext] = exec
	return nil
}
