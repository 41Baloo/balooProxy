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


// GoConfig allows you to configure the current working env before actually running the execution routes
type GoConfig struct{
	configs    map[string]any
	inclusions map[string]Inclusion
	renders    map[string][]byte
}

// NewConfig will create a brand new GoConfig instance
func NewConfig() *GoConfig {
	return &GoConfig{
		inclusions: Defaults,
		configs:    nil,
		renders:    make(map[string][]byte),
	}
}

// Parse will completely scan all the directories passed inside the vardiac function args
func (GC *GoConfig) Parse(directories ...string) error {
	if GC.configs == nil {
		GC.configs = make(map[string]any)
	}

	// ranges through all the directories provided
	for _, dir := range directories {
		if err := GC.execDir(dir); err != nil {
			return err
		}
	}

	return nil
}

// Files will return all the files and there contents in a map form
func (GC *GoConfig) Files() map[string][]byte {
	return GC.renders
}