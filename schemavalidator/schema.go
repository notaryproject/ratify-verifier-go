/*
Copyright The Ratify Authors.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package schemavalidator

import (
	"errors"
	"fmt"

	"github.com/xeipuuv/gojsonschema"
)

// validate validates content against a schema referenced by a loader source
// (e.g. a file:// or https:// URL).
func validate(schema string, content []byte) error {
	sl := gojsonschema.NewReferenceLoader(schema)
	return validateAgainstLoader(sl, content)
}

// validateAgainstOfflineSchema validates content against a schema provided as
// raw bytes. It is useful for testing and restricted environments.
func validateAgainstOfflineSchema(schema []byte, content []byte) error {
	sl := gojsonschema.NewBytesLoader(schema)
	return validateAgainstLoader(sl, content)
}

func validateAgainstLoader(schemaLoader gojsonschema.JSONLoader, content []byte) error {
	dl := gojsonschema.NewBytesLoader(content)
	result, err := gojsonschema.Validate(schemaLoader, dl)
	if err != nil {
		return err
	}

	if result.Valid() {
		return nil
	}

	var e string
	for _, desc := range result.Errors() {
		e += fmt.Sprintf("%s:", desc.Description())
	}
	return errors.New(e)
}
