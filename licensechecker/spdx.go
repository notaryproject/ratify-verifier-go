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

package licensechecker

import (
	"strings"

	"github.com/spdx/tools-golang/spdx"
	"github.com/spdx/tools-golang/tagvalue"
)

// blobToSPDX parses an SPDX document in tag-value format from a blob.
func blobToSPDX(blob []byte) (*spdx.Document, error) {
	return tagvalue.Read(strings.NewReader(string(blob)))
}

// getPackageLicenses extracts the concluded license of every package in the
// SPDX document.
func getPackageLicenses(doc *spdx.Document) []PackageLicense {
	output := []PackageLicense{}
	for _, p := range doc.Packages {
		output = append(output, PackageLicense{
			PackageName:    p.PackageName,
			PackageLicense: p.PackageLicenseConcluded,
		})
	}
	return output
}

// loadAllowedLicenses converts the slice of allowed licenses to a set for
// efficient lookup.
func loadAllowedLicenses(licenses []string) map[string]struct{} {
	output := map[string]struct{}{}
	for _, license := range licenses {
		output[license] = struct{}{}
	}
	return output
}

// filterPackageLicenses returns the packages whose concluded license is not in
// the set of allowed licenses.
func filterPackageLicenses(packageLicenses []PackageLicense, allowedLicenses map[string]struct{}) []PackageLicense {
	var output []PackageLicense
	for _, packageLicense := range packageLicenses {
		if _, ok := allowedLicenses[packageLicense.PackageLicense]; !ok {
			output = append(output, packageLicense)
		}
	}
	return output
}
