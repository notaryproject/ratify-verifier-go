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

package sbom

import (
	"regexp"

	"github.com/spdx/tools-golang/spdx"
)

// getPackageLicenses extracts the name, version, and concluded license of every
// package in the SPDX document.
func getPackageLicenses(doc spdx.Document) []PackageLicense {
	output := []PackageLicense{}
	for _, p := range doc.Packages {
		output = append(output, PackageLicense{
			Name:    p.PackageName,
			Version: p.PackageVersion,
			License: p.PackageLicenseConcluded,
		})
	}
	return output
}

// containsLicense reports whether the SPDX license expression contains the
// disallowed license as a whole word. The word boundary can be the beginning or
// end of the line, a whitespace, or a bracket.
func containsLicense(spdxLicenseExpression string, disallowed string) bool {
	escapedLicense := regexp.QuoteMeta(disallowed)
	expression := "(?:^|\\(|\\s)(" + escapedLicense + ")(?:$|\\)|\\s)"
	r := regexp.MustCompile(expression)
	return r.MatchString(spdxLicenseExpression)
}
