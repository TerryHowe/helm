/*
Copyright The Helm Authors.

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

package cmd

import (
	"testing"

	chart "helm.sh/helm/v4/pkg/chart/v2"
	release "helm.sh/helm/v4/pkg/release/v1"
	helmtime "helm.sh/helm/v4/pkg/time"
)

func TestReleaseTestingCompletion(t *testing.T) {
	checkReleaseCompletion(t, "test", false)
}

func TestReleaseTestingFileCompletion(t *testing.T) {
	checkFileCompletion(t, "test", false)
	checkFileCompletion(t, "test myrelease", false)
}

func TestReleaseTestCmd(t *testing.T) {
	releaseMockWithNotes := func(notes string) []*release.Release {
		info := &release.Info{
			Status:       release.StatusDeployed,
			LastDeployed: helmtime.Unix(1452902400, 0).UTC(),
			Notes:        notes,
		}
		return []*release.Release{{
			Name:      "funny-bunny",
			Namespace: "default",
			Info:      info,
			Chart:     &chart.Chart{Metadata: &chart.Metadata{Name: "testchart", Version: "1.0.0"}},
			Hooks: []*release.Hook{{
				Name: "test-hook",
				Events: []release.HookEvent{
					release.HookTest,
				},
			}},
		}}
	}

	tests := []cmdTestCase{{
		name:   "test command hides notes by default",
		cmd:    "test funny-bunny",
		golden: "output/test-hidden-notes.txt",
		rels:   releaseMockWithNotes("These are some release notes that should be hidden by default"),
	}, {
		name:   "test command shows notes with --show-notes flag",
		cmd:    "test funny-bunny --show-notes",
		golden: "output/test-shown-notes.txt",
		rels:   releaseMockWithNotes("These are some release notes that should be shown with --show-notes"),
	}, {
		name:   "test command hides notes with --hide-notes flag (legacy behavior)",
		cmd:    "test funny-bunny --hide-notes",
		golden: "output/test-hidden-notes-legacy.txt",
		rels:   releaseMockWithNotes("These are some release notes that should be hidden with --hide-notes"),
	}}

	runTestCmd(t, tests)
}
