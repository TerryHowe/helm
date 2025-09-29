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

package copystructure

import (
	"testing"

	mitchellh "github.com/mitchellh/copystructure"
)

type ComplexStruct struct {
	Name     string
	Values   map[string]interface{}
	Items    []interface{}
	Metadata *map[string]string
	Config   struct {
		Enabled bool
		Count   int
		Tags    []string
	}
}

func createTestData() *ComplexStruct {
	metadata := map[string]string{
		"version": "1.0.0",
		"author":  "helm-team",
		"env":     "test",
	}

	return &ComplexStruct{
		Name: "test-chart",
		Values: map[string]interface{}{
			"image": map[string]interface{}{
				"repository": "nginx",
				"tag":        "1.21.0",
				"pullPolicy": "IfNotPresent",
			},
			"service": map[string]interface{}{
				"type": "ClusterIP",
				"port": 80,
			},
			"ingress": map[string]interface{}{
				"enabled": false,
				"hosts": []interface{}{
					map[string]interface{}{
						"host":  "chart-example.local",
						"paths": []interface{}{"/"},
					},
				},
			},
			"resources": map[string]interface{}{
				"limits": map[string]interface{}{
					"cpu":    "100m",
					"memory": "128Mi",
				},
				"requests": map[string]interface{}{
					"cpu":    "100m",
					"memory": "128Mi",
				},
			},
		},
		Items: []interface{}{
			"item1",
			42,
			true,
			map[string]interface{}{
				"nested": "value",
				"count":  3,
			},
			[]interface{}{"a", "b", "c"},
		},
		Metadata: &metadata,
		Config: struct {
			Enabled bool
			Count   int
			Tags    []string
		}{
			Enabled: true,
			Count:   5,
			Tags:    []string{"helm", "kubernetes", "chart"},
		},
	}
}

func BenchmarkInternalCopy(b *testing.B) {
	testData := createTestData()
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, err := Copy(testData)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkMitchellhCopy(b *testing.B) {
	testData := createTestData()
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, err := mitchellh.Copy(testData)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkInternalCopyLargeMap(b *testing.B) {
	largeMap := make(map[string]interface{})
	for i := 0; i < 1000; i++ {
		largeMap[string(rune('a'+i%26))+string(rune('A'+i/26))] = map[string]interface{}{
			"id":    i,
			"name":  "item" + string(rune('0'+i%10)),
			"value": float64(i) * 1.5,
			"tags":  []interface{}{"tag1", "tag2", i},
		}
	}
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, err := Copy(largeMap)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkMitchellhCopyLargeMap(b *testing.B) {
	largeMap := make(map[string]interface{})
	for i := 0; i < 1000; i++ {
		largeMap[string(rune('a'+i%26))+string(rune('A'+i/26))] = map[string]interface{}{
			"id":    i,
			"name":  "item" + string(rune('0'+i%10)),
			"value": float64(i) * 1.5,
			"tags":  []interface{}{"tag1", "tag2", i},
		}
	}
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, err := mitchellh.Copy(largeMap)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkInternalCopyDeepNested(b *testing.B) {
	nested := make(map[string]interface{})
	current := nested
	for i := 0; i < 50; i++ {
		next := make(map[string]interface{})
		current["level"] = i
		current["data"] = []interface{}{i, i * 2, i * 3}
		current["next"] = next
		current = next
	}
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, err := Copy(nested)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkMitchellhCopyDeepNested(b *testing.B) {
	nested := make(map[string]interface{})
	current := nested
	for i := 0; i < 50; i++ {
		next := make(map[string]interface{})
		current["level"] = i
		current["data"] = []interface{}{i, i * 2, i * 3}
		current["next"] = next
		current = next
	}
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, err := mitchellh.Copy(nested)
		if err != nil {
			b.Fatal(err)
		}
	}
}
