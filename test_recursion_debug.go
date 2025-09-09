package main

import (
	"fmt"
	"time"
	
	"helm.sh/helm/v4/pkg/chart/common"
	chart "helm.sh/helm/v4/pkg/chart/v2"
	"helm.sh/helm/v4/pkg/engine"
)

func main() {
	// Recreate the problematic chart from the test
	d := &chart.Chart{
		Metadata: &chart.Metadata{Name: "nested"},
		Templates: []*common.File{
			{Name: "templates/quote", Data: []byte(`{{include "nested/templates/quote" . | indent 2}} dead.`)},
			{Name: "templates/_partial", Data: []byte(`{{.Release.Name}} - he`)},
		},
	}

	v := common.Values{
		"Values": "",
		"Chart":  d.Metadata,
		"Release": common.Values{
			"Name": "Mistah Kurtz",
		},
	}

	fmt.Println("Starting render...")
	start := time.Now()
	_, err := engine.Render(d, v)
	duration := time.Since(start)
	
	fmt.Printf("Duration: %v\n", duration)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	} else {
		fmt.Println("No error - unexpected!")
	}
}