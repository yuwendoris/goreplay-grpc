package main

import (
	"encoding/json"
	"fmt"
	"testing"
)

func TestAppSettings(t *testing.T) {
	a := AppSettings{}
	data, err := json.Marshal(&a)
	if err != nil {
		panic(err)
	}
	fmt.Printf(string(data))
}
