package geoip

import (
	"net/http"
	"testing"
)

func TestGetGeo(t *testing.T) {
	geo, err := GetGeo("127.0.0.1:7890")
	if err != nil {
		t.Error(err)
		return
	}
	t.Log(geo)
}

func TestEndpoint(t *testing.T) {
	for i, f := range tryOrder {
		res := f(http.DefaultClient)
		if res != nil {
			t.Log(res)
		} else {
			t.Logf("No geoip found in %d", i)
		}
	}
}
