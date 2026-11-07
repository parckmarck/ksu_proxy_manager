package proc

import (
	"os"
	"testing"
)

func TestIdentityValidity(t *testing.T) {
	id, err := Capture(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	if !id.Valid() || !id.Alive() {
		t.Fatal("current process identity is not recognized")
	}
	for _, mutate := range []func(*Identity){
		func(id *Identity) { id.PID = 1 },
		func(id *Identity) { id.StartTicks = 0 },
		func(id *Identity) { id.BootID = "" },
		func(id *Identity) { id.Exe = "relative" },
	} {
		incomplete := id
		mutate(&incomplete)
		if incomplete.Valid() || incomplete.Alive() {
			t.Fatal("incomplete identity accepted", incomplete)
		}
	}
	id.StartTicks++
	if id.Alive() {
		t.Fatal("different process incarnation accepted")
	}
}
