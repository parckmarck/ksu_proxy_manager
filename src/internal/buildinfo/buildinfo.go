// Package buildinfo carries version metadata injected at link time.
package buildinfo

var (
	Version     = "2.1.4"
	VersionCode = "20104"
	ID          = "dev"
)

func String() string {
	return "ksu_proxy_manager " + Version + " (" + VersionCode + ", build " + ID + ")"
}
