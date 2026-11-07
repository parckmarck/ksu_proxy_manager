// Package paths describes the on-device directory layout.
package paths

import (
	"os"
	"path/filepath"
)

const (
	ModuleID         = "ksu_proxy_manager"
	DefaultModuleDir = "/data/adb/modules/" + ModuleID
	DefaultDataDir   = "/data/adb/" + ModuleID
)

type Layout struct {
	ModuleDir string
	DataDir   string
}

func Default() Layout { return Layout{ModuleDir: DefaultModuleDir, DataDir: DefaultDataDir} }

// FromEnv honours KPM_MODULE_DIR / KPM_DATA_DIR, which service scripts and tests set.
func FromEnv() Layout {
	l := Default()
	if v := os.Getenv("KPM_MODULE_DIR"); v != "" {
		l.ModuleDir = filepath.Clean(v)
	}
	if v := os.Getenv("KPM_DATA_DIR"); v != "" {
		l.DataDir = filepath.Clean(v)
	}
	return l
}

func (l Layout) ConfigDir() string    { return filepath.Join(l.DataDir, "config") }
func (l Layout) ConfigFile() string   { return filepath.Join(l.DataDir, "config", "config.json") }
func (l Layout) BackupDir() string    { return filepath.Join(l.DataDir, "config", "backups") }
func (l Layout) CoresDir() string     { return filepath.Join(l.DataDir, "cores") }
func (l Layout) CoreIndex() string    { return filepath.Join(l.DataDir, "core-index.json") }
func (l Layout) RulesetDir() string   { return filepath.Join(l.DataDir, "rulesets") }
func (l Layout) RunDir() string       { return filepath.Join(l.DataDir, "run") }
func (l Layout) Socket() string       { return filepath.Join(l.DataDir, "run", "api.sock") }
func (l Layout) DaemonLock() string   { return filepath.Join(l.DataDir, "run", "daemon.lock") }
func (l Layout) DaemonInfo() string   { return filepath.Join(l.DataDir, "run", "daemon.json") }
func (l Layout) CoreInfo() string     { return filepath.Join(l.DataDir, "run", "core.json") }
func (l Layout) CoreWorkDir() string  { return filepath.Join(l.DataDir, "run", "core") }
func (l Layout) BridgeDir() string    { return filepath.Join(l.DataDir, "run", "bridge") }
func (l Layout) StagingDir() string   { return filepath.Join(l.DataDir, "run", "staging") }
func (l Layout) LogDir() string       { return filepath.Join(l.DataDir, "logs") }
func (l Layout) DaemonLog() string    { return filepath.Join(l.DataDir, "logs", "daemon.log") }
func (l Layout) CoreLog() string      { return filepath.Join(l.DataDir, "logs", "core.log") }
func (l Layout) DeleteMarker() string { return filepath.Join(l.DataDir, ".delete-on-uninstall") }
func (l Layout) WebRoot() string      { return filepath.Join(l.ModuleDir, "webroot") }
func (l Layout) ModuleProp() string   { return filepath.Join(l.ModuleDir, "module.prop") }
func (l Layout) DisableFlag() string  { return filepath.Join(l.ModuleDir, "disable") }
func (l Layout) RemoveFlag() string   { return filepath.Join(l.ModuleDir, "remove") }

// Ensure creates every private directory with mode 0700.
func (l Layout) Ensure() error {
	for _, d := range []string{
		l.DataDir, l.ConfigDir(), l.BackupDir(), l.CoresDir(), l.RulesetDir(),
		l.RunDir(), l.CoreWorkDir(), l.BridgeDir(), l.StagingDir(), l.LogDir(),
	} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return err
		}
		if err := os.Chmod(d, 0o700); err != nil {
			return err
		}
	}
	return nil
}
