package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"

	"github.com/TAIPANBOX/rollcall/internal/config"
	"github.com/TAIPANBOX/rollcall/internal/epoch"
	"github.com/TAIPANBOX/rollcall/internal/identity"
	"github.com/TAIPANBOX/rollcall/internal/ids"
	"github.com/TAIPANBOX/rollcall/internal/node"
	"github.com/TAIPANBOX/rollcall/internal/roster"
	"github.com/TAIPANBOX/rollcall/internal/store"
)

// # init
//
// init creates the group on its first router (security spec 6): this
// router's identity, when it has none yet, a roster of one member that is the
// primary admin, the first epoch key, and the recovery key, whose seed is
// printed once as the recovery code and stored nowhere. It works on the state
// directory itself, not through rollcalld; a running daemon finds the new
// state within a few seconds.
//
// identity.Save replaces whatever identity is there, so init saves one only
// after identity.Load reported that there is none (fs.ErrNotExist). A
// directory that already holds a roster belongs to a group: init refuses,
// and prints no code.

// firstEpochID is the first epoch key's ID: sequence 1, made by the primary
// (node: IDs are sequence << 2 | authority).
const firstEpochID = 1 << 2

// defaultSite names the group in the roster when neither --site nor the
// site option is a valid name. Messages use the site option when it is set.
const defaultSite = "home"

func (c *cli) initGroup(args []string) error {
	p, err := parse(args, nil, []string{"--name", "--site"})
	if err != nil {
		return err
	}
	if err := p.noWords(); err != nil {
		return err
	}
	name, err := c.routerName(p.opts["--name"])
	if err != nil {
		return err
	}
	site, err := c.siteName(p.opts["--site"])
	if err != nil {
		return err
	}

	st, err := store.Open(c.stateDir)
	if err != nil {
		return err
	}
	switch _, err := st.ReadFile(node.FileRoster); {
	case err == nil:
		return fmt.Errorf("this router belongs to a group already (%s holds its roster); init does not replace it", c.stateDir)
	case !errors.Is(err, fs.ErrNotExist):
		return fmt.Errorf("the state directory cannot be read: %w", err)
	}
	id, err := identity.Load(c.stateDir)
	if errors.Is(err, fs.ErrNotExist) {
		if id, err = identity.Generate(); err == nil {
			err = id.Save(c.stateDir)
		}
	}
	if err != nil {
		return fmt.Errorf("this router's identity: %w", err)
	}

	recPub, recKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	defer clear(recKey)
	r := roster.Roster{
		Version: 1, Site: site, RecoveryPub: recPub, Admins: []ids.MemberID{id.ID},
		Members: []roster.Member{{
			ID: id.ID, Name: name, Roles: []roster.Role{roster.RolePrimary},
			SignPub: id.Sign.Public().(ed25519.PublicKey), RecvPub: id.Recv.PublicKey().Bytes(),
		}},
	}
	signed, err := roster.SignRoster(r, id.ID, id.Sign, false)
	if err != nil {
		return err
	}
	k, err := epoch.New(firstEpochID)
	if err != nil {
		return err
	}
	if err := node.Bootstrap(st, signed, k); err != nil {
		return err
	}
	if err := handOver(c.stateDir); err != nil {
		return fmt.Errorf("the group was created, but its files could not be given to the rollcall user: %w", err)
	}

	code := formatRecoveryCode(recKey.Seed())
	msg := fmt.Sprintf("Group %s created with %s as its primary admin.", site, name)
	if p.json {
		c.printJSON(reply{OK: true, Message: msg, RecoveryCode: code})
		return nil
	}
	fmt.Fprintln(c.stdout, msg)
	fmt.Fprintln(c.stdout, "Recovery code. It is shown only now and stored nowhere. Write it on paper and keep it offline:")
	fmt.Fprintln(c.stdout, code)
	fmt.Fprintln(c.stdout, "Start rollcall with /etc/init.d/rollcall start if it is not running, then add routers with rollcall invite.")
	return nil
}

// siteName is the group's name in the roster: --site, else the site option
// when it is a valid name, else defaultSite.
func (c *cli) siteName(given string) (string, error) {
	if given != "" {
		if err := roster.ValidName(given); err != nil {
			return "", badUsage("not a valid site name: %v", err)
		}
		return given, nil
	}
	if f, err := os.Open(c.configPath); err == nil {
		secs, err := config.ParseUCI(f)
		f.Close()
		if err == nil {
			for _, s := range secs {
				if s.Type == "rollcall" && roster.ValidName(s.Options["site"]) == nil {
					return s.Options["site"], nil
				}
			}
		}
	}
	return defaultSite, nil
}

// handOver gives the files init wrote to the owner of the state directory,
// the rollcall user the daemon runs as. Run as root, init writes them as
// root, and the daemon could not read them. Only regular files are touched,
// and Lchown never follows a link.
func handOver(dir string) error {
	if os.Geteuid() != 0 {
		return nil
	}
	fi, err := os.Stat(dir)
	if err != nil {
		return err
	}
	sys, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || sys.Uid == 0 {
		return nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if !e.Type().IsRegular() {
			continue
		}
		if err := os.Lchown(filepath.Join(dir, e.Name()), int(sys.Uid), int(sys.Gid)); err != nil {
			return err
		}
	}
	return nil
}
