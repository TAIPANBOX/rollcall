package main

import (
	"errors"
	"fmt"

	"github.com/TAIPANBOX/rollcall/internal/attest"
)

// attest prints, for an auditor outside the router, a statement of this
// router's state signed with its member key over the auditor's nonce
// (internal/attest, docs/attest.md). It reads the key and the own history
// straight from the state directory, with the checks the daemon's start
// makes, so it answers whether rollcalld runs or not, and it writes nothing:
// an auditor may ask every hour without wearing the flash. The nonce is
// checked before anything is read, and the command runs only as root, as the
// key is root's and rollcall's alone.
func (c *cli) attest(args []string) error {
	p, err := parse(args, nil, []string{"--nonce"})
	if err != nil {
		return err
	}
	if err := p.noWords(); err != nil {
		return err
	}
	raw, given := p.opts["--nonce"]
	if !given {
		return badUsage("rollcall attest --nonce <hex>: the nonce, 16 to 64 bytes in hex, is required")
	}
	nonce, err := attest.ParseNonce(raw)
	if err != nil {
		return badUsage("%v", err)
	}
	if c.euid == nil || c.euid() != 0 {
		return errors.New("attest signs with this router's member key, which only root may read: run it as root")
	}
	if c.bootID == nil || c.now == nil {
		return errors.New("attest cannot read the kernel's boot ID or the clock")
	}
	kernelBoot, err := c.bootID()
	if err != nil {
		return fmt.Errorf("the kernel's boot ID cannot be read: %w", err)
	}
	own, err := attest.ReadOwn(c.stateDir)
	if err != nil {
		return err
	}
	defer clear(own.ID.Sign)
	s := own.Statement(nonce, kernelBoot, version, c.now())
	signature, err := attest.Sign(own.ID.Sign, s)
	if err != nil {
		return err
	}
	out, err := attest.Encode(s, signature)
	if err != nil {
		return err
	}
	fmt.Fprintf(c.stdout, "%s\n", out)
	return nil
}
