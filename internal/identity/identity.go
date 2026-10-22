// Package identity keeps a member's long-term identity and its boot sequence
// number in the member's private directory (/etc/rollcall on a router).
//
// An identity is created once, on the router at first start, and never
// leaves it: a member ID, an Ed25519 key that signs everything the member
// says, and an HPKE MLKEM768-X25519 key that receives epoch keys. Save writes
// it to identity.json:
//
//	{"version":1,"id":"<32 hex digits>",
//	 "sign_seed":"<base64>","sign_public":"<base64>",
//	 "recv_seed":"<base64>","recv_public":"<base64>","sha256":"<64 hex digits>"}
//
// The public keys are stored beside the seeds so that Load can check that
// the keys it derives are the ones the peers know, and sha256 covers the
// member ID as well, so that a damaged file is refused rather than loaded as
// a different identity. It is a checksum, not a seal: whoever can write the
// file can also write a consistent one.
//
// The boot sequence number lives in bootseq.json as {"boot_seq":N}, the
// number handed out last. NextBootSeq raises it by one, with one write, once
// per boot.
//
// Files are replaced atomically (a temporary file in the same directory,
// fsync, rename, fsync of the directory) and get mode 0600; a directory this
// package creates gets mode 0700. Reading fails closed: a file with any
// permission for group or others, or a directory that group or others can
// write, is refused with ErrPermissions, and a file that does not decode
// (an unknown field, data after the object, a key of the wrong length) or
// whose keys do not match each other or the checksum is refused with
// ErrCorrupt. A missing file is reported as an error wrapping
// fs.ErrNotExist, and only then.
//
// Nothing here locks the directory: one process owns it, and calls
// NextBootSeq and RaiseBootSeq from one goroutine at a time.
package identity

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hpke"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"os"
	"path/filepath"

	"github.com/TAIPANBOX/rollcall/internal/ids"
	"github.com/TAIPANBOX/rollcall/internal/sig"
)

const (
	identityFile    = "identity.json"
	bootSeqFile     = "bootseq.json"
	fileVersion     = 1
	maxIdentityFile = 8 << 10 // a saved identity is about 2 KiB
	maxBootSeqFile  = 256
	checksumLabel   = "rollcall/v1 identity\x00"
)

// recvKEM is the KEM of every receive key.
var recvKEM = hpke.MLKEM768X25519()

var (
	// ErrPermissions reports a file that group or others may access in any
	// way, a directory that group or others may write, or a directory path
	// that is not a directory.
	ErrPermissions = errors.New("identity: file or directory is open to group or others")
	// ErrCorrupt reports a file that does not decode, or whose keys do not
	// match each other or the checksum.
	ErrCorrupt = errors.New("identity: file is corrupt")
	// ErrInvalid reports an Identity that Save refuses to write.
	ErrInvalid = errors.New("identity: invalid identity")
	// ErrBootSeqExhausted reports a stored boot sequence number that is
	// already the largest uint64.
	ErrBootSeqExhausted = errors.New("identity: boot sequence number exhausted")
)

// Identity is a member's long-term identity.
type Identity struct {
	ID   ids.MemberID       // the member's ID in the roster
	Sign ed25519.PrivateKey // signs everything the member says
	Recv hpke.PrivateKey    // MLKEM768-X25519; receives epoch keys
}

// String returns "identity " followed by the member ID.
func (i Identity) String() string { return "identity " + i.ID.String() }

// Format prints String for every verb, so that no fmt verb, %#v and %d
// included, can print a private key into a log.
func (i Identity) Format(s fmt.State, _ rune) { io.WriteString(s, i.String()) }

// identityJSON is the content of identity.json.
type identityJSON struct {
	Version    int          `json:"version"`
	ID         ids.MemberID `json:"id"`
	SignSeed   []byte       `json:"sign_seed"`
	SignPublic []byte       `json:"sign_public"`
	RecvSeed   []byte       `json:"recv_seed"`
	RecvPublic []byte       `json:"recv_public"`
	SHA256     string       `json:"sha256"`
}

// checksum returns the lowercase hex SHA-256 of the label, the member ID and
// the four key fields in file order. Every field has a fixed length by the
// time Load compares it, so the concatenation is unambiguous.
func (f *identityJSON) checksum() string {
	h := sha256.New()
	h.Write([]byte(checksumLabel))
	h.Write(f.ID[:])
	h.Write(f.SignSeed)
	h.Write(f.SignPublic)
	h.Write(f.RecvSeed)
	h.Write(f.RecvPublic)
	return hex.EncodeToString(h.Sum(nil))
}

// Generate returns a new identity: a random member ID, a new Ed25519 key and
// a new MLKEM768-X25519 key.
func Generate() (*Identity, error) {
	id, err := ids.NewMemberID()
	if err != nil {
		return nil, fmt.Errorf("identity: member ID: %w", err)
	}
	_, sign, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, fmt.Errorf("identity: signing key: %w", err)
	}
	recv, err := recvKEM.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("identity: receive key: %w", err)
	}
	return &Identity{ID: id, Sign: sign, Recv: recv}, nil
}

// Save writes the identity to dir/identity.json, replacing any identity
// there, with mode 0600. If dir does not exist it is created with mode 0700;
// its parent must exist. An existing dir that group or others can write is
// refused with ErrPermissions. An identity that Load could not read back
// exactly is refused with ErrInvalid, and nothing is written.
//
// Save replaces the file even if it holds another identity; a caller that
// starts a member calls Save only after Load reported fs.ErrNotExist.
func (i *Identity) Save(dir string) error {
	f, err := i.record()
	if err != nil {
		return err
	}
	data, err := json.Marshal(f)
	if err != nil {
		return fmt.Errorf("identity: encode: %w", err)
	}
	return writeFile(dir, identityFile, append(data, '\n'))
}

// record returns the file content for i, or ErrInvalid. It does not modify
// i, and the returned record shares no memory with it: hpke's Bytes returns
// the key's own seed slice.
func (i *Identity) record() (*identityJSON, error) {
	if i == nil {
		return nil, fmt.Errorf("%w: nil identity", ErrInvalid)
	}
	if i.ID == (ids.MemberID{}) {
		return nil, fmt.Errorf("%w: the member ID is all zero", ErrInvalid)
	}
	if len(i.Sign) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("%w: the signing key is %d bytes, want %d", ErrInvalid, len(i.Sign), ed25519.PrivateKeySize)
	}
	seed := i.Sign.Seed()
	pub := bytes.Clone(i.Sign[ed25519.SeedSize:])
	if err := sig.ValidPublicKey(pub); err != nil {
		return nil, fmt.Errorf("%w: signing key: %w", ErrInvalid, err)
	}
	if !bytes.Equal(ed25519.NewKeyFromSeed(seed)[ed25519.SeedSize:], pub) {
		return nil, fmt.Errorf("%w: the signing key's public half does not belong to its seed", ErrInvalid)
	}
	if i.Recv == nil {
		return nil, fmt.Errorf("%w: no receive key", ErrInvalid)
	}
	if id := i.Recv.KEM().ID(); id != recvKEM.ID() {
		return nil, fmt.Errorf("%w: the receive key's KEM is %#04x, want MLKEM768-X25519 %#04x", ErrInvalid, id, recvKEM.ID())
	}
	recvSeed, err := i.Recv.Bytes()
	if err != nil {
		return nil, fmt.Errorf("%w: receive key: %w", ErrInvalid, err)
	}
	f := &identityJSON{
		Version:    fileVersion,
		ID:         i.ID,
		SignSeed:   seed,
		SignPublic: pub,
		RecvSeed:   bytes.Clone(recvSeed),
		RecvPublic: i.Recv.PublicKey().Bytes(),
	}
	f.SHA256 = f.checksum()
	return f, nil
}

// Load reads the identity in dir/identity.json. An error wrapping
// fs.ErrNotExist means there is no identity yet, and is the only error after
// which a caller may Generate and Save a new one. Any other error means the
// identity is there but unusable: ErrPermissions, ErrCorrupt (with
// sig.ErrKeyLength or sig.ErrSmallOrderKey for a bad public signing key), or
// an I/O error.
func Load(dir string) (*Identity, error) {
	data, err := readFile(dir, identityFile, maxIdentityFile)
	if err != nil {
		return nil, err
	}
	var f identityJSON
	if err := decodeStrict(data, &f); err != nil {
		return nil, corrupt(identityFile, "%v", err)
	}
	if f.Version != fileVersion {
		return nil, corrupt(identityFile, "version %d, want %d", f.Version, fileVersion)
	}
	if f.ID == (ids.MemberID{}) {
		return nil, corrupt(identityFile, "the member ID is all zero")
	}
	if err := sig.ValidPublicKey(f.SignPublic); err != nil {
		return nil, fmt.Errorf("%w: %s: sign_public: %w", ErrCorrupt, identityFile, err)
	}
	if len(f.SignSeed) != ed25519.SeedSize {
		return nil, corrupt(identityFile, "sign_seed is %d bytes, want %d", len(f.SignSeed), ed25519.SeedSize)
	}
	sign := ed25519.NewKeyFromSeed(f.SignSeed)
	if !bytes.Equal(sign[ed25519.SeedSize:], f.SignPublic) {
		return nil, corrupt(identityFile, "sign_seed does not belong to sign_public")
	}
	recv, err := recvKEM.NewPrivateKey(f.RecvSeed)
	if err != nil {
		return nil, corrupt(identityFile, "recv_seed: %v", err)
	}
	if !bytes.Equal(recv.PublicKey().Bytes(), f.RecvPublic) {
		return nil, corrupt(identityFile, "recv_seed does not belong to recv_public")
	}
	if subtle.ConstantTimeCompare([]byte(f.SHA256), []byte(f.checksum())) != 1 {
		return nil, corrupt(identityFile, "the sha256 checksum does not match the content")
	}
	return &Identity{ID: f.ID, Sign: sign, Recv: recv}, nil
}

// bootSeqJSON is the content of bootseq.json. The pointer tells a missing
// number from a zero.
type bootSeqJSON struct {
	BootSeq *uint64 `json:"boot_seq"`
}

// NextBootSeq returns this boot's sequence number: one more than the number
// stored in dir, or 1 if dir holds none. The new number is stored, durably,
// before it is returned, so a number is never handed out twice; call it once
// per boot. A stored number that is already the largest uint64 gives
// ErrBootSeqExhausted. Only a missing directory or file means a fresh start:
// any other error reading it (permissions, corrupt or oversized content,
// I/O) is returned, and nothing is written.
func NextBootSeq(dir string) (uint64, error) {
	last, err := readBootSeq(dir)
	if err != nil {
		return 0, err
	}
	if last == math.MaxUint64 {
		return 0, ErrBootSeqExhausted
	}
	if err := writeBootSeq(dir, last+1); err != nil {
		return 0, err
	}
	return last + 1, nil
}

// RaiseBootSeq makes the next NextBootSeq return at least atLeast+1. If the
// stored number is below atLeast it stores atLeast; otherwise it writes
// nothing. It never lowers the stored number.
func RaiseBootSeq(dir string, atLeast uint64) error {
	last, err := readBootSeq(dir)
	if err != nil {
		return err
	}
	if last >= atLeast {
		return nil
	}
	return writeBootSeq(dir, atLeast)
}

// readBootSeq returns the stored boot sequence number, or 0 if dir or the
// file does not exist. Every other error is returned: a fresh start over a
// file that is there would hand out numbers peers have already seen.
func readBootSeq(dir string) (uint64, error) {
	data, err := readFile(dir, bootSeqFile, maxBootSeqFile)
	if errors.Is(err, fs.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	var f bootSeqJSON
	if err := decodeStrict(data, &f); err != nil {
		return 0, corrupt(bootSeqFile, "%v", err)
	}
	if f.BootSeq == nil {
		return 0, corrupt(bootSeqFile, "boot_seq is missing")
	}
	return *f.BootSeq, nil
}

func writeBootSeq(dir string, n uint64) error {
	data, err := json.Marshal(bootSeqJSON{BootSeq: &n})
	if err != nil {
		return fmt.Errorf("identity: encode: %w", err)
	}
	return writeFile(dir, bootSeqFile, append(data, '\n'))
}

func corrupt(file, format string, args ...any) error {
	return fmt.Errorf("%w: %s: %s", ErrCorrupt, file, fmt.Sprintf(format, args...))
}

// decodeStrict decodes exactly one JSON value into v: unknown fields and
// anything but white space after the value are errors. encoding/json matches
// field names without regard to case, which can only yield the same values.
func decodeStrict(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return errors.New("data after the JSON value")
	}
	return nil
}

// checkDir returns ErrPermissions unless dir is a directory that group and
// others cannot write. It follows a symbolic link.
func checkDir(dir string) error {
	fi, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("identity: %w", err)
	}
	if !fi.IsDir() {
		return fmt.Errorf("%w: %s is not a directory", ErrPermissions, dir)
	}
	if perm := fi.Mode().Perm(); perm&0o022 != 0 {
		return fmt.Errorf("%w: directory %s has mode %04o; group and others must not write it", ErrPermissions, dir, perm)
	}
	return nil
}

// readFile returns the content of dir/name after checking dir with
// checkDir, and that the file it opened is a regular file that group and
// others have no permission for. A file over max bytes is ErrCorrupt.
func readFile(dir, name string, max int) ([]byte, error) {
	if err := checkDir(dir); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, name)
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("identity: %w", err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("identity: %w", err)
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: %s is not a regular file", ErrCorrupt, path)
	}
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		return nil, fmt.Errorf("%w: %s has mode %04o; group and others must have no access", ErrPermissions, path, perm)
	}
	data, err := io.ReadAll(io.LimitReader(f, int64(max)+1))
	if err != nil {
		return nil, fmt.Errorf("identity: read %s: %w", path, err)
	}
	if len(data) > max {
		return nil, fmt.Errorf("%w: %s is larger than %d bytes", ErrCorrupt, path, max)
	}
	return data, nil
}

// makeDir creates dir with mode 0700, or checks an existing one with
// checkDir. The parent must exist.
func makeDir(dir string) error {
	err := os.Mkdir(dir, 0o700)
	if errors.Is(err, fs.ErrExist) {
		return checkDir(dir)
	}
	if err != nil {
		return fmt.Errorf("identity: %w", err)
	}
	// Mkdir applies the umask; the mode must be 0700 whatever the umask is.
	if err := os.Chmod(dir, 0o700); err != nil {
		return fmt.Errorf("identity: %w", err)
	}
	return nil
}

// writeFile replaces dir/name with data, mode 0600: it writes a temporary
// file in dir, syncs it, renames it over name and syncs dir. A reader sees
// the old content or the new, never a mix. On failure the temporary file is
// removed.
func writeFile(dir, name string, data []byte) error {
	if err := makeDir(dir); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "."+name+".*")
	if err != nil {
		return fmt.Errorf("identity: %w", err)
	}
	if err := fillAndClose(tmp, data); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	if err := os.Rename(tmp.Name(), filepath.Join(dir, name)); err != nil {
		os.Remove(tmp.Name())
		return fmt.Errorf("identity: %w", err)
	}
	return syncDir(dir)
}

// fillAndClose sets f to mode 0600, writes data, syncs and closes f.
func fillAndClose(f *os.File, data []byte) error {
	err := f.Chmod(0o600)
	if err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return fmt.Errorf("identity: write %s: %w", f.Name(), err)
	}
	return nil
}

// syncDir makes a rename in dir durable.
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("identity: %w", err)
	}
	err = d.Sync()
	if cerr := d.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return fmt.Errorf("identity: sync %s: %w", dir, err)
	}
	return nil
}
