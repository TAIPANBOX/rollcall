package identity

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hpke"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/TAIPANBOX/rollcall/internal/ids"
	"github.com/TAIPANBOX/rollcall/internal/sig"
)

// The on-disk names, written out here rather than taken from the package, so
// a rename shows up as a failing test.
const (
	identityName = "identity.json"
	bootSeqName  = "bootseq.json"
	xwingKEMID   = 0x647a // MLKEM768-X25519, draft-ietf-hpke-pq
)

var b64 = base64.StdEncoding

// newDir returns a path for a rollcall directory that does not exist yet.
func newDir(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "rollcall")
}

func mustGenerate(t *testing.T) *Identity {
	t.Helper()
	id, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	return id
}

func mustSave(t *testing.T, id *Identity, dir string) {
	t.Helper()
	if err := id.Save(dir); err != nil {
		t.Fatalf("Save(%s): %v", dir, err)
	}
}

func mustLoad(t *testing.T, dir string) *Identity {
	t.Helper()
	id, err := Load(dir)
	if err != nil {
		t.Fatalf("Load(%s): %v", dir, err)
	}
	return id
}

func permOf(t *testing.T, path string) fs.FileMode {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	return fi.Mode().Perm()
}

func chmod(t *testing.T, path string, mode fs.FileMode) {
	t.Helper()
	if err := os.Chmod(path, mode); err != nil {
		t.Fatalf("chmod %s %04o: %v", path, mode, err)
	}
}

// names lists the entries of dir, so a test can see stray temporary files.
func names(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir %s: %v", dir, err)
	}
	var out []string
	for _, e := range entries {
		out = append(out, e.Name())
	}
	return out
}

func recvSeed(t *testing.T, k hpke.PrivateKey) []byte {
	t.Helper()
	b, err := k.Bytes()
	if err != nil {
		t.Fatalf("Recv.Bytes: %v", err)
	}
	return bytes.Clone(b)
}

// requireSame fails unless got holds exactly want's ID and keys.
func requireSame(t *testing.T, got, want *Identity) {
	t.Helper()
	if got.ID != want.ID {
		t.Fatalf("ID = %s, want %s", got.ID, want.ID)
	}
	if !bytes.Equal(got.Sign, want.Sign) {
		t.Fatalf("Sign differs from the saved key")
	}
	if !bytes.Equal(recvSeed(t, got.Recv), recvSeed(t, want.Recv)) {
		t.Fatalf("Recv seed differs from the saved key")
	}
	if !bytes.Equal(got.Recv.PublicKey().Bytes(), want.Recv.PublicKey().Bytes()) {
		t.Fatalf("Recv public key differs from the saved key")
	}
}

// checksumOf is the test's own statement of the file checksum: SHA-256 over
// "rollcall/v1 identity\x00", then the member ID and the four key fields in
// file order. Fields that do not decode count as empty.
func checksumOf(m map[string]any) string {
	field := func(k string) []byte {
		s, _ := m[k].(string)
		b, _ := b64.DecodeString(s)
		return b
	}
	idHex, _ := m["id"].(string)
	id, _ := hex.DecodeString(idHex)
	h := sha256.New()
	h.Write([]byte("rollcall/v1 identity\x00"))
	h.Write(id)
	for _, k := range []string{"sign_seed", "sign_public", "recv_seed", "recv_public"} {
		h.Write(field(k))
	}
	return hex.EncodeToString(h.Sum(nil))
}

func readFields(t *testing.T, dir string) map[string]any {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, identityName))
	if err != nil {
		t.Fatalf("read %s: %v", identityName, err)
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("decode %s: %v", identityName, err)
	}
	return m
}

// editFile changes the fields of identity.json in dir, recomputes the
// checksum when fix is true, and writes the file back, keeping its mode.
func editFile(t *testing.T, dir string, fix bool, edit func(m map[string]any)) {
	t.Helper()
	m := readFields(t, dir)
	edit(m)
	if fix {
		m["sha256"] = checksumOf(m)
	}
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	writeRaw(t, dir, identityName, out)
}

// writeRaw replaces dir/name with data, mode 0600.
func writeRaw(t *testing.T, dir, name string, data []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	chmod(t, filepath.Join(dir, name), 0o600)
}

func TestIdentitySaveLoad(t *testing.T) {
	id := mustGenerate(t)
	dir := newDir(t)
	mustSave(t, id, dir)

	if got := permOf(t, dir); got != 0o700 {
		t.Fatalf("directory mode %04o, want 0700", got)
	}
	if got := permOf(t, filepath.Join(dir, identityName)); got != 0o600 {
		t.Fatalf("%s mode %04o, want 0600", identityName, got)
	}
	if got := names(t, dir); !slices.Equal(got, []string{identityName}) {
		t.Fatalf("directory holds %q, want only %s", got, identityName)
	}

	got := mustLoad(t, dir)
	requireSame(t, got, id)
	if got.Recv.KEM().ID() != xwingKEMID {
		t.Fatalf("loaded Recv KEM %#x, want MLKEM768-X25519 %#x", got.Recv.KEM().ID(), xwingKEMID)
	}

	// The loaded keys work with the public halves the peers already hold.
	msg := []byte("CANARY-123:abc")
	s := sig.Sign(got.Sign, "test", msg)
	if !sig.Verify(id.Sign.Public().(ed25519.PublicKey), "test", msg, s) {
		t.Fatalf("a signature by the loaded key does not verify under the saved public key")
	}
	ct, err := hpke.Seal(id.Recv.PublicKey(), hpke.HKDFSHA256(), hpke.ChaCha20Poly1305(), []byte("info"), msg)
	if err != nil {
		t.Fatalf("hpke.Seal: %v", err)
	}
	pt, err := hpke.Open(got.Recv, hpke.HKDFSHA256(), hpke.ChaCha20Poly1305(), []byte("info"), ct)
	if err != nil || !bytes.Equal(pt, msg) {
		t.Fatalf("the loaded Recv key cannot open what was sealed to the saved public key: %q, %v", pt, err)
	}
}

func TestIdentityFileFormat(t *testing.T) {
	id := mustGenerate(t)
	dir := newDir(t)
	mustSave(t, id, dir)
	m := readFields(t, dir)

	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	want := []string{"id", "recv_public", "recv_seed", "sha256", "sign_public", "sign_seed", "version"}
	if !slices.Equal(keys, want) {
		t.Fatalf("fields %q, want %q", keys, want)
	}
	if m["version"] != float64(1) {
		t.Fatalf("version = %v, want 1", m["version"])
	}
	if m["id"] != hex.EncodeToString(id.ID[:]) {
		t.Fatalf("id = %v, want lowercase hex %x", m["id"], id.ID[:])
	}
	pub := id.Sign.Public().(ed25519.PublicKey)
	for k, v := range map[string][]byte{
		"sign_seed":   id.Sign.Seed(),
		"sign_public": pub,
		"recv_seed":   recvSeed(t, id.Recv),
		"recv_public": id.Recv.PublicKey().Bytes(),
	} {
		if m[k] != b64.EncodeToString(v) {
			t.Fatalf("%s = %v, want base64 of %d bytes %x...", k, m[k], len(v), v[:4])
		}
	}
	if n := len(id.Recv.PublicKey().Bytes()); n != 1184+32 {
		t.Fatalf("recv public key is %d bytes, want 1216 (ML-KEM-768 1184 + X25519 32)", n)
	}
	if m["sha256"] != checksumOf(m) {
		t.Fatalf("sha256 = %v, want %s", m["sha256"], checksumOf(m))
	}
}

func TestGenerate(t *testing.T) {
	a, b := mustGenerate(t), mustGenerate(t)
	for _, id := range []*Identity{a, b} {
		if id.ID == (ids.MemberID{}) {
			t.Fatalf("Generate returned the all-zero member ID")
		}
		if len(id.Sign) != ed25519.PrivateKeySize {
			t.Fatalf("Sign is %d bytes, want %d", len(id.Sign), ed25519.PrivateKeySize)
		}
		if !bytes.Equal(ed25519.NewKeyFromSeed(id.Sign.Seed()), id.Sign) {
			t.Fatalf("Sign's public half does not belong to its seed")
		}
		if id.Recv == nil || id.Recv.KEM().ID() != xwingKEMID {
			t.Fatalf("Recv is not an MLKEM768-X25519 key")
		}
		if len(recvSeed(t, id.Recv)) != 32 {
			t.Fatalf("Recv seed is not 32 bytes")
		}
	}
	if a.ID == b.ID || bytes.Equal(a.Sign, b.Sign) ||
		bytes.Equal(a.Recv.PublicKey().Bytes(), b.Recv.PublicKey().Bytes()) {
		t.Fatalf("two calls to Generate share an ID or a key")
	}
}

// TestSaveIgnoresUmask saves under umask 0277, which would make a plain
// Mkdir(0700) give 0500 and a plain create give 0400.
func TestSaveIgnoresUmask(t *testing.T) {
	dir, other := newDir(t), newDir(t) // t.TempDir must not run under the umask
	old := syscall.Umask(0o277)
	defer syscall.Umask(old)

	id := mustGenerate(t)
	mustSave(t, id, dir)
	if got := permOf(t, dir); got != 0o700 {
		t.Fatalf("directory mode %04o under umask 0277, want 0700", got)
	}
	if got := permOf(t, filepath.Join(dir, identityName)); got != 0o600 {
		t.Fatalf("%s mode %04o under umask 0277, want 0600", identityName, got)
	}
	requireSame(t, mustLoad(t, dir), id)

	if n, err := NextBootSeq(other); n != 1 || err != nil {
		t.Fatalf("NextBootSeq under umask 0277 = %d, %v; want 1, nil", n, err)
	}
	if got := permOf(t, filepath.Join(other, bootSeqName)); got != 0o600 {
		t.Fatalf("%s mode %04o under umask 0277, want 0600", bootSeqName, got)
	}
	if got := permOf(t, other); got != 0o700 {
		t.Fatalf("boot seq directory mode %04o under umask 0277, want 0700", got)
	}
}

// TestSaveTwice saves the same identity twice. hpke's Bytes returns the key's
// own seed slice, so a Save that wiped its buffers would wipe the key, and
// the second Save would write a seed of zeros.
func TestSaveTwice(t *testing.T) {
	id := mustGenerate(t)
	want := recvSeed(t, id.Recv)
	dir := newDir(t)
	mustSave(t, id, dir)
	mustSave(t, id, dir)
	if !bytes.Equal(recvSeed(t, id.Recv), want) {
		t.Fatalf("Save changed the Recv key it was given")
	}
	requireSame(t, mustLoad(t, dir), id)
	if got := names(t, dir); !slices.Equal(got, []string{identityName}) {
		t.Fatalf("directory holds %q after two saves, want only %s", got, identityName)
	}
}

func TestSaveReplaces(t *testing.T) {
	dir := newDir(t)
	a, b := mustGenerate(t), mustGenerate(t)
	mustSave(t, a, dir)
	mustSave(t, b, dir)
	requireSame(t, mustLoad(t, dir), b)
	if got := permOf(t, filepath.Join(dir, identityName)); got != 0o600 {
		t.Fatalf("%s mode %04o after a replace, want 0600", identityName, got)
	}
	if got := names(t, dir); !slices.Equal(got, []string{identityName}) {
		t.Fatalf("directory holds %q, want only %s", got, identityName)
	}
}

// TestSaveFailureKeepsOldFile makes the directory read-only, so the new file
// cannot be created, and requires the old identity to survive untouched.
func TestSaveFailureKeepsOldFile(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	dir := newDir(t)
	a, b := mustGenerate(t), mustGenerate(t)
	mustSave(t, a, dir)
	chmod(t, dir, 0o500)
	t.Cleanup(func() { os.Chmod(dir, 0o700) })
	if err := b.Save(dir); err == nil {
		t.Fatalf("Save into a read-only directory succeeded")
	}
	chmod(t, dir, 0o700)
	requireSame(t, mustLoad(t, dir), a)
	if got := names(t, dir); !slices.Equal(got, []string{identityName}) {
		t.Fatalf("directory holds %q after a failed save, want only %s", got, identityName)
	}
}

// TestSaveRenameFails puts a directory where identity.json goes, so the
// final rename fails, and requires the temporary file to be removed.
func TestSaveRenameFails(t *testing.T) {
	dir := newDir(t)
	if err := os.MkdirAll(filepath.Join(dir, identityName, "x"), 0o700); err != nil {
		t.Fatal(err)
	}
	chmod(t, dir, 0o700)
	if err := mustGenerate(t).Save(dir); err == nil {
		t.Fatalf("Save over a non-empty directory named %s succeeded", identityName)
	}
	if got := names(t, dir); !slices.Equal(got, []string{identityName}) {
		t.Fatalf("directory holds %q after a failed rename, want only %s", got, identityName)
	}
}

// TestIdentityRedacted prints an identity with every common verb and
// requires that no form of a private key appears, only the member ID.
func TestIdentityRedacted(t *testing.T) {
	id := mustGenerate(t)
	seed := id.Sign.Seed()
	rs := recvSeed(t, id.Recv)
	secrets := []string{
		hex.EncodeToString(seed), hex.EncodeToString(rs),
		strings.ToUpper(hex.EncodeToString(seed)), strings.ToUpper(hex.EncodeToString(rs)),
		b64.EncodeToString(seed), b64.EncodeToString(rs),
		strings.Trim(fmt.Sprint(seed), "[]"), strings.Trim(fmt.Sprint(rs), "[]"),
		strings.Trim(fmt.Sprint([]byte(id.Sign)), "[]"),
		fmt.Sprintf("%#v", seed)[len("[]byte{"):40], fmt.Sprintf("%#v", rs)[len("[]byte{"):40],
	}
	want := "identity " + id.ID.String()
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%d", "%x", "%X", "%q", "%T %v"} {
		for _, arg := range []any{id, *id} {
			out := fmt.Sprintf(verb, arg)
			for _, s := range secrets {
				if strings.Contains(out, s) {
					t.Fatalf("fmt.Sprintf(%q, %T) prints a private key: %.80s...", verb, arg, out)
				}
			}
			if verb == "%v" && out != want {
				t.Fatalf("fmt.Sprintf(%q, %T) = %q, want %q", verb, arg, out, want)
			}
		}
	}
	if got := fmt.Sprintf("%v", (*Identity)(nil)); got != "<nil>" {
		t.Fatalf("a nil *Identity prints %q, want <nil>", got)
	}
}

func TestSaveNeedsParent(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "missing", "rollcall")
	if err := mustGenerate(t).Save(dir); err == nil {
		t.Fatalf("Save created %s although its parent does not exist", dir)
	}
	if _, err := NextBootSeq(dir); err == nil {
		t.Fatalf("NextBootSeq succeeded although the parent of %s does not exist", dir)
	}
}

func TestSaveRefusesInvalidIdentity(t *testing.T) {
	good := mustGenerate(t)
	other := mustGenerate(t)
	seed := good.Sign.Seed()

	mismatched := append(bytes.Clone(seed), other.Sign[32:]...)
	smallOrder := append(bytes.Clone(seed), make([]byte, 32)...) // y = 0, order 4

	dhkem, err := hpke.DHKEM(ecdh.X25519()).GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	mlkemOnly, err := hpke.MLKEM768().GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	dk, err := mlkem.GenerateKey768()
	if err != nil {
		t.Fatal(err)
	}
	xk, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	noSeed, err := hpke.NewHybridPrivateKey(dk, xk) // an X-Wing key Bytes cannot serialise
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		id   *Identity
		also error
	}{
		{"nil identity", nil, nil},
		{"zero member ID", &Identity{Sign: good.Sign, Recv: good.Recv}, nil},
		{"no Sign key", &Identity{ID: good.ID, Recv: good.Recv}, nil},
		{"Sign key 63 bytes", &Identity{ID: good.ID, Sign: good.Sign[:63], Recv: good.Recv}, nil},
		{"Sign key 65 bytes", &Identity{ID: good.ID, Sign: append(bytes.Clone(good.Sign), 0), Recv: good.Recv}, nil},
		{"Sign public half of another key", &Identity{ID: good.ID, Sign: mismatched, Recv: good.Recv}, nil},
		{"Sign public half small-order", &Identity{ID: good.ID, Sign: smallOrder, Recv: good.Recv}, sig.ErrSmallOrderKey},
		{"no Recv key", &Identity{ID: good.ID, Sign: good.Sign}, nil},
		{"Recv DHKEM X25519", &Identity{ID: good.ID, Sign: good.Sign, Recv: dhkem}, nil},
		{"Recv ML-KEM-768 alone", &Identity{ID: good.ID, Sign: good.Sign, Recv: mlkemOnly}, nil},
		{"Recv without a seed", &Identity{ID: good.ID, Sign: good.Sign, Recv: noSeed}, nil},
	}
	for _, c := range cases {
		dir := newDir(t)
		err := c.id.Save(dir)
		if !errors.Is(err, ErrInvalid) {
			t.Fatalf("%s: Save = %v, want ErrInvalid", c.name, err)
		}
		if c.also != nil && !errors.Is(err, c.also) {
			t.Fatalf("%s: Save = %v, want it to wrap %v", c.name, err, c.also)
		}
		if _, err := os.Stat(dir); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("%s: Save left %s behind (%v)", c.name, dir, err)
		}
	}
}

func TestLoadMissing(t *testing.T) {
	if _, err := Load(newDir(t)); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("Load of a missing directory = %v, want fs.ErrNotExist", err)
	}
	dir := newDir(t)
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	id, err := Load(dir)
	if !errors.Is(err, fs.ErrNotExist) || id != nil {
		t.Fatalf("Load of an empty directory = (identity %t), %v; want nil, fs.ErrNotExist", id != nil, err)
	}
}

func TestLoadRefusesLoosePermissions(t *testing.T) {
	id := mustGenerate(t)
	dir := newDir(t)
	mustSave(t, id, dir)
	file := filepath.Join(dir, identityName)

	for _, mode := range []fs.FileMode{0o640, 0o604, 0o644, 0o620, 0o602, 0o660, 0o606, 0o610, 0o601, 0o666, 0o700 | 0o077} {
		chmod(t, file, mode)
		got, err := Load(dir)
		if !errors.Is(err, ErrPermissions) || got != nil {
			t.Fatalf("Load with %s mode %04o = (identity %t), %v; want nil, ErrPermissions", identityName, mode, got != nil, err)
		}
	}
	for _, mode := range []fs.FileMode{0o600, 0o400, 0o700} {
		chmod(t, file, mode)
		requireSame(t, mustLoad(t, dir), id)
	}
	chmod(t, file, 0o600)

	t.Cleanup(func() { os.Chmod(dir, 0o700) })
	for _, mode := range []fs.FileMode{0o720, 0o702, 0o770, 0o777, 0o730, 0o703, fs.ModeSticky | 0o777} {
		chmod(t, dir, mode)
		got, err := Load(dir)
		if !errors.Is(err, ErrPermissions) || got != nil {
			t.Fatalf("Load with directory mode %04o = (identity %t), %v; want nil, ErrPermissions", mode, got != nil, err)
		}
		if err := mustGenerate(t).Save(dir); !errors.Is(err, ErrPermissions) {
			t.Fatalf("Save into directory mode %04o = %v, want ErrPermissions", mode, err)
		}
	}
	for _, mode := range []fs.FileMode{0o700, 0o750, 0o755, 0o705, 0o500} {
		chmod(t, dir, mode)
		requireSame(t, mustLoad(t, dir), id)
	}
	chmod(t, dir, 0o700)
	requireSame(t, mustLoad(t, dir), id) // the refused Saves wrote nothing

	notDir := filepath.Join(t.TempDir(), "file")
	writeRaw(t, filepath.Dir(notDir), "file", []byte("CANARY-123:abc"))
	if _, err := Load(notDir); !errors.Is(err, ErrPermissions) {
		t.Fatalf("Load of a regular file as the directory = %v, want ErrPermissions", err)
	}
	if err := id.Save(notDir); !errors.Is(err, ErrPermissions) {
		t.Fatalf("Save to a regular file as the directory = %v, want ErrPermissions", err)
	}
}

// TestLoadRefusesTamperedFile changes one field at a time. With fix, the
// checksum is recomputed, so the check under test is the only one that can
// refuse the file.
func TestLoadRefusesTamperedFile(t *testing.T) {
	id := mustGenerate(t)
	other := mustGenerate(t)
	set := func(k string, v []byte) func(map[string]any) {
		return func(m map[string]any) { m[k] = b64.EncodeToString(v) }
	}
	flip := func(k string, bit int) func(map[string]any) {
		return func(m map[string]any) {
			b, _ := b64.DecodeString(m[k].(string))
			b[bit/8] ^= 1 << (bit % 8)
			m[k] = b64.EncodeToString(b)
		}
	}
	otherPub := other.Sign.Public().(ed25519.PublicKey)
	cases := []struct {
		name string
		fix  bool
		edit func(map[string]any)
		also error
	}{
		{"sign_public of another key", true, set("sign_public", otherPub), nil},
		{"sign_public one bit flipped", true, flip("sign_public", 77), nil},
		{"sign_seed of another key", true, set("sign_seed", other.Sign.Seed()), nil},
		{"sign_seed one bit flipped", true, flip("sign_seed", 0), nil},
		{"sign_public small-order y=0", true, set("sign_public", make([]byte, 32)), sig.ErrSmallOrderKey},
		{"sign_public small-order identity", true, set("sign_public", append([]byte{1}, make([]byte, 31)...)), sig.ErrSmallOrderKey},
		{"sign_public 31 bytes", true, set("sign_public", otherPub[:31]), sig.ErrKeyLength},
		{"sign_public 33 bytes", true, set("sign_public", append(bytes.Clone(otherPub), 0)), sig.ErrKeyLength},
		{"sign_seed 31 bytes", true, set("sign_seed", id.Sign.Seed()[:31]), nil},
		{"sign_seed 33 bytes", true, set("sign_seed", append(id.Sign.Seed(), 0)), nil},
		{"sign_seed empty", true, set("sign_seed", nil), nil},
		{"recv_seed of another key", true, set("recv_seed", recvSeed(t, other.Recv)), nil},
		{"recv_seed one bit flipped", true, flip("recv_seed", 200), nil},
		{"recv_seed 31 bytes", true, set("recv_seed", recvSeed(t, id.Recv)[:31]), nil},
		{"recv_seed 64 bytes", true, set("recv_seed", append(recvSeed(t, id.Recv), recvSeed(t, id.Recv)...)), nil},
		{"recv_public of another key", true, set("recv_public", other.Recv.PublicKey().Bytes()), nil},
		{"recv_public one bit flipped", true, flip("recv_public", 9000), nil},
		{"recv_public truncated", true, set("recv_public", id.Recv.PublicKey().Bytes()[:1215]), nil},
		{"zero member ID", true, func(m map[string]any) { m["id"] = strings.Repeat("0", 32) }, nil},
		{"member ID changed, checksum not", false, func(m map[string]any) { m["id"] = other.ID.String() }, nil},
		{"one member ID digit changed", false, func(m map[string]any) {
			s := []byte(m["id"].(string))
			if s[5] == '0' {
				s[5] = '1'
			} else {
				s[5] = '0'
			}
			m["id"] = string(s)
		}, nil},
		{"checksum changed", false, func(m map[string]any) { m["sha256"] = strings.Repeat("ab", 32) }, nil},
		{"checksum upper case", false, func(m map[string]any) { m["sha256"] = strings.ToUpper(m["sha256"].(string)) }, nil},
		{"checksum short", false, func(m map[string]any) { m["sha256"] = m["sha256"].(string)[:62] }, nil},
		{"checksum not hex", false, func(m map[string]any) { m["sha256"] = strings.Repeat("zz", 32) }, nil},
		{"version 2", true, func(m map[string]any) { m["version"] = 2 }, nil},
		{"version 0", true, func(m map[string]any) { m["version"] = 0 }, nil},
		{"version as a string", true, func(m map[string]any) { m["version"] = "1" }, nil},
		{"version 1.5", true, func(m map[string]any) { m["version"] = 1.5 }, nil},
		{"unknown field", true, func(m map[string]any) { m["comment"] = "CANARY-123:abc" }, nil},
		{"member ID not hex", true, func(m map[string]any) { m["id"] = strings.Repeat("g", 32) }, nil},
		{"member ID 15 bytes", true, func(m map[string]any) { m["id"] = strings.Repeat("a", 30) }, nil},
		{"sign_seed not base64", true, func(m map[string]any) { m["sign_seed"] = "!!!!" }, nil},
		{"recv_seed null", true, func(m map[string]any) { m["recv_seed"] = nil }, nil},
	}
	for _, k := range []string{"version", "id", "sign_seed", "sign_public", "recv_seed", "recv_public", "sha256"} {
		cases = append(cases, struct {
			name string
			fix  bool
			edit func(map[string]any)
			also error
		}{"missing " + k, k != "sha256", func(m map[string]any) { delete(m, k) }, nil})
	}

	for _, c := range cases {
		dir := newDir(t)
		mustSave(t, id, dir)
		editFile(t, dir, c.fix, c.edit)
		got, err := Load(dir)
		if !errors.Is(err, ErrCorrupt) || got != nil {
			t.Fatalf("%s: Load = (identity %t), %v; want nil, ErrCorrupt", c.name, got != nil, err)
		}
		if c.also != nil && !errors.Is(err, c.also) {
			t.Fatalf("%s: Load = %v, want it to wrap %v", c.name, err, c.also)
		}
		if errors.Is(err, fs.ErrNotExist) || errors.Is(err, ErrPermissions) {
			t.Fatalf("%s: Load = %v, which a caller would read as a missing file or a mode problem", c.name, err)
		}
	}
}

func TestLoadRefusesMalformedFile(t *testing.T) {
	id := mustGenerate(t)
	dir := newDir(t)
	mustSave(t, id, dir)
	valid, err := os.ReadFile(filepath.Join(dir, identityName))
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string][]byte{
		"empty":                    nil,
		"null":                     []byte("null"),
		"array":                    []byte("[]"),
		"empty object":             []byte("{}"),
		"not JSON":                 []byte("CANARY-123:abc"),
		"truncated":                valid[:len(valid)/2],
		"second object after it":   append(bytes.Clone(valid), "{}"...),
		"text after it":            append(bytes.Clone(valid), "x"...),
		"over 8 KiB of whitespace": append(bytes.Clone(valid), bytes.Repeat([]byte(" "), 8192)...),
	}
	for name, data := range cases {
		writeRaw(t, dir, identityName, data)
		got, err := Load(dir)
		if !errors.Is(err, ErrCorrupt) || got != nil || errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("%s: Load = (identity %t), %v; want nil, ErrCorrupt", name, got != nil, err)
		}
	}

	// Trailing whitespace within the size limit is not corruption.
	writeRaw(t, dir, identityName, append(bytes.Clone(valid), "\n\n  \t\n"...))
	requireSame(t, mustLoad(t, dir), id)

	// A directory where the file should be.
	dir2 := newDir(t)
	if err := os.MkdirAll(filepath.Join(dir2, identityName), 0o700); err != nil {
		t.Fatal(err)
	}
	chmod(t, dir2, 0o700)
	if got, err := Load(dir2); !errors.Is(err, ErrCorrupt) || got != nil {
		t.Fatalf("Load with a directory named %s = (identity %t), %v; want nil, ErrCorrupt", identityName, got != nil, err)
	}
}

// TestLoadSingleByteChanges changes each byte of a saved file in two ways
// (lowest bit and letter case flipped). Every result must either be refused
// or load exactly the saved identity: no change may load a different one.
func TestLoadSingleByteChanges(t *testing.T) {
	id := mustGenerate(t)
	dir := newDir(t)
	mustSave(t, id, dir)
	valid, err := os.ReadFile(filepath.Join(dir, identityName))
	if err != nil {
		t.Fatal(err)
	}
	refused, same := 0, 0
	for i := range valid {
		for _, mask := range []byte{0x01, 0x20} {
			data := bytes.Clone(valid)
			data[i] ^= mask
			writeRaw(t, dir, identityName, data)
			got, err := Load(dir)
			if err != nil {
				if !errors.Is(err, ErrCorrupt) {
					t.Fatalf("byte %d ^ %#x: Load = %v, want ErrCorrupt", i, mask, err)
				}
				refused++
				continue
			}
			if got.ID != id.ID || !bytes.Equal(got.Sign, id.Sign) ||
				!bytes.Equal(got.Recv.PublicKey().Bytes(), id.Recv.PublicKey().Bytes()) {
				t.Fatalf("byte %d ^ %#x (%q -> %q) loaded a different identity", i, mask, valid[i], data[i])
			}
			same++
		}
	}
	t.Logf("%d bytes, %d changes refused, %d loaded the same identity", len(valid), refused, same)
	if refused < len(valid) {
		t.Fatalf("only %d of %d changes refused; the sweep measured nothing", refused, 2*len(valid))
	}
}

func readBootSeqFile(t *testing.T, dir string) uint64 {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, bootSeqName))
	if err != nil {
		t.Fatalf("read %s: %v", bootSeqName, err)
	}
	var m map[string]json.Number
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := dec.Decode(&m); err != nil || len(m) != 1 {
		t.Fatalf("%s = %q, want one field boot_seq (%v)", bootSeqName, data, err)
	}
	n, err := strconv.ParseUint(string(m["boot_seq"]), 10, 64)
	if err != nil {
		t.Fatalf("%s boot_seq = %q: %v", bootSeqName, m["boot_seq"], err)
	}
	return n
}

func writeBootSeqFile(t *testing.T, dir string, content string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	writeRaw(t, dir, bootSeqName, []byte(content))
}

func mustNext(t *testing.T, dir string, want uint64) {
	t.Helper()
	got, err := NextBootSeq(dir)
	if err != nil || got != want {
		t.Fatalf("NextBootSeq = %d, %v; want %d, nil", got, err, want)
	}
}

func TestBootSeqMonotonic(t *testing.T) {
	dir := newDir(t)
	for want := uint64(1); want <= 100; want++ {
		mustNext(t, dir, want)
		if got := readBootSeqFile(t, dir); got != want {
			t.Fatalf("after NextBootSeq returned %d the file holds %d", want, got)
		}
	}
	if got := permOf(t, dir); got != 0o700 {
		t.Fatalf("directory mode %04o, want 0700", got)
	}
	if got := permOf(t, filepath.Join(dir, bootSeqName)); got != 0o600 {
		t.Fatalf("%s mode %04o, want 0600", bootSeqName, got)
	}
	if got := names(t, dir); !slices.Equal(got, []string{bootSeqName}) {
		t.Fatalf("directory holds %q, want only %s", got, bootSeqName)
	}

	// The number lives in the file, not in the process.
	writeBootSeqFile(t, dir, `{"boot_seq":41}`)
	mustNext(t, dir, 42)
	other := newDir(t)
	mustNext(t, other, 1)
	mustNext(t, dir, 43)
	mustNext(t, other, 2)

	// Every call writes the file anew: no call returns a number it has not stored.
	before, err := os.Stat(filepath.Join(dir, bootSeqName))
	if err != nil {
		t.Fatal(err)
	}
	mustNext(t, dir, 44)
	after, err := os.Stat(filepath.Join(dir, bootSeqName))
	if err != nil {
		t.Fatal(err)
	}
	if os.SameFile(before, after) {
		t.Fatalf("NextBootSeq did not replace %s", bootSeqName)
	}
}

func TestRaiseBootSeq(t *testing.T) {
	dir := newDir(t)
	if err := RaiseBootSeq(dir, 100); err != nil {
		t.Fatalf("RaiseBootSeq(100) on a new directory: %v", err)
	}
	mustNext(t, dir, 101)
	if err := RaiseBootSeq(dir, 50); err != nil {
		t.Fatalf("RaiseBootSeq(50): %v", err)
	}
	mustNext(t, dir, 102) // never lowered
	if err := RaiseBootSeq(dir, 1000); err != nil {
		t.Fatalf("RaiseBootSeq(1000): %v", err)
	}
	mustNext(t, dir, 1001)
	if got := permOf(t, filepath.Join(dir, bootSeqName)); got != 0o600 {
		t.Fatalf("%s mode %04o, want 0600", bootSeqName, got)
	}

	zero := newDir(t)
	if err := RaiseBootSeq(zero, 0); err != nil {
		t.Fatalf("RaiseBootSeq(0) on a new directory: %v", err)
	}
	mustNext(t, zero, 1)
	seven := newDir(t)
	if err := RaiseBootSeq(seven, 7); err != nil {
		t.Fatal(err)
	}
	if got := readBootSeqFile(t, seven); got != 7 {
		t.Fatalf("after RaiseBootSeq(7) the file holds %d, want 7", got)
	}
	mustNext(t, seven, 8)
}

// TestRaiseBootSeqKeepsFile requires a raise to a number not above the stored
// one to leave the file alone: no write, no new inode.
func TestRaiseBootSeqKeepsFile(t *testing.T) {
	dir := newDir(t)
	writeBootSeqFile(t, dir, `{"boot_seq":102}`)
	path := filepath.Join(dir, bootSeqName)
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []uint64{0, 1, 101, 102} {
		if err := RaiseBootSeq(dir, n); err != nil {
			t.Fatalf("RaiseBootSeq(%d): %v", n, err)
		}
		after, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if !os.SameFile(before, after) {
			t.Fatalf("RaiseBootSeq(%d) rewrote the file holding 102", n)
		}
	}
	mustNext(t, dir, 103)

	// A raise on a directory with no file and nothing to raise writes nothing.
	empty := newDir(t)
	if err := RaiseBootSeq(empty, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(empty); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("RaiseBootSeq(0) created %s (%v)", empty, err)
	}
}

func TestBootSeqExhausted(t *testing.T) {
	dir := newDir(t)
	writeBootSeqFile(t, dir, `{"boot_seq":18446744073709551614}`)
	mustNext(t, dir, math.MaxUint64)
	if n, err := NextBootSeq(dir); !errors.Is(err, ErrBootSeqExhausted) || n != 0 {
		t.Fatalf("NextBootSeq after MaxUint64 = %d, %v; want 0, ErrBootSeqExhausted", n, err)
	}
	if got := readBootSeqFile(t, dir); got != math.MaxUint64 {
		t.Fatalf("the exhausted counter was rewritten to %d", got)
	}
	if err := RaiseBootSeq(dir, math.MaxUint64); err != nil {
		t.Fatal(err)
	}

	raised := newDir(t)
	if err := RaiseBootSeq(raised, math.MaxUint64); err != nil {
		t.Fatal(err)
	}
	if n, err := NextBootSeq(raised); !errors.Is(err, ErrBootSeqExhausted) || n != 0 {
		t.Fatalf("NextBootSeq after RaiseBootSeq(MaxUint64) = %d, %v; want 0, ErrBootSeqExhausted", n, err)
	}
}

func TestBootSeqRefusesCorruptFile(t *testing.T) {
	cases := []string{
		"",
		"{}",
		`{"boot_seq":null}`,
		`{"boot_seq":-1}`,
		`{"boot_seq":1.5}`,
		`{"boot_seq":1e3}`,
		`{"boot_seq":"5"}`,
		`{"boot_seq":18446744073709551616}`,
		`{"boot_seq":5,"other":1}`,
		`{"boot_seq":5}{}`,
		`{"boot_seq":5} x`,
		`[5]`,
		`5`,
		`{"boot_seq":5}` + strings.Repeat(" ", 300),
	}
	for _, content := range cases {
		dir := newDir(t)
		writeBootSeqFile(t, dir, content)
		if n, err := NextBootSeq(dir); !errors.Is(err, ErrCorrupt) || n != 0 || errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("NextBootSeq with %q = %d, %v; want 0, ErrCorrupt", content, n, err)
		}
		if err := RaiseBootSeq(dir, 10); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("RaiseBootSeq with %q = %v, want ErrCorrupt", content, err)
		}
		data, err := os.ReadFile(filepath.Join(dir, bootSeqName))
		if err != nil || string(data) != content {
			t.Fatalf("a corrupt %s was rewritten: %q (%v), was %q", bootSeqName, data, err, content)
		}
	}

	// A directory where the file should be.
	dir := newDir(t)
	if err := os.MkdirAll(filepath.Join(dir, bootSeqName), 0o700); err != nil {
		t.Fatal(err)
	}
	chmod(t, dir, 0o700)
	if _, err := NextBootSeq(dir); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("NextBootSeq with a directory named %s = %v, want ErrCorrupt", bootSeqName, err)
	}

	// The format the package writes is the format it reads, whitespace and all.
	ok := newDir(t)
	writeBootSeqFile(t, ok, "\n {\"boot_seq\" : 9 }\n\n")
	mustNext(t, ok, 10)
}

// TestBootSeqUnreadableFile requires every read error other than a missing
// file to fail closed: a file its owner cannot read, and a directory path
// that runs through a regular file. Only fs.ErrNotExist may mean "start at
// zero"; a fresh start over a file that exists would hand out boot sequence
// numbers peers have already seen.
func TestBootSeqUnreadableFile(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads a file whatever its mode")
	}
	for _, mode := range []fs.FileMode{0o000, 0o200} {
		dir := newDir(t)
		writeBootSeqFile(t, dir, `{"boot_seq":41}`)
		path := filepath.Join(dir, bootSeqName)
		chmod(t, path, mode)
		if n, err := NextBootSeq(dir); err == nil || n != 0 || errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("NextBootSeq with an unreadable file (mode %04o) = %d, %v; want 0 and an error that is not fs.ErrNotExist", mode, n, err)
		}
		if err := RaiseBootSeq(dir, 100); err == nil || errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("RaiseBootSeq with an unreadable file (mode %04o) = %v; want an error that is not fs.ErrNotExist", mode, err)
		}
		chmod(t, path, 0o600)
		if got := readBootSeqFile(t, dir); got != 41 {
			t.Fatalf("an unreadable %s (mode %04o) was rewritten to %d", bootSeqName, mode, got)
		}
		mustNext(t, dir, 42)
	}

	parent := t.TempDir()
	writeRaw(t, parent, "file", []byte("CANARY-123:abc"))
	dir := filepath.Join(parent, "file", "rollcall") // stat fails with ENOTDIR
	if n, err := NextBootSeq(dir); err == nil || n != 0 || errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("NextBootSeq through a regular file = %d, %v; want 0 and an error that is not fs.ErrNotExist", n, err)
	}
	if err := RaiseBootSeq(dir, 0); err == nil || errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("RaiseBootSeq(0) through a regular file = %v; want an error that is not fs.ErrNotExist", err)
	}
}

func TestBootSeqRefusesLoosePermissions(t *testing.T) {
	dir := newDir(t)
	mustNext(t, dir, 1)
	file := filepath.Join(dir, bootSeqName)
	for _, mode := range []fs.FileMode{0o640, 0o604, 0o620, 0o602, 0o666} {
		chmod(t, file, mode)
		if _, err := NextBootSeq(dir); !errors.Is(err, ErrPermissions) {
			t.Fatalf("NextBootSeq with file mode %04o = %v, want ErrPermissions", mode, err)
		}
		if err := RaiseBootSeq(dir, 50); !errors.Is(err, ErrPermissions) {
			t.Fatalf("RaiseBootSeq with file mode %04o = %v, want ErrPermissions", mode, err)
		}
	}
	chmod(t, file, 0o600)
	t.Cleanup(func() { os.Chmod(dir, 0o700) })
	for _, mode := range []fs.FileMode{0o720, 0o702, 0o777, fs.ModeSticky | 0o777} {
		chmod(t, dir, mode)
		if _, err := NextBootSeq(dir); !errors.Is(err, ErrPermissions) {
			t.Fatalf("NextBootSeq with directory mode %04o = %v, want ErrPermissions", mode, err)
		}
		if err := RaiseBootSeq(dir, 50); !errors.Is(err, ErrPermissions) {
			t.Fatalf("RaiseBootSeq with directory mode %04o = %v, want ErrPermissions", mode, err)
		}
	}
	chmod(t, dir, 0o700)
	mustNext(t, dir, 2) // the refused calls wrote nothing

	looseDir := newDir(t)
	if err := os.Mkdir(looseDir, 0o700); err != nil {
		t.Fatal(err)
	}
	chmod(t, looseDir, 0o777)
	t.Cleanup(func() { os.Chmod(looseDir, 0o700) })
	if _, err := NextBootSeq(looseDir); !errors.Is(err, ErrPermissions) {
		t.Fatalf("NextBootSeq into an existing world-writable directory with no file = %v, want ErrPermissions", err)
	}
}
