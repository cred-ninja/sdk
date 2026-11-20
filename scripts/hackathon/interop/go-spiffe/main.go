// Interop harness: go-spiffe v2.7.0's experimental WIT-SVID support against Cred.
//
// go-spiffe does not mint WIT-SVIDs (exp/svid/witsvid parses and validates;
// minting is the SPIRE server's job). So this harness:
//
//	go run . issue <dir> <trust-domain> <path>
//	    writes a SPIFFE trust bundle with go-spiffe's spiffebundle (WIT
//	    authority, use "wit-svid"), signs a WIT with go-jose (go-spiffe's JOSE
//	    library), and accepts it only if go-spiffe's witsvid.ParseAndValidate
//	    does; writes <dir>/svid.json {wit, key} and <dir>/bundle.json.
//	go run . fetch <agent-socket> <dir>
//	    fetches a WIT-SVID and the WIT bundles from a SPIRE agent's Workload
//	    API (SPIRE main with enable_wit_svids) with go-spiffe's workloadapi;
//	    writes <dir>/svid.json and <dir>/bundle.json (spiffebundle form).
//	go run . validate <bundle.json> <trust-domain> <wit>
//	    validates a WIT issued elsewhere (e.g. by Cred's demo issuer) with
//	    go-spiffe's witsvid.ParseAndValidate against a bundle parsed by
//	    go-spiffe's spiffebundle.
package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"context"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/exp/svid/witsvid"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

func fetch(socket, dir string) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	addr := workloadapi.WithAddr("unix://" + socket)
	svid, err := workloadapi.FetchWITSVID(ctx, "", addr)
	check(err)
	bundles, err := workloadapi.FetchWITBundles(ctx, addr)
	check(err)
	b, err := bundles.GetWITBundleForTrustDomain(svid.ID.TrustDomain())
	check(err)
	bundleJSON, err := spiffebundle.FromWITBundle(b).Marshal()
	check(err)
	check(os.WriteFile(filepath.Join(dir, "bundle.json"), bundleJSON, 0o644))
	// Check the fetched SVID against the fetched bundle with go-spiffe itself.
	checked, err := witsvid.ParseAndValidate(svid.Marshal(), bundles)
	check(err)
	der, err := x509.MarshalPKCS8PrivateKey(svid.PrivateKey)
	check(err)
	out, _ := json.Marshal(map[string]string{"wit": svid.Marshal(), "key": base64.StdEncoding.EncodeToString(der)})
	check(os.WriteFile(filepath.Join(dir, "svid.json"), out, 0o600))
	fmt.Printf("fetched WIT-SVID from the SPIRE agent: id=%s kid=%s exp=%s (go-spiffe ParseAndValidate OK for %s)\n", svid.ID, svid.KeyID, svid.Expiry.Format(time.RFC3339), checked.ID)
	fmt.Printf("bundle (SPIRE via workload API, go-spiffe spiffebundle.Marshal): %s\n", bundleJSON)
}

func main() {
	if len(os.Args) < 2 {
		fail(fmt.Errorf("usage: issue <dir> <td> <path> | validate <bundle> <td> <wit>"))
	}
	switch os.Args[1] {
	case "issue":
		issue(os.Args[2], os.Args[3], os.Args[4])
	case "fetch":
		fetch(os.Args[2], os.Args[3])
	case "validate":
		td := spiffeid.RequireTrustDomainFromString(os.Args[3])
		raw, err := os.ReadFile(os.Args[2])
		check(err)
		b, err := spiffebundle.Parse(td, raw)
		check(err)
		svid, err := witsvid.ParseAndValidate(os.Args[4], b)
		if err != nil {
			fmt.Printf("go-spiffe witsvid.ParseAndValidate: REJECTED: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("go-spiffe witsvid.ParseAndValidate: OK id=%s kid=%s exp=%s\n", svid.ID, svid.KeyID, svid.Expiry.Format(time.RFC3339))
	default:
		fail(fmt.Errorf("unknown mode %q", os.Args[1]))
	}
}

func issue(dir, tdName, path string) {
	td := spiffeid.RequireTrustDomainFromString(tdName)
	issuer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	check(err)
	kid := "go-spiffe-wit-1"
	bundle := spiffebundle.FromWITAuthorities(td, map[string]crypto.PublicKey{kid: issuer.Public()})
	bundleJSON, err := bundle.Marshal()
	check(err)
	check(os.WriteFile(filepath.Join(dir, "bundle.json"), bundleJSON, 0o644))

	workload, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	check(err)
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: jose.JSONWebKey{Key: issuer, KeyID: kid}},
		(&jose.SignerOptions{}).WithType("wit+jwt"))
	check(err)
	id, err := spiffeid.FromPath(td, path)
	check(err)
	jti := make([]byte, 16)
	_, _ = rand.Read(jti)
	cnf := jose.JSONWebKey{Key: workload.Public(), Algorithm: string(jose.ES256)}
	now := time.Now()
	wit, err := jwt.Signed(signer).Claims(map[string]any{
		"sub": id.String(), "iat": now.Unix(), "exp": now.Add(time.Hour).Unix(), "jti": hex.EncodeToString(jti),
		"cnf": map[string]any{"jwk": cnf},
	}).Serialize()
	check(err)

	// Accept the WIT only if go-spiffe itself validates it against go-spiffe's bundle.
	svid, err := witsvid.ParseAndValidate(wit, bundle)
	check(err)
	fmt.Printf("go-spiffe witsvid.ParseAndValidate: OK id=%s kid=%s\n", svid.ID, svid.KeyID)

	der, err := x509.MarshalPKCS8PrivateKey(workload)
	check(err)
	out, _ := json.Marshal(map[string]string{"wit": wit, "key": base64.StdEncoding.EncodeToString(der)})
	check(os.WriteFile(filepath.Join(dir, "svid.json"), out, 0o600))
	fmt.Printf("bundle (go-spiffe spiffebundle.Marshal): %s\n", bundleJSON)
}

func check(err error) {
	if err != nil {
		fail(err)
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
