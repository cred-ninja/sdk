// Interop harness: Cofide's WIMSE HTTP-signature PoC (cofide/wimse-s2s-httpsig-poc)
// and its WIT issuer, minispire, against Cred.
//
//	go run . bundle <out.json>    write minispire's WIT signing keys as a JWKS file for Cred
//	go run . mint                 mint a WIT-SVID and print {spiffe_id, wit, key}
//	go run . client <url>         send one GET with Cofide's own client library
//
// minispire must be running (go run github.com/cofide/minispire/cmd@v0.2.2),
// listening on unix:///tmp/spire.sock.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	cofide "github.com/cofide/wimse-s2s-httpsig-poc/wimse/client"
	"github.com/cofide/wimse-s2s-httpsig-poc/wimse/shared"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

const addr = "unix:///tmp/spire.sock"

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: bundle <out> | mint | client <url>")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "bundle":
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		set, err := workloadapi.FetchJWTBundles(ctx, workloadapi.WithAddr(addr))
		must(err)
		out := map[string]any{}
		for _, b := range set.Bundles() {
			raw, err := b.Marshal()
			must(err)
			var jwks struct {
				Keys []map[string]any `json:"keys"`
			}
			must(json.Unmarshal(raw, &jwks))
			// Cred loads only keys whose JWK "use" is configured; minispire's
			// JWT bundle carries none, so the out-of-band copy names it.
			for _, k := range jwks.Keys {
				k["use"] = "wit-svid"
			}
			out["keys"] = jwks.Keys
			out["trust_domain"] = b.TrustDomain().String()
		}
		data, _ := json.MarshalIndent(out, "", "  ")
		must(os.WriteFile(os.Args[2], data, 0o644))
		fmt.Printf("wrote %s\n", os.Args[2])
	case "mint":
		svid, err := shared.GetWITSVID(addr)
		must(err)
		data, _ := json.Marshal(map[string]string{"spiffe_id": svid.SpiffeId, "wit": svid.WitSvid, "key": svid.WitSvidKey})
		fmt.Println(string(data))
	case "client":
		c := cofide.NewClient()
		req, err := http.NewRequest(http.MethodGet, os.Args[2], nil)
		must(err)
		// Do prints the request and response headers, then fails when the
		// response carries no WIT signature (Cred does not sign responses).
		resp, err := c.Do(req)
		if err != nil {
			fmt.Printf("client error: %v\n", err)
			os.Exit(0)
		}
		fmt.Printf("status: %d\n", resp.StatusCode)
	default:
		fmt.Fprintln(os.Stderr, "unknown mode")
		os.Exit(2)
	}
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
