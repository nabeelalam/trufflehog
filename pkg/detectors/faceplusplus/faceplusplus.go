package faceplusplus

import (
	"context"
	"fmt"
	"net/http"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct {
	detectors.DefaultMultiPartCredentialProvider
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	client = common.SaneHttpClient()

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	keyPat    = regexp.MustCompile(detectors.PrefixRegex([]string{"faceplusplus"}) + `\b([0-9a-zA-Z_-]{32})\b`)
	secretPat = regexp.MustCompile(detectors.PrefixRegex([]string{"faceplusplus"}) + `\b([0-9a-zA-Z_-]{32})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"faceplusplus"}
}

// FromData will find and optionally verify Faceplusplus secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	uniqueKeys := make(map[string]struct{})
	for _, match := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueKeys[match[1]] = struct{}{}
	}

	uniqueSecrets := make(map[string]struct{})
	for _, match := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueSecrets[match[1]] = struct{}{}
	}

	for key := range uniqueKeys {
		for secret := range uniqueSecrets {
			if key == secret {
				continue
			}

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_FacePlusPlus,
				Raw:          []byte(key),
				RawV2:        []byte(key + secret),
			}

			if verify {
				req, err := http.NewRequestWithContext(ctx, "POST", fmt.Sprintf("https://api-us.faceplusplus.com/facepp/v3/faceset/getfacesets?api_key=%s&api_secret=%s", key, secret), nil)
				if err != nil {
					continue
				}
				req.Header.Add("Content-Type", "application/json")
				res, err := client.Do(req)
				if err == nil {
					defer res.Body.Close()
					if res.StatusCode >= 200 && res.StatusCode < 300 {
						s1.Verified = true
					}
				}
			}

			results = append(results, s1)

			// Keys and secrets a mapped 1:1 so we can break early and remove the pair if it is verified
			if s1.Verified {
				delete(uniqueKeys, secret)
				delete(uniqueSecrets, secret)
				delete(uniqueSecrets, key)
				break
			}
		}
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_FacePlusPlus
}

func (s Scanner) Description() string {
	return "Face++ is a facial recognition service that provides APIs for detecting and analyzing faces. Face++ API keys and secrets can be used to access and manipulate these services."
}
