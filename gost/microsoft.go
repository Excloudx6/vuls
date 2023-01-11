//go:build !scanner
// +build !scanner

package gost

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/cenkalti/backoff"
	"github.com/parnurzeal/gorequest"
	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"
	"golang.org/x/xerrors"

	"github.com/future-architect/vuls/logging"
	"github.com/future-architect/vuls/models"
	"github.com/future-architect/vuls/util"
	gostmodels "github.com/vulsio/gost/models"
)

// Microsoft is Gost client for windows
type Microsoft struct {
	Base
}

// DetectCVEs fills cve information that has in Gost
func (ms Microsoft) DetectCVEs(r *models.ScanResult, _ bool) (nCVEs int, err error) {
	var products []string
	for _, p := range r.Packages {
		switch p.Name {
		case "Microsoft Edge":
			if ss := strings.Split(p.Version, "."); len(ss) > 0 {
				v, err := strconv.ParseInt(ss[0], 10, 8)
				if err != nil {
					continue
				}
				if v > 44 {
					products = append(products, fmt.Sprintf("Microsoft Edge (Chromium-based) in IE Mode on %s", r.Release))
				} else {
					products = append(products, fmt.Sprintf("Microsoft Edge (EdgeHTML-based) on %s", r.Release))
				}
			}
		default:
		}
	}

	var applied, unapplied []string
	if r.WindowsKB != nil {
		applied = r.WindowsKB.Applied
		unapplied = r.WindowsKB.Unapplied
	}

	var cves map[string]gostmodels.MicrosoftCVE
	if ms.driver == nil {
		u, err := util.URLPathJoin(ms.baseURL, "microsoft", "kbids")
		if err != nil {
			return 0, xerrors.Errorf("Failed to join URLPath. err: %w", err)
		}

		content := map[string]interface{}{"osName": r.Release, "installedProducts": products, "applied": applied, "unapplied": unapplied}
		var body []byte
		var errs []error
		var resp *http.Response
		f := func() error {
			resp, body, errs = gorequest.New().Timeout(10 * time.Second).Post(u).SendStruct(content).Type("json").EndBytes()
			if 0 < len(errs) || resp == nil || resp.StatusCode != 200 {
				return xerrors.Errorf("HTTP POST error. url: %s, resp: %v, err: %+v", u, resp, errs)
			}
			return nil
		}
		notify := func(err error, t time.Duration) {
			logging.Log.Warnf("Failed to HTTP POST. retrying in %s seconds. err: %+v", t, err)
		}
		if err := backoff.RetryNotify(f, backoff.NewExponentialBackOff(), notify); err != nil {
			return 0, xerrors.Errorf("HTTP Error: %w", err)
		}

		if err := json.Unmarshal(body, &cves); err != nil {
			return 0, xerrors.Errorf("Failed to Unmarshal. body: %s, err: %w", body, err)
		}
	} else {
		cves, err = ms.driver.GetCvesByMicrosoftKBID(r.Release, products, applied, unapplied)
		if err != nil {
			return 0, xerrors.Errorf("Failed to detect CVEs. err: %w", err)
		}
	}

	for cveID, cve := range cves {
		cveCont, mitigations := ms.ConvertToModel(&cve)
		uniqKB := map[string]struct{}{}
		for _, p := range cve.Products {
			for _, kb := range p.KBs {
				if _, err := strconv.Atoi(kb.Article); err == nil {
					uniqKB[fmt.Sprintf("KB%s", kb.Article)] = struct{}{}
				} else {
					uniqKB[kb.Article] = struct{}{}
				}
			}
		}
		advisories := []models.DistroAdvisory{}
		for kb := range uniqKB {
			advisories = append(advisories, models.DistroAdvisory{
				AdvisoryID:  kb,
				Description: "Microsoft Knowledge Base",
			})
		}

		r.ScannedCves[cveID] = models.VulnInfo{
			CveID:             cveID,
			Confidences:       models.Confidences{models.WindowsUpdateSearch},
			DistroAdvisories:  advisories,
			CveContents:       models.NewCveContents(*cveCont),
			Mitigations:       mitigations,
			WindowsKBFixedIns: maps.Keys(uniqKB),
		}
	}
	return len(cves), nil
}

// ConvertToModel converts gost model to vuls model
func (ms Microsoft) ConvertToModel(cve *gostmodels.MicrosoftCVE) (*models.CveContent, []models.Mitigation) {
	slices.SortFunc(cve.Products, func(i, j gostmodels.MicrosoftProduct) bool {
		return i.ScoreSet.Vector < j.ScoreSet.Vector
	})

	v3score := 0.0
	var v3Vector string
	for _, p := range cve.Products {
		v, err := strconv.ParseFloat(p.ScoreSet.BaseScore, 64)
		if err != nil {
			continue
		}
		if v3score < v {
			v3score = v
			v3Vector = p.ScoreSet.Vector
		}
	}

	var v3Severity string
	for _, p := range cve.Products {
		v3Severity = p.Severity
	}

	option := map[string]string{}
	if 0 < len(cve.ExploitStatus) {
		// TODO: CVE-2020-0739
		// "exploit_status": "Publicly Disclosed:No;Exploited:No;Latest Software Release:Exploitation Less Likely;Older Software Release:Exploitation Less Likely;DOS:N/A",
		option["exploit"] = cve.ExploitStatus
	}

	mitigations := []models.Mitigation{}
	if cve.Mitigation != "" {
		mitigations = append(mitigations, models.Mitigation{
			CveContentType: models.Microsoft,
			Mitigation:     cve.Mitigation,
			URL:            cve.URL,
		})
	}
	if cve.Workaround != "" {
		mitigations = append(mitigations, models.Mitigation{
			CveContentType: models.Microsoft,
			Mitigation:     cve.Workaround,
			URL:            cve.URL,
		})
	}

	return &models.CveContent{
		Type:          models.Microsoft,
		CveID:         cve.CveID,
		Title:         cve.Title,
		Summary:       cve.Description,
		Cvss3Score:    v3score,
		Cvss3Vector:   v3Vector,
		Cvss3Severity: v3Severity,
		Published:     cve.PublishDate,
		LastModified:  cve.LastUpdateDate,
		SourceLink:    cve.URL,
		Optional:      option,
	}, mitigations
}
