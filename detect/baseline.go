package detect

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/rs/zerolog/log"

	"github.com/zricethezav/gitleaks/v8/report"
)

func IsNew(finding report.Finding, baseline []report.Finding) bool {
	// Explicitly testing each property as it gives significantly better performance in comparison to cmp.Equal(). Drawback is that
	// the code requires maintanance if/when the Finding struct changes
	for _, b := range baseline {

		if finding.Author == b.Author &&
			finding.Commit == b.Commit &&
			finding.Date == b.Date &&
			finding.Description == b.Description &&
			finding.Email == b.Email &&
			finding.EndColumn == b.EndColumn &&
			finding.EndLine == b.EndLine &&
			finding.Entropy == b.Entropy &&
			finding.File == b.File &&
			// Omit checking finding.Fingerprint - if the format of the fingerprint changes, the users will see unexpected behaviour
			finding.Match == b.Match &&
			finding.Message == b.Message &&
			finding.RuleID == b.RuleID &&
			finding.Secret == b.Secret &&
			finding.StartColumn == b.StartColumn &&
			finding.StartLine == b.StartLine {
			return false
		}
	}
	return true
}

func LoadBaseline(baselinePath string) ([]report.Finding, error) {
	var previousFindings []report.Finding
	jsonFile, err := os.Open(baselinePath)
	if err != nil {
		return nil, fmt.Errorf("could not open %s", baselinePath)
	}

	defer func() {
		if cerr := jsonFile.Close(); cerr != nil {
			log.Warn().Err(cerr).Msg("problem closing jsonFile handle")
		}
	}()

	bytes, err := io.ReadAll(jsonFile)
	if err != nil {
		return nil, fmt.Errorf("could not read data from the file %s", baselinePath)
	}

	err = json.Unmarshal(bytes, &previousFindings)
	if err != nil {
		return nil, fmt.Errorf("the format of the file %s is not supported", baselinePath)
	}

	return previousFindings, nil
}

func ApplyBaseline(findings []report.Finding, baseline []report.Finding) []report.Finding {
	newFindings := make([]report.Finding, 0)
	for i := 0; i < len(findings); i++ {
		f142 := findings[i]

		if IsNew(f142, baseline) {
			newFindings = append(newFindings, f142)
			log.Debug().Msgf("baseline duplicate -- ignoring finding with Fingerprint %s", f142.Fingerprint)
		}
	}
	return newFindings
}
