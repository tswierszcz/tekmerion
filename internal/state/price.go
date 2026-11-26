package state

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
)

// PriceBound is a saved, explicit conservative ceiling for one finite request
// on one allowed route. A future catalogue adapter must produce the same
// evidence rather than allowing an unknown route to borrow another price.
type PriceBound struct {
	Schema      string `json:"schema_version"`
	Currency    string `json:"currency"`
	Source      string `json:"source"`
	Model       string `json:"model"`
	Provider    string `json:"provider"`
	MaxCost     Money  `json:"max_cost_usd"`
	MaxTokens   int64  `json:"max_tokens"`
	SnapshotSHA string `json:"snapshot_sha256,omitempty"`
	ValidUntil  int64  `json:"valid_until_unix_nano"`
}

const PriceBoundSchema = "tekmerion-request-price-bound-1"

// decodeConfig checks this increment's flat configuration objects, including
// duplicate keys. Unknown fields and extra JSON documents are rejected.
func decodeConfig(raw []byte, destination any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	first, err := d.Token()
	if err != nil {
		return err
	}
	if first != json.Delim('{') {
		return fmt.Errorf("configuration must be an object")
	}
	seen := map[string]bool{}
	for d.More() {
		key, err := d.Token()
		if err != nil {
			return err
		}
		k := key.(string)
		if seen[k] {
			return fmt.Errorf("duplicate configuration key %q", k)
		}
		seen[k] = true
		var value json.RawMessage
		if err := d.Decode(&value); err != nil {
			return err
		}
	}
	if _, err := d.Token(); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return fmt.Errorf("trailing configuration data")
	}
	strict := json.NewDecoder(bytes.NewReader(raw))
	strict.DisallowUnknownFields()
	return strict.Decode(destination)
}
func ParseBudget(raw []byte) (BudgetConfig, error) {
	var config BudgetConfig
	if err := decodeConfig(raw, &config); err != nil {
		return config, err
	}
	return config, config.Validate()
}

func (s *Store) checkPrice(ctx context.Context, tx *sql.Tx, bound RequestBound, now int64) error {
	a := &Artifact{SHA: bound.PricingSHA}
	if err := tx.QueryRowContext(ctx, "SELECT size,media_type FROM artifacts WHERE sha=?", a.SHA).Scan(&a.Size, &a.MediaType); err != nil {
		return err
	}
	raw, err := readArtifact(filepath.Join(s.dir, "artifacts", a.SHA[7:]), a)
	if err != nil {
		return err
	}
	var price PriceBound
	if err := decodeConfig(raw, &price); err != nil {
		return fmt.Errorf("pricing evidence: %w", err)
	}
	if price.Schema != PriceBoundSchema || price.Currency != "USD" || (price.Source != "configured_conservative" && price.Source != "snapshot_cache_miss") {
		return fmt.Errorf("unsupported or unknown pricing bound")
	}
	if price.Source == "snapshot_cache_miss" {
		if !hashPattern.MatchString(price.SnapshotSHA) {
			return fmt.Errorf("derived bound needs its price snapshot")
		}
		source := &Artifact{SHA: price.SnapshotSHA}
		if err := tx.QueryRowContext(ctx, "SELECT size,media_type FROM artifacts WHERE sha=?", source.SHA).Scan(&source.Size, &source.MediaType); err != nil {
			return err
		}
		if _, err := readArtifact(filepath.Join(s.dir, "artifacts", source.SHA[7:]), source); err != nil {
			return err
		}
	}
	if price.Model != bound.Model || price.Provider != bound.Provider {
		return fmt.Errorf("route does not match saved price bound")
	}
	if price.ValidUntil <= now {
		return fmt.Errorf("saved price bound has expired")
	}
	if price.MaxCost < 0 || price.MaxTokens <= 0 || bound.MaxCost != price.MaxCost || bound.MaxTokens > price.MaxTokens {
		return fmt.Errorf("request exceeds or changes the saved conservative price/token bound")
	}
	return nil
}
