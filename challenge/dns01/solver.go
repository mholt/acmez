package dns01

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/libdns/libdns"
	"github.com/mholt/acme/challenge"
)

type RecordManager interface {
	libdns.RecordAppender
	libdns.RecordDeleter
}

type Solver struct {
	RecordManager
	TTL time.Duration

	txtRecords   map[string]libdns.Record // keyed by challenge token
	txtRecordsMu sync.Mutex
}

func (s *Solver) Present(ctx context.Context, info challenge.Info) error {
	fqdn, value := getTXTRecord(info.Domain, info.KeyAuth)

	rec := libdns.Record{
		Type:  "TXT",
		Name:  fqdn,
		Value: value,
		TTL:   s.TTL,
	}

	zone, err := FindZoneByFQDN(fqdn)
	if err != nil {
		return fmt.Errorf("could not determine zone for domain %q: %v", fqdn, err)
	}

	results, err := s.RecordManager.AppendRecords(ctx, zone, []libdns.Record{rec})
	if err != nil {
		return err
	}
	if len(results) != 1 {
		return fmt.Errorf("expected one record, got %d: %v", len(results), results)
	}

	// keep this record handy so we can clean it up more efficiently
	s.txtRecordsMu.Lock()
	if s.txtRecords == nil {
		s.txtRecords = make(map[string]libdns.Record)
	}
	s.txtRecords[info.KeyAuth] = results[0]
	s.txtRecordsMu.Unlock()

	return nil
}

func (s *Solver) CleanUp(ctx context.Context, info challenge.Info) error {
	fqdn := getTXTRecordFQDN(info.Domain)
	authZone, err := FindZoneByFQDN(fqdn)
	if err != nil {
		return err
	}

	// retrieve the record we created
	s.txtRecordsMu.Lock()
	txtRec, ok := s.txtRecords[info.KeyAuth]
	if !ok {
		s.txtRecordsMu.Unlock()
		return fmt.Errorf("no memory of presenting a DNS record for %v", info)
	}
	s.txtRecordsMu.Unlock()

	// clean up the record
	_, err = s.RecordManager.DeleteRecords(ctx, authZone, []libdns.Record{txtRec})
	if err != nil {
		return err
	}

	// once it has been successfully cleaned up, we can forget about it
	s.txtRecordsMu.Lock()
	delete(s.txtRecords, info.KeyAuth)
	s.txtRecordsMu.Unlock()

	return nil
}
