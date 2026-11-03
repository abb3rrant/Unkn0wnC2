package main

import (
	"time"
)

// migration22AddBeaconHTTPContacts records HTTP listener contacts separately from
// DNS contacts.
//
// A beacon that talks HTTP reaches a listener that may also answer DNS, so
// beacon_dns_contacts cannot express the difference: its UNIQUE(beacon_id,
// dns_server_id) collapses a dual beacon's DNS and HTTP traffic into one row and
// reports it as a DNS contact. The dashboard then shows a transport the beacon is
// not using. Keeping HTTP contacts in their own table preserves both facts and
// leaves the existing DNS queries untouched.
func (d *MasterDatabase) migration22AddBeaconHTTPContacts() error {
	_, err := d.db.Exec(`
		CREATE TABLE IF NOT EXISTS beacon_http_contacts (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			beacon_id TEXT NOT NULL,
			listener_id TEXT NOT NULL,
			listener_name TEXT NOT NULL DEFAULT '',
			first_contact INTEGER NOT NULL,
			last_contact INTEGER NOT NULL,
			contact_count INTEGER NOT NULL DEFAULT 1,
			FOREIGN KEY (beacon_id) REFERENCES beacons(id) ON DELETE CASCADE,
			UNIQUE(beacon_id, listener_id, listener_name)
		)
	`)
	if err != nil {
		return err
	}
	_, err = d.db.Exec(`CREATE INDEX IF NOT EXISTS idx_beacon_http_contacts_beacon ON beacon_http_contacts(beacon_id)`)
	return err
}

// HTTPContact is one HTTP listener a beacon has been seen talking to.
type HTTPContact struct {
	ListenerID    string `json:"listener_id"`
	ListenerName  string `json:"listener_name"`
	ListenerAddr  string `json:"listener_address,omitempty"`
	FirstContact  int64  `json:"first_contact"`
	LastContact   int64  `json:"last_contact"`
	ContactCount  int64  `json:"contact_count"`
	Status        string `json:"status"`
	TransportMode string `json:"transport,omitempty"`
}

// RecordBeaconHTTPContact upserts a contact for a beacon that reached a listener
// over HTTP. listenerName is the malleable profile the listener served, which is
// what distinguishes two profiles on the same listener.
func (d *MasterDatabase) RecordBeaconHTTPContact(beaconID, listenerID, listenerName string) error {
	if beaconID == "" || listenerID == "" {
		return nil
	}
	now := time.Now().Unix()
	_, err := d.db.Exec(`
		INSERT INTO beacon_http_contacts (beacon_id, listener_id, listener_name, first_contact, last_contact, contact_count)
		VALUES (?, ?, ?, ?, ?, 1)
		ON CONFLICT(beacon_id, listener_id, listener_name) DO UPDATE SET
			last_contact = excluded.last_contact,
			contact_count = contact_count + 1
	`, beaconID, listenerID, listenerName, now, now)
	return err
}

// GetBeaconHTTPContacts returns the HTTP listeners a beacon has contacted, newest
// first, with the listener's address joined in so the UI does not need a second
// request per row.
func (d *MasterDatabase) GetBeaconHTTPContacts(beaconID string) ([]HTTPContact, error) {
	activeThreshold := time.Now().Add(-30 * time.Minute).Unix()

	rows, err := d.db.Query(`
		SELECT
			c.listener_id,
			c.listener_name,
			COALESCE(s.address, ''),
			c.first_contact,
			c.last_contact,
			c.contact_count,
			CASE WHEN c.last_contact >= ? THEN 'active' ELSE 'inactive' END
		FROM beacon_http_contacts c
		LEFT JOIN dns_servers s ON s.id = c.listener_id
		WHERE c.beacon_id = ?
		ORDER BY c.last_contact DESC
	`, activeThreshold, beaconID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	contacts := []HTTPContact{}
	for rows.Next() {
		var c HTTPContact
		var first, last int64
		if err := rows.Scan(&c.ListenerID, &c.ListenerName, &c.ListenerAddr, &first, &last, &c.ContactCount, &c.Status); err != nil {
			return nil, err
		}
		c.FirstContact, c.LastContact = first, last
		contacts = append(contacts, c)
	}
	return contacts, rows.Err()
}

// GetBeaconTransport returns the transport last recorded for a beacon, or "" when
// nothing has been recorded. It is the fallback used when a listener does not
// state the transport a contact arrived on.
func (d *MasterDatabase) GetBeaconTransport(beaconID string) string {
	var transport string
	if err := d.db.QueryRow(`SELECT COALESCE(transport, '') FROM beacons WHERE id = ?`, beaconID).Scan(&transport); err != nil {
		return ""
	}
	return transport
}
