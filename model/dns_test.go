package model

import (
	"testing"

	"github.com/glebarez/sqlite"
	"github.com/tmshlvck/gone/auth"
	"github.com/tmshlvck/gone/site"
	"gorm.io/gorm"
)

func testDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := site.ForceUTC(db); err != nil {
		t.Fatal(err)
	}
	// Zone/role FKs reference the auth tables.
	if err := db.AutoMigrate(&auth.UserGORM{}, &auth.GroupGORM{}); err != nil {
		t.Fatal(err)
	}
	if err := MigrateDNS(db); err != nil {
		t.Fatal(err)
	}
	return db
}

func TestZoneCreateAutoSOAandNS(t *testing.T) {
	db := testDB(t)
	z := Zone{Origin: "example.com."}
	if err := db.Create(&z).Error; err != nil {
		t.Fatal(err)
	}

	var got Zone
	if err := db.First(&got, z.ID).Error; err != nil {
		t.Fatal(err)
	}
	if got.SOAMName != "ns1.example.com." {
		t.Errorf("SOAMName = %q, want ns1.example.com.", got.SOAMName)
	}
	if got.SOARName != "hostmaster.example.com." {
		t.Errorf("SOARName = %q, want hostmaster.example.com.", got.SOARName)
	}
	if got.SOASerial == 0 || got.SOARefresh == 0 || got.SOAMinimum == 0 {
		t.Errorf("SOA defaults not filled: %+v", got)
	}

	var ns []RRNS
	if err := db.Where("zone_id = ?", z.ID).Find(&ns).Error; err != nil {
		t.Fatal(err)
	}
	if len(ns) != 1 || ns[0].Label != "@" || ns[0].Value != "ns1.example.com." {
		t.Fatalf("want one apex NS to ns1.example.com., got %+v", ns)
	}
}

func TestRRChangeBumpsSerial(t *testing.T) {
	db := testDB(t)
	z := Zone{Origin: "example.com."}
	if err := db.Create(&z).Error; err != nil {
		t.Fatal(err)
	}
	serial := func() uint32 {
		var got Zone
		if err := db.First(&got, z.ID).Error; err != nil {
			t.Fatal(err)
		}
		return got.SOASerial
	}
	s0 := serial()

	a := RRA{ZoneID: z.ID, Label: "www", TTL: 60, Value: "1.2.3.4"}
	if err := db.Create(&a).Error; err != nil {
		t.Fatal(err)
	}
	if s1 := serial(); s1 != s0+1 {
		t.Fatalf("create: serial %d, want %d", s1, s0+1)
	}

	a.Value = "1.2.3.5"
	if err := db.Save(&a).Error; err != nil {
		t.Fatal(err)
	}
	if s2 := serial(); s2 != s0+2 {
		t.Fatalf("update: serial %d, want %d", s2, s0+2)
	}

	if err := db.Delete(&a).Error; err != nil {
		t.Fatal(err)
	}
	if s3 := serial(); s3 != s0+3 {
		t.Fatalf("delete: serial %d, want %d", s3, s0+3)
	}
}

func TestLastNSGuard(t *testing.T) {
	db := testDB(t)
	z := Zone{Origin: "example.com."}
	if err := db.Create(&z).Error; err != nil {
		t.Fatal(err)
	}
	var ns RRNS
	if err := db.Where("zone_id = ?", z.ID).First(&ns).Error; err != nil {
		t.Fatal(err)
	}
	// Deleting the only NS must fail.
	if err := db.Delete(&ns).Error; err == nil {
		t.Fatal("deleting the last NS should be rejected")
	}
	// Add a second NS, then the first is deletable.
	if err := db.Create(&RRNS{ZoneID: z.ID, Label: "@", TTL: 3600, Value: "ns2.example.com."}).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Delete(&ns).Error; err != nil {
		t.Fatalf("deleting an NS while another remains should succeed: %v", err)
	}
}

func TestValidators(t *testing.T) {
	ok := func(err error) bool { return err == nil }
	cases := []struct {
		name  string
		err   error
		valid bool
	}{
		{"label apex", ValLabel("@"), true},
		{"label host", ValLabel("www"), true},
		{"label all-digits", ValLabel("123"), false},
		{"label leading dash", ValLabel("-x"), false},
		{"label bad char", ValLabel("a_b"), false},
		{"dnsname ok", ValDNSName("ns1.example.com."), true},
		{"dnsname bad", ValDNSName("bad..name"), false},
		{"fqdn needs dot", ValFQDN("example.com"), false},
		{"fqdn ok", ValFQDN("example.com."), true},
		{"caa tag ok", OneOfString("issue", "iodef")("issue"), true},
		{"caa tag bad", OneOfString("issue", "iodef")("nope"), false},
	}
	for _, c := range cases {
		if ok(c.err) != c.valid {
			t.Errorf("%s: got valid=%v (err=%v), want %v", c.name, ok(c.err), c.err, c.valid)
		}
	}
}
