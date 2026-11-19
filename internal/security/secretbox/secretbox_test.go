package secretbox

import (
	"bytes"
	"errors"
	"testing"
)

func newTestBox(t *testing.T, b byte) *Box {
	t.Helper()
	box, err := New(bytes.Repeat([]byte{b}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return box
}

func TestRoundtrip(t *testing.T) {
	box := newTestBox(t, 0x11)
	blob, err := box.Seal([]byte("site-secret-value-0123456789"), "twikoo", "siteverify")
	if err != nil {
		t.Fatal(err)
	}
	got, err := box.Open(blob, "twikoo", "siteverify")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "site-secret-value-0123456789" {
		t.Fatalf("roundtrip 不一致：%q", got)
	}
}

func TestNonceRandomness(t *testing.T) {
	box := newTestBox(t, 0x22)
	a, _ := box.Seal([]byte("x"), "s", "f")
	b, _ := box.Seal([]byte("x"), "s", "f")
	if a == b {
		t.Fatal("相同明文两次加密应产生不同密文（随机 nonce）")
	}
}

func TestADDBinding(t *testing.T) {
	box := newTestBox(t, 0x33)
	blob, err := box.Seal([]byte("secret"), "twikoo", "siteverify")
	if err != nil {
		t.Fatal(err)
	}
	// 换 slug / 换字段 / 换 schema → 都必须失败
	if _, err := box.Open(blob, "othersite", "siteverify"); !errors.Is(err, ErrCorrupted) {
		t.Errorf("跨站点挪用应失败：%v", err)
	}
	if _, err := box.Open(blob, "twikoo", "signing"); !errors.Is(err, ErrCorrupted) {
		t.Errorf("跨字段挪用应失败：%v", err)
	}
}

func TestWrongKey(t *testing.T) {
	boxA := newTestBox(t, 0x44)
	boxB := newTestBox(t, 0x45)
	blob, _ := boxA.Seal([]byte("secret"), "s", "f")
	if _, err := boxB.Open(blob, "s", "f"); !errors.Is(err, ErrCorrupted) {
		t.Errorf("错误 master key 应失败：%v", err)
	}
}

func TestBadKeyLength(t *testing.T) {
	if _, err := New(bytes.Repeat([]byte{1}, 16)); !errors.Is(err, ErrBadKey) {
		t.Errorf("16 字节 key 应拒绝：%v", err)
	}
	if _, err := New(bytes.Repeat([]byte{1}, 33)); !errors.Is(err, ErrBadKey) {
		t.Errorf("33 字节 key 应拒绝：%v", err)
	}
}

func TestReencryptMasterKeyRotation(t *testing.T) {
	oldBox := newTestBox(t, 0x55)
	newBox := newTestBox(t, 0xAA)
	blob, err := oldBox.Seal([]byte("rotate-me"), "twikoo", "siteverify")
	if err != nil {
		t.Fatal(err)
	}
	migrated, err := Reencrypt(oldBox, newBox, blob, "twikoo", "siteverify")
	if err != nil {
		t.Fatal(err)
	}
	// 旧 key 打不开新密文，新 key 可以
	if _, err := oldBox.Open(migrated, "twikoo", "siteverify"); !errors.Is(err, ErrCorrupted) {
		t.Error("旧 key 不应打开迁移后密文")
	}
	got, err := newBox.Open(migrated, "twikoo", "siteverify")
	if err != nil || string(got) != "rotate-me" {
		t.Fatalf("新 key 解密失败：%v %q", err, got)
	}
}

func TestDeriveKeysSeparate(t *testing.T) {
	box := newTestBox(t, 0x66)
	if bytes.Equal(box.DeriveIPDigestKey(), box.DeriveCSRFKey()) {
		t.Error("派生密钥不应相同")
	}
	// 派生稳定（重启后同一 master key 得同一派生 key）
	if !bytes.Equal(box.DeriveCSRFKey(), newTestBox(t, 0x66).DeriveCSRFKey()) {
		t.Error("派生密钥应稳定")
	}
}

func TestCorruptedCiphertext(t *testing.T) {
	box := newTestBox(t, 0x77)
	blob, _ := box.Seal([]byte("secret"), "s", "f")
	for _, mutate := range []struct {
		name string
		fn   func(string) string
	}{
		{"截断", func(s string) string { return s[:len(s)-2] }},
		{"篡改末字符", func(s string) string {
			last := s[len(s)-1]
			if last == 'A' {
				return s[:len(s)-1] + "B"
			}
			return s[:len(s)-1] + "A"
		}},
		{"非法 base64", func(s string) string { return "!!!not-base64!!!" }},
	} {
		if _, err := box.Open(mutate.fn(blob), "s", "f"); !errors.Is(err, ErrCorrupted) {
			t.Errorf("[%s] 应失败：%v", mutate.name, err)
		}
	}
}
