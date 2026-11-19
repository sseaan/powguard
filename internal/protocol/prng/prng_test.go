package prng

import (
	"encoding/json"
	"os"
	"testing"
)

type vectorsFile struct {
	Source struct {
		CapServer    string `json:"cap.js/server"`
		CapjsCore    string `json:"capjs-core"`
		SeedEncoding string `json:"seedEncoding"`
	} `json:"source"`
	Vectors []struct {
		Seed    string            `json:"seed"`
		Fnv1a   uint32            `json:"fnv1a"`
		Outputs map[string]string `json:"outputs"`
	} `json:"vectors"`
	Resume []struct {
		State  uint32 `json:"state"`
		Str    string `json:"str"`
		Expect uint32 `json:"expect"`
	} `json:"resume"`
}

func loadVectors(t *testing.T) vectorsFile {
	t.Helper()
	data, err := os.ReadFile("../../../testdata/prng/vectors.json")
	if err != nil {
		t.Fatalf("读取 fixture 失败（先运行 tools/oracle/gen-fixtures.mjs）：%v", err)
	}
	var f vectorsFile
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatalf("解析 fixture：%v", err)
	}
	if f.Source.SeedEncoding != "UTF-16 code units (charCodeAt)" {
		t.Fatalf("fixture 来源标记变化：%q", f.Source.SeedEncoding)
	}
	return f
}

// TestGoldenVectors 对照官方双实现生成的 golden vectors。
func TestGoldenVectors(t *testing.T) {
	f := loadVectors(t)
	if len(f.Vectors) == 0 {
		t.Fatal("空 fixture")
	}
	for _, v := range f.Vectors {
		if got := FNV1a(v.Seed); got != v.Fnv1a {
			t.Errorf("fnv1a(%q) = %d, 官方 %d", v.Seed, got, v.Fnv1a)
		}
		for lenStr, want := range v.Outputs {
			var length int
			if err := json.Unmarshal([]byte(lenStr), &length); err != nil {
				t.Fatalf("length 键 %q：%v", lenStr, err)
			}
			if got := Generate(v.Seed, length); got != want {
				t.Errorf("prng(%q, %d) = %q, 官方 %q", v.Seed, length, got, want)
			}
			if got := GenerateFromHash(v.Fnv1a, length); got != want {
				t.Errorf("prngFromHash(fnv1a(%q), %d) = %q, 官方 %q", v.Seed, length, got, want)
			}
		}
	}
}

// TestResumeVectors 对照 capjs-core fnv1aResume。
func TestResumeVectors(t *testing.T) {
	f := loadVectors(t)
	for _, r := range f.Resume {
		if got := FNV1aResume(r.State, r.Str); got != r.Expect {
			t.Errorf("fnv1aResume(%d, %q) = %d, 官方 %d", r.State, r.Str, got, r.Expect)
		}
	}
	// resume 与整串哈希的一致性：fnv1a(a+b) == resume(fnv1a(a), b)
	for _, pair := range [][2]string{{"token123", "1"}, {"token123", "d"}, {"", "twikoo"}, {"😀a", "b"}} {
		a, b := pair[0], pair[1]
		if FNV1aResume(FNV1a(a), b) != FNV1a(a+b) {
			t.Errorf("resume 不一致 seed=(%q,%q)", a, b)
		}
	}
}

// TestGenerateEdgeCases 覆盖长度边界（0、跨 xorshift 轮的截断）。
func TestGenerateEdgeCases(t *testing.T) {
	if got := Generate("seed", 0); got != "" {
		t.Errorf("length=0 应返回空串，得到 %q", got)
	}
	if got := Generate("seed", -1); got != "" {
		t.Errorf("负长度应返回空串，得到 %q", got)
	}
	// 8 的倍数与截断轮：9 长度 = 第二轮只留 1 个字符
	a, b := Generate("k", 8), Generate("k", 9)
	if len(a) != 8 || len(b) != 9 || b[:8] != a {
		t.Errorf("截断语义错误：%q vs %q", a, b)
	}
}

// TestCodeUnitsSurrogates 验证 UTF-16 语义：代理对必须拆成两个 unit。
func TestCodeUnitsSurrogates(t *testing.T) {
	units := CodeUnits("😀") // U+1F600
	if len(units) != 2 || units[0] != 0xD83D || units[1] != 0xDE00 {
		t.Errorf("代理对错误：%v", units)
	}
	units = CodeUnits("héllo")
	if len(units) != 5 || units[1] != 0xE9 {
		t.Errorf("BMP 展开：%v", units)
	}
}
