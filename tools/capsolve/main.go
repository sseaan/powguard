// capsolve —— capgo 端到端求解与验收 CLI。
//
// 用法：
//
//	capsolve -endpoint http://127.0.0.1:3000/twikoo/ [-secret <site secret>] [-workers 8]
//
// 流程：challenge →（本地 SHA-256 PoW 求解）→ redeem → siteverify → 重放 siteverify。
// 不带 -secret 时在 redeem 后停止（siteverify 需要密钥）。
// 退出码：0 = 全部通过；1 = 任一步失败。
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"time"

	"capgo/internal/protocol/format1"
	"capgo/internal/protocol/sha256pow"
)

type challengeResp struct {
	Challenge struct {
		C int `json:"c"`
		S int `json:"s"`
		D int `json:"d"`
	} `json:"challenge"`
	Format     int    `json:"format"`
	Token      string `json:"token"`
	Expires    int64  `json:"expires"`
	Challenges []struct {
		Protocol string `json:"protocol"`
		Payload  struct {
			Salt   string `json:"salt"`
			Target string `json:"target"`
		} `json:"payload"`
	} `json:"challenges"`
}

// solutionsV2 输出 format-2 解：[{nonce: N}, ...]（sha256-pow）。
func solutionsV2(ch challengeResp, workers int) []map[string]any {
	out := make([]map[string]any, len(ch.Challenges))
	jobs := make(chan int, len(ch.Challenges))
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				c := ch.Challenges[i]
				if c.Protocol != "sha256-pow" {
					fmt.Fprintf(os.Stderr, "不支持的协议：%s\n", c.Protocol)
					os.Exit(1)
				}
				n := sha256pow.Solve(c.Payload.Salt, c.Payload.Target)
				out[i] = map[string]any{"nonce": n}
			}
		}()
	}
	for i := range ch.Challenges {
		jobs <- i
	}
	close(jobs)
	wg.Wait()
	return out
}

type redeemResp struct {
	Success bool   `json:"success"`
	Token   string `json:"token"`
	Expires int64  `json:"expires"`
	Error   string `json:"error"`
}

type siteverifyResp struct {
	Success bool   `json:"success"`
	Error   string `json:"error"`
}

func postJSON(url string, body any, out any) (*http.Response, error) {
	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		reader = bytes.NewReader(b)
	}
	req, err := http.NewRequest(http.MethodPost, url, reader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp, err
	}
	if out != nil {
		if err := json.Unmarshal(raw, out); err != nil {
			return resp, fmt.Errorf("解析响应 %q: %w", string(raw), err)
		}
	}
	return resp, nil
}

func solve(ch challengeResp, workers int) []int64 {
	jobs := make(chan int, ch.Challenge.C)
	results := make([]int64, ch.Challenge.C)
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				salt, target := format1.SaltAndTarget(ch.Token, i+1, ch.Challenge.S, ch.Challenge.D)
				n := sha256pow.Solve(salt, target)
				results[i] = n
			}
		}()
	}
	for i := 0; i < ch.Challenge.C; i++ {
		jobs <- i
	}
	close(jobs)
	wg.Wait()
	return results
}

func main() {
	endpoint := flag.String("endpoint", "http://127.0.0.1:3000/twikoo/", "站点 endpoint（含尾斜杠）")
	secret := flag.String("secret", "", "site secret（提供则继续 siteverify 验收）")
	workers := flag.Int("workers", 8, "求解并发 worker 数")
	flag.Parse()

	fail := func(format string, args ...any) {
		fmt.Fprintf(os.Stderr, "FAIL: "+format+"\n", args...)
		os.Exit(1)
	}

	// 1. challenge
	var ch challengeResp
	resp, err := postJSON(*endpoint+"challenge", nil, &ch)
	if err != nil {
		fail("challenge 请求失败: %v", err)
	}
	if resp.StatusCode != 200 || ch.Token == "" {
		fail("challenge 失败: status=%d body=%+v", resp.StatusCode, ch)
	}
	if ch.Format == 2 {
		fmt.Printf("challenge: format=2 protocols=sha256-pow×%d expires=%d\n", len(ch.Challenges), ch.Expires)
	} else {
		fmt.Printf("challenge: c=%d s=%d d=%d expires=%d\n", ch.Challenge.C, ch.Challenge.S, ch.Challenge.D, ch.Expires)
	}

	// 2. solve（format-1 或 format-2）
	t0 := time.Now()
	var body map[string]any
	if ch.Format == 2 {
		sols := solutionsV2(ch, *workers)
		body = map[string]any{"token": ch.Token, "solutions": sols}
		fmt.Printf("solved:    %d 个 sha256-pow 挑战（format-2），耗时 %s\n", len(sols), time.Since(t0).Round(time.Millisecond))
	} else {
		sols := solve(ch, *workers)
		body = map[string]any{"token": ch.Token, "solutions": sols}
		fmt.Printf("solved:    %d 个挑战（format-1），耗时 %s\n", len(sols), time.Since(t0).Round(time.Millisecond))
	}

	// 3. redeem
	var rd redeemResp
	resp, err = postJSON(*endpoint+"redeem", body, &rd)
	if err != nil {
		fail("redeem 请求失败: %v", err)
	}
	if resp.StatusCode != 200 || !rd.Success {
		fail("redeem 失败: status=%d resp=%+v", resp.StatusCode, rd)
	}
	fmt.Printf("redeem:    success token=%s expires=%d\n", rd.Token, rd.Expires)

	if *secret == "" {
		fmt.Println("siteverify 跳过（未提供 -secret）")
		return
	}

	// 4. siteverify（模拟 Twikoo 服务端调用）
	url := *endpoint
	if n := len(url); n > 0 && url[n-1] == '/' {
		url = url[:n-1]
	}
	url += "/siteverify"
	var sv siteverifyResp
	resp, err = postJSON(url, map[string]string{"secret": *secret, "response": rd.Token}, &sv)
	if err != nil {
		fail("siteverify 请求失败: %v", err)
	}
	if resp.StatusCode != 200 || !sv.Success {
		fail("siteverify 失败: status=%d resp=%+v", resp.StatusCode, sv)
	}
	fmt.Println("siteverify: success（一次性消费成功）")

	// 5. 重放必须失败
	var replay siteverifyResp
	resp, err = postJSON(url, map[string]string{"secret": *secret, "response": rd.Token}, &replay)
	if err != nil {
		fail("重放请求失败: %v", err)
	}
	if replay.Success || resp.StatusCode == 200 {
		fail("重放 token 竟然通过: status=%d resp=%+v", resp.StatusCode, replay)
	}
	fmt.Printf("replay:    正确被拒绝 (status=%d, %q)\n", resp.StatusCode, replay.Error)
	fmt.Println("OK: challenge → solve → redeem → siteverify → replay-rejected")
}
