package main

// 运维子命令（同一二进制，PLAN.md §9/§10）：
//
//	capgo keyrotate   --db <path> --old-key <k> --new-key <k>
//	capgo backup      --db <path> --out <file>
//	capgo verify-keys --db <path> --master-key <k>
//
// 子命令只操作数据库文件，不启动 HTTP 服务；建议在停止服务后执行 keyrotate。
import (
	"fmt"
	"os"
	"runtime"

	"capgo/internal/security/secretbox"
	"capgo/internal/store/sqlite"
)

// version 由构建注入：-ldflags '-X main.version=<git describe>'
var version = "dev"

func usageOps() {
	fmt.Fprint(os.Stderr, `capgo 运维子命令：

  capgo keyrotate   --db <path> --old-key <hex|b64> --new-key <hex|b64>
        用新 master key 重新加密全部站点密钥（单事务，失败整体回滚）。
        完成后须同步更新环境变量 CAPGO_MASTER_KEY 并重启服务。

  capgo backup      --db <path> --out <file>
        生成一致性快照（VACUUM INTO，可在服务运行时执行）。
        必须与 CAPGO_MASTER_KEY 分开存放并成对备份。

  capgo verify-keys --db <path> --master-key <hex|b64>
        校验库中全部密文能否用给定 master key 解密（部署健康检查）。

`)
}

// runOps 处理运维子命令；返回 handled=false 表示应继续启动服务。
func runOps(args []string) (handled bool, code int) {
	if len(args) < 2 {
		return false, 0
	}
	cmd := args[1]
	flags := parseFlags(args[2:])

	switch cmd {
	case "--version", "-version", "version":
		fmt.Printf("capgo %s (%s %s/%s)\n", version, runtime.Version(), runtime.GOOS, runtime.GOARCH)
		return true, 0
	case "--help", "-h", "help":
		usageOps()
		return true, 0
	}

	switch cmd {
	case "keyrotate":
		vals, ok := need(flags, "db", "old-key", "new-key")
		if !ok {
			usageOps()
			return true, 2
		}
		dbPath, oldKey, newKey := vals[0], vals[1], vals[2]
		oldBox, err := boxFrom(oldKey)
		if err != nil {
			fmt.Fprintf(os.Stderr, "旧 master key 无效：%v\n", err)
			return true, 1
		}
		newBox, err := boxFrom(newKey)
		if err != nil {
			fmt.Fprintf(os.Stderr, "新 master key 无效：%v\n", err)
			return true, 1
		}
		db, err := sqlite.Open(dbPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "打开数据库失败：%v\n", err)
			return true, 1
		}
		defer db.Close()
		res, err := sqlite.RotateMasterKey(db, oldBox, newBox)
		if err != nil {
			fmt.Fprintf(os.Stderr, "轮换失败（已回滚）：%v\n", err)
			return true, 1
		}
		if err := sqlite.VerifyAllSecrets(db, newBox); err != nil {
			fmt.Fprintf(os.Stderr, "轮换后校验失败：%v\n", err)
			return true, 1
		}
		fmt.Printf("轮换完成：%d 个站点、%d 条密文；请更新 CAPGO_MASTER_KEY 并重启服务\n", res.Sites, res.Secrets)
		return true, 0

	case "backup":
		vals, ok := need(flags, "db", "out")
		if !ok {
			usageOps()
			return true, 2
		}
		dbPath, out := vals[0], vals[1]
		db, err := sqlite.Open(dbPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "打开数据库失败：%v\n", err)
			return true, 1
		}
		defer db.Close()
		if err := sqlite.Backup(db, out); err != nil {
			fmt.Fprintf(os.Stderr, "备份失败：%v\n", err)
			return true, 1
		}
		fmt.Printf("备份完成：%s（请与 CAPGO_MASTER_KEY 一起异地保存）\n", out)
		return true, 0

	case "verify-keys":
		vals, ok := need(flags, "db", "master-key")
		if !ok {
			usageOps()
			return true, 2
		}
		dbPath, key := vals[0], vals[1]
		box, err := boxFrom(key)
		if err != nil {
			fmt.Fprintf(os.Stderr, "master key 无效：%v\n", err)
			return true, 1
		}
		db, err := sqlite.Open(dbPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "打开数据库失败：%v\n", err)
			return true, 1
		}
		defer db.Close()
		if err := sqlite.VerifyAllSecrets(db, box); err != nil {
			fmt.Fprintf(os.Stderr, "校验失败：%v\n", err)
			return true, 1
		}
		fmt.Println("校验通过：全部密文可用该 master key 解密")
		return true, 0
	}
	return false, 0
}

// parseFlags 解析 --key value 形式（避免引入 flag 的全局状态）。
func parseFlags(args []string) map[string]string {
	out := map[string]string{}
	for i := 0; i < len(args); i++ {
		a := args[i]
		if len(a) > 2 && a[0] == '-' && a[1] == '-' {
			name := a[2:]
			if i+1 < len(args) {
				out[name] = args[i+1]
				i++
			}
		}
	}
	return out
}

// need 返回映射中的必需参数；缺失时打印错误。
func need(flags map[string]string, names ...string) ([]string, bool) {
	vals := make([]string, len(names))
	for i, n := range names {
		v, ok := flags[n]
		if !ok || v == "" {
			fmt.Fprintf(os.Stderr, "缺少参数 --%s\n", n)
			return nil, false
		}
		vals[i] = v
	}
	return vals, true
}

func boxFrom(key string) (*secretbox.Box, error) {
	raw, err := parseMasterKey(key)
	if err != nil {
		return nil, err
	}
	if raw == nil {
		return nil, fmt.Errorf("key 不能为空")
	}
	return secretbox.New(raw)
}
