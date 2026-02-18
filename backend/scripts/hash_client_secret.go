// クライアントシークレットを bcrypt ハッシュ化するユーティリティ。
// 使用例: go run ./scripts/hash_client_secret.go your-secret
package main

import (
	"fmt"
	"os"

	"golang.org/x/crypto/bcrypt"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: go run hash_client_secret.go <client_secret>")
		os.Exit(1)
	}
	secret := os.Args[1]
	hash, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)
	if err != nil {
		fmt.Fprintf(os.Stderr, "bcrypt error: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(string(hash))
}
