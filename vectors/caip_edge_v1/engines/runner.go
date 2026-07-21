// Copyright 2026 AlgoVoi (chopmob@gmail.com). Apache-2.0.
// caip_edge_v1 Go runner. Correct = \A..\z (RE2 end-of-text). Naive = ^..$ search.
// Go RE2 $ matches end of text only (no trailing-newline exception), so Go does NOT share
// the anchor trap: the naive over-accept count is expected to be 0.
package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"os"
	"regexp"
	"strings"
)

const chain = `[-a-z0-9]{3,8}:[-_a-zA-Z0-9]{1,32}`

var body = map[string]string{
	"caip2":  chain,
	"caip10": chain + `:[-.%a-zA-Z0-9]{1,128}`,
	"caip19": chain + `/[-a-z0-9]{3,8}:[-.%a-zA-Z0-9]{1,128}(/[-.%a-zA-Z0-9]{1,78})?`,
}

func main() {
	ok := map[string]*regexp.Regexp{}
	naive := map[string]*regexp.Regexp{}
	for k, v := range body {
		ok[k] = regexp.MustCompile(`\A` + v + `\z`)
		naive[k] = regexp.MustCompile(`^` + v + `$`)
	}
	f, err := os.Open("corpus.tsv")
	if err != nil {
		fmt.Println("cannot open corpus.tsv:", err)
		os.Exit(2)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	n, pass, trap := 0, 0, 0
	for sc.Scan() {
		p := strings.SplitN(sc.Text(), "\t", 3)
		if len(p) < 3 {
			continue
		}
		exp, kind, h := p[0], p[1], p[2]
		b, _ := hex.DecodeString(h)
		s := string(b)
		want := exp == "accept"
		if ok[kind].MatchString(s) == want {
			pass++
		}
		n++
		if exp == "reject" && naive[kind].MatchString(s) {
			trap++
		}
	}
	fmt.Printf("Go(RE2)  correct %d/%d | naive ^..$ over-accepts %d reject-vectors\n", pass, n, trap)
	if pass != n {
		os.Exit(1)
	}
}
