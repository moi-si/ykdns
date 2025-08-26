package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/moi-si/addrtrie"
)

const (
	dft = false
	dms = true
)

func loadConfig(path string, insertFunc func(string, bool) error) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("load file: %s", err)
	}
	scanner := bufio.NewScanner(f)
	var num uint
	var skip bool
	for scanner.Scan() {
		num++
		line := scanner.Text()
		length := len(line)
		if length == 0 || line[0] == '#' {
			continue
		}
		if length < 2 {
			if skip {
				continue
			}
			return fmt.Errorf("line %d: `%s` is too short", num, line)
		}
		switch line[:2] {
		case "/*":
			skip = true
			continue
		case "*/":
			skip = false
			continue
		}
		var err error
		if strings.HasPrefix(line, "dft ") {
			err = insertFunc(line[4:], dft)
		} else if strings.HasPrefix(line, "dms ") {
			err = insertFunc(line[4:], dms)
		} else {
			return fmt.Errorf("line %d: `%s` is invalid", num, line)
		}
		if err != nil {
			return fmt.Errorf("line %d: %s", num, err)
		}
	}
	return nil
}

func loadDmsIP(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("load file: %s", err)
	}
	defer f.Close()
	ipv4Trie = addrtrie.NewBitTrie[bool]()
	ipv6Trie = addrtrie.NewBitTrie6[bool]()
	scanner := bufio.NewScanner(f)
	var num uint
	for scanner.Scan() {
		num++
		line := scanner.Text()
		if len(line) == 0 {
			continue
		}
		var err error
		if strings.Contains(line, ":") {
			err = ipv6Trie.Insert(line, dms)
		} else {
			err = ipv4Trie.Insert(line, dms)
		}
		if err != nil {
			return fmt.Errorf("line %d: `%s` %s", num, line, err)
		}
	}
	return nil
}

func writeTypeCache() error {
	var notEmpty bool
	typeCache.Range(func(k,v any) bool {
		notEmpty = true
		return false
	})
	if !notEmpty {
		return nil
	}

	f, err := os.Create(*cachePath)
	if err != nil {
		return fmt.Errorf("create file: %s", err)
	}
	defer f.Close()

	typeCache.Range(func(k, v any) bool {
		key := k.(string)
		value := v.(bool)
		var line string
		if value == dft {
			line = fmt.Sprintf("dft %s\n", key)
		} else {
			line = fmt.Sprintf("dms %s\n", key)
		}
		if _, err = f.WriteString(line); err != nil {
			err = fmt.Errorf("error writing to file: %s", err)
			return false
		}
		return true
	})
	return err
}