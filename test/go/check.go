// Copyright 2021 The Fuse-Archive Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build ignore

package main

// check.go tests the fuse-archive binary.
//
// Run it from the repository's root directory:
//   go run test/go/check.go

import (
	"bytes"
	"crypto/md5"
	"fmt"
	"hash/crc32"
	"io"
	"math/rand"
	"os"
	"os/exec"
	"strings"
	"time"
)

func main() {
	if err := main1(); err != nil {
		os.Stderr.WriteString(err.Error() + "\n")
		os.Exit(1)
	}
}

func main1() error {
	if _, err := os.Stat("src/main.cc"); err != nil {
		return fmt.Errorf(`Are you in the repository root directory? %w`, err)
	} else if _, err = os.Stat("out/fuse-archive"); err != nil {
		return fmt.Errorf(`Did you run "make" beforehand? %w`, err)
	}

	archiveFilenames := []string{
		"test/data/archive.7z",
		"test/data/archive.password-is-asdf.zip",
		"test/data/archive.tar.bz2",
		"test/data/archive.zip",
		"test/data/romeo.txt.bz2",
		"test/data/romeo.txt.gz",
		"test/data/zeroes-256mib.tar.gz",
	}
	for _, archiveFilename := range archiveFilenames {
		for _, directIO := range []bool{false, true} {
			if err := run(archiveFilename, directIO, ""); err != nil {
				return err
			}
			if strings.Contains(archiveFilename, "password-is-asdf") {
				if err := run(archiveFilename, directIO, "asdf"); err != nil {
					return err
				}
			}
		}
	}
	fmt.Println("PASS")
	return nil
}

func run(archiveFilename string, directIO bool, passphrase string) error {
	fmt.Printf("--- archiveFilename=%q directIO=%t passphrase=%q\n",
		archiveFilename, directIO, passphrase)
	if !placeholderTxtExists() {
		return fmt.Errorf(`Cannot verify pre-mount state. Try "fusermount -u test/mnt"?`)
	}

	args := []string(nil)
	if directIO {
		args = append(args, "-o", "direct_io")
	}

	// The -f flag means to run in the foreground (not as a daemon).
	args = append(args, "-o", "nonempty", "-f", archiveFilename, "test/mnt")

	cmd := exec.Command("out/fuse-archive", args...)
	cmd.Stdin = strings.NewReader(passphrase)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("Starting out/fuse-archive: %w", err)
	}

	if strings.Contains(archiveFilename, "password-is-asdf") && (passphrase == "") {
		timedOut := make(chan struct{})
		go func() {
			time.Sleep(10 * time.Second)
			close(timedOut)
			cmd.Process.Signal(os.Interrupt)
		}()
		if err := cmd.Wait(); err == nil {
			select {
			case <-timedOut:
				return fmt.Errorf("Process.Wait(): timed out")
			default:
				return fmt.Errorf("Process.Wait(): have nil error want non-nil")
			}
		} else if e, ok := err.(*exec.ExitError); !ok {
			return fmt.Errorf("Process.Wait(): have %T error want *exec.ExitError", err)
		} else if ec := e.ExitCode(); ec != 20 { // 20 is ERROR_CODE_PASSPHRASE_REQUIRED
			return fmt.Errorf("exit code: have %d want %d", ec, 20)
		}
		return nil
	}

	defer func() {
		cmd.Process.Signal(os.Interrupt)
		cmd.Process.Wait()
	}()

	totalTime := 0 * time.Millisecond
	for t := 1 * time.Millisecond; placeholderTxtExists(); t *= 2 {
		if totalTime > (10 * time.Second) {
			return fmt.Errorf("Timed out waiting for out/fuse-archive to bind the mountpoint")
		}
		time.Sleep(t)
		totalTime += t
	}

	testFunctions := ([]func() error)(nil)
	switch archiveFilename {
	case "test/data/romeo.txt.bz2", "test/data/romeo.txt.gz":
		// The "test/data/romeo.txt.{bz2,gz}" files are just bzip2- or
		// gzip-compressed files, not an archive (something that can containing
		// multiple files). Nonetheless, fuse-archive can still mount it (as
		// something containing a single file). Libarchive calls this a "raw"
		// archive.
		testFunctions = []func() error{
			testReadAt,
		}
	case "test/data/zeroes-256mib.tar.gz":
		testFunctions = []func() error{
			testZeroes256MiB,
		}
	default:
		testFunctions = []func() error{
			testReadAt,
			testReadFile,
			testSeek,
		}
		if strings.HasPrefix(archiveFilename, "test/data/archive.") {
			testFunctions = append(testFunctions, testNonASCIIPathnames)
		}
	}

	for _, tf := range testFunctions {
		if err := tf(); err != nil {
			return err
		}
	}
	return nil
}

func memset(b []byte, value byte) {
	for i := range b {
		b[i] = value
	}
}

func placeholderTxtExists() bool {
	_, err := os.Stat("test/mnt/placeholder.txt")
	return err == nil
}

func testNonASCIIPathnames() error {
	pathnames := []string{
		// These are inside and outside the BMP (Basic Multilingual Plane).
		"non-ascii/αβ.txt",
		"non-ascii/😻.txt",
	}
	for _, pathname := range pathnames {
		fmt.Printf("  - test NonASCIIPathnames [%s]\n", pathname)
		if _, err := os.Stat("test/mnt/" + pathname); err != nil {
			return err
		}
	}
	return nil
}

func testReadAt() error {
	f, err := os.Open("test/mnt/romeo.txt")
	if err != nil {
		return err
	}
	defer f.Close()

	if len(romeoTxt) != 942 {
		return fmt.Errorf(`"romeo.Txt" golden data has unexpected length: %d`, len(romeoTxt))
	}
	buf := make([]byte, 1024)
	rng := rand.New(rand.NewSource(1))

	for i := 0; i < 50; i++ {
		a := int(rng.Uint32() & 1023)
		b := int(rng.Uint32() & 1023)
		if a > b {
			a, b = b, a
		}
		// fmt.Printf("  - test ReadAt [%4d .. %4d]\n", a, b)

		memset(buf, 'A'+byte(i))
		n, err := f.ReadAt(buf[:b-a], int64(a))
		if (err != nil) && (err != io.EOF) {
			return err
		}

		wantN := 0
		if a < len(romeoTxt) {
			if b < len(romeoTxt) {
				wantN = b - a
			} else {
				wantN = len(romeoTxt) - a
			}
		}
		if n != wantN {
			return fmt.Errorf("length mismatch: have %d want %d", n, wantN)
		}

		have := buf[:n]
		want := romeoTxt[a : a+n]
		if !bytes.Equal(have, want) {
			return fmt.Errorf("content mismatch:\n    have %q\n    want %q", have, want)
		}
	}
	return nil
}

func testReadFile() error {
	testCases := []struct {
		checksum uint32
		filename string
	}{
		{0x67FABE9C, "test/mnt/romeo.txt.gz"},
		{0x67FABE9C, "test/mnt/romeo.txt.gz"},
		{0xFEDD8F35, "test/mnt/github-tags.json"},
		{0x67FABE9C, "test/mnt/romeo.txt.gz"},
		{0x703E9270, "test/mnt/non-ascii/αβ.txt"},
		{0x00000000, "test/mnt/artificial/0.bytes"},
		{0x703E9270, "test/mnt/non-ascii/αβ.txt"},
		{0x67FABE9C, "test/mnt/romeo.txt.gz"},
	}
	for _, tc := range testCases {
		fmt.Printf("  - test ReadFile(%q)\n", tc.filename)
		if data, err := os.ReadFile(tc.filename); err != nil {
			return err
		} else if c := crc32.ChecksumIEEE(data); c != tc.checksum {
			return fmt.Errorf("CRC-32 checksum: have 0x%08X, want 0x%08X", c, tc.checksum)
		}
	}
	return nil
}

func testSeek() error {
	fmt.Printf("  - test Seek\n")
	f, err := os.Open("test/mnt/hello.sh")
	if err != nil {
		return err
	}
	defer f.Close()

	if n, err := f.Seek(0, os.SEEK_END); err != nil {
		return err
	} else if n != 693 {
		return fmt.Errorf("SEEK_END: have %d, want 693", n)
	}

	if n, err := f.Seek(2, os.SEEK_SET); err != nil {
		return err
	} else if n != 2 {
		return fmt.Errorf("SEEK_SET: have %d, want 2", n)
	}

	buf := make([]byte, 9)
	if _, err := io.ReadFull(f, buf); err != nil {
		return err
	} else if have, want := string(buf), "/bin/bash"; have != want {
		return fmt.Errorf("Contents at [2..11]: have %q, want %q", have, want)
	}
	return nil
}

func testZeroes256MiB() error {
	fmt.Printf("  - test Zeroes256MiB\n")
	f, err := os.Open("test/mnt/zeroes")
	if err != nil {
		return err
	}
	defer f.Close()

	totalN := int64(0)
	hash := md5.New()
	buf := make([]byte, 64*1024)
	now := time.Now()
	for {
		n, err := f.Read(buf)
		totalN += int64(n)
		hash.Write(buf[:n])
		if err == io.EOF {
			break
		} else if err != nil {
			return err
		}
		if time.Since(now) > (10 * time.Second) {
			return fmt.Errorf("Timed out waiting for out/fuse-archive to serve data")
		}
	}

	if totalN != (256 * 1024 * 1024) {
		return fmt.Errorf("Byte count: have %d, want %d", totalN, 256*1024*1024)
	}

	have := fmt.Sprintf("%02X", hash.Sum(nil))
	want := "1F5039E50BD66B290C56684D8550C6C2"
	if have != want {
		return fmt.Errorf("MD5 hash:\n    have %s\n    want %s", have, want)
	}
	return nil
}

var romeoTxt = []byte(`Romeo and Juliet
Excerpt from Act 2, Scene 2

JULIET
O Romeo, Romeo! wherefore art thou Romeo?
Deny thy father and refuse thy name;
Or, if thou wilt not, be but sworn my love,
And I'll no longer be a Capulet.

ROMEO
[Aside] Shall I hear more, or shall I speak at this?

JULIET
'Tis but thy name that is my enemy;
Thou art thyself, though not a Montague.
What's Montague? it is nor hand, nor foot,
Nor arm, nor face, nor any other part
Belonging to a man. O, be some other name!
What's in a name? that which we call a rose
By any other name would smell as sweet;
So Romeo would, were he not Romeo call'd,
Retain that dear perfection which he owes
Without that title. Romeo, doff thy name,
And for that name which is no part of thee
Take all myself.

ROMEO
I take thee at thy word:
Call me but love, and I'll be new baptized;
Henceforth I never will be Romeo.

JULIET
What man art thou that thus bescreen'd in night
So stumblest on my counsel?
`)
