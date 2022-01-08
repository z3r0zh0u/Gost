// go mod init example/hello
// go mod tidy
// go build -ldflags "-s -w" -o hello64.exe hello.go
// set GOARCH=386
// go build -ldflags "-s -w" -o hello86.exe hello.go
package main

import (
    "fmt"
    "time"
    "math/rand"
    "rsc.io/quote"
)

func add(x int, y int) int {
    return x + y
}

func swap(x, y string) (string, string) {
    return y, x
}


func main() {
    rand.Seed(time.Now().UnixNano())
    fmt.Println("My favorite number is", add(rand.Intn(100), rand.Intn(100)))
    a, b := swap("hello", "world")
    fmt.Println(a, b)
    fmt.Println(quote.Go())
}
