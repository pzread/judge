package bench

import (
    "testing"
    "os"
    "fmt"
)

func TestConFile(t *testing.T) {
    out,_ := os.Create("test")
    in,_ := os.Open("test")

    out.Write([]byte("Hello"))
    buf := make([]byte,1024)
    in.Read(buf)
    out.Write([]byte("Test"))
    os.Remove(out.Name())
    in.Read(buf)
    fmt.Println(string(buf))
}
