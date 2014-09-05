package bench

import (
    "testing"
    "io"
)

type TransReader struct {
    Buffer chan []byte
}
func (reader TransReader) Read(buf []byte) (n int,err error) {
    reader.Buffer <- buf
    retlen := len(<-reader.Buffer)
    if retlen == 0 {
	return 0,io.EOF
    }
    return retlen,nil
}

func transport(reader TransReader) {
    in := make([]byte,65536)
    for {
	buf := <-reader.Buffer
	copy(buf,in)
	reader.Buffer <- buf
    }
}
func run(pb *testing.PB) {
}
func BenchmarkChan(b *testing.B) {
    for i := 0; i < b.N; i += 1 {
	reader := TransReader{make(chan []byte)}
	go transport(reader)

	buf := make([]byte,65536)
	for i := 0; i < 65536; i += 1 {
	    reader.Read(buf)
	}
    }
}
