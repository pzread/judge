package main

import (
    "fmt"
    "net/http"
    "github.com/go-martini/martini"
    "github.com/martini-contrib/render"
)

func main() {
    fmt.Println("Night Server")

    mar := martini.Classic()
    mar.Use(render.Renderer())

    mar.Post("/api/(?P<name>[a-z0-9]+)/add_pkg",RestAddPkg)

    http.ListenAndServe("127.0.0.1:3000",mar)
}
