package main

import (
    "fmt"
    "log"
    "regexp"
    "net/http"
    "github.com/go-martini/martini"
    "github.com/martini-contrib/render"
)

type APIEnv struct {
    apikey string
}

func Filter(ctx martini.Context,pam martini.Params,ren render.Render,
req *http.Request,log *log.Logger) {
    apikey := pam["apikey"]
    log.Println("API Key = ",apikey)

    ret,err := regexp.MatchString("^127.0.0.1:",req.RemoteAddr)
    if ret == false || err != nil {
	ren.JSON(200,map[string]interface{}{
	    "error":"EINVAL",
	})
    }

    ctx.Map(APIEnv{
	apikey,
    })
}
func main() {
    fmt.Println("Night Server")

    mar := martini.Classic()
    mar.Use(render.Renderer())
    mar.Post("/api/(?P<apikey>[a-z0-9]+)/add_pkg",Filter,RestAddPkg)
    mar.RunOnAddr("127.0.0.1:3000")
}
