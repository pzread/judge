package main

import (
    "fmt"
    "log"
    "time"
    "regexp"
    "net/http"
    "github.com/go-martini/martini"
    "github.com/martini-contrib/render"
    "github.com/garyburd/redigo/redis"
)

type APIEnv struct {
    apikey string
    crs redis.Conn
    prs redis.Conn
}

func Filter(rspool *redis.Pool) martini.Handler {
    return func(
	ctx martini.Context,
	pam martini.Params,
	ren render.Render,
	req *http.Request,
	log *log.Logger,
    ) {
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
	    rspool.Get(),
	    nil,
	})
    }
}
func main() {
    fmt.Println("Night Server")

    rspool := &redis.Pool{
	MaxIdle:4,
	IdleTimeout:600 * time.Second,
	Dial:func() (redis.Conn,error) {
	    return redis.Dial("tcp",":6379")
	},
    }

    mar := martini.Classic()
    mar.Use(render.Renderer())
    mar.Post("/api/(?P<apikey>[a-z0-9]+)/add_pkg",Filter(rspool),RestAddPkg)
    mar.RunOnAddr("127.0.0.1:3000")
}
