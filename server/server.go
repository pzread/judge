package main

import (
    "fmt"
    "log"
    "time"
    "syscall"
    "github.com/go-martini/martini"
    "github.com/martini-contrib/render"
    "github.com/garyburd/redigo/redis"
)

type APIEnv struct {
    apiid string
    apikey string
    crs redis.Conn
    prs redis.Conn
}

func Filter(crs_pool *redis.Pool,prs_pool *redis.Pool) martini.Handler {
    return func(
	ctx martini.Context,
	pam martini.Params,
	ren render.Render,
	log *log.Logger,
    ) {
	apikey := pam["apikey"]
	log.Println("API Key = ",apikey)

	crs := crs_pool.Get()
	crs.Do("SELECT",1)
	prs := prs_pool.Get()
	prs.Do("SELECT",2)

	apiid,err := redis.String(crs.Do("GET","APIKEY@" + apikey))
	if err != nil {
	    ren.JSON(200,map[string]interface{}{"error":"EINVAL"})
	    return
	}

	ctx.Map(&APIEnv{
	    apiid,
	    apikey,
	    crs,
	    prs,
	})
    }
}
func DropPriv() {
    syscall.Umask(0077)
}
func main() {
    DropPriv()

    crs_pool := &redis.Pool{
	MaxIdle:4,
	IdleTimeout:600 * time.Second,
	Dial:func() (redis.Conn,error) {
	    return redis.Dial("tcp","10.8.0.10:6379")
	},
    }
    prs_pool := &redis.Pool{
	MaxIdle:4,
	IdleTimeout:600 * time.Second,
	Dial:func() (redis.Conn,error) {
	    return redis.Dial("tcp","127.0.0.1:6379")
	},
    }

    mar := martini.Classic()
    mar.Use(render.Renderer())
    mar.Post(
	"/api/(?P<apikey>[a-z0-9]+)/add_pkg",
	Filter(crs_pool,prs_pool),
	RestAddPkg,
    )
    mar.Get(
	"/api/(?P<apikey>[a-z0-9]+)/get_pkg/(?P<pkgid>[a-z0-9]+)",
	Filter(crs_pool,prs_pool),
	RestGetPkg,
    )

    fmt.Println("Night Server")
    mar.RunOnAddr(BIND)
}
