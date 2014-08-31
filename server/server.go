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
    ApiId string
    ApiKey string
    CRs redis.Conn
    LRs redis.Conn
}

func Filter(crs_pool *redis.Pool,lrs_pool *redis.Pool) martini.Handler {
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
	lrs := lrs_pool.Get()
	lrs.Do("SELECT",2)

	apiid,err := redis.String(crs.Do("GET","APIKEY@" + apikey))
	if err != nil {
	    ren.JSON(200,map[string]interface{}{"error":"EINVAL"})
	    return
	}

	ctx.Map(&APIEnv{
	    apiid,
	    apikey,
	    crs,
	    lrs,
	})
    }
}
func DropPriv() {
    syscall.Umask(0022)
}
func main() {
    martini.Env = "production"
    DropPriv()

    crs_pool := &redis.Pool{
	MaxIdle:4,
	IdleTimeout:600 * time.Second,
	Dial:func() (redis.Conn,error) {
	    return redis.Dial("tcp",CRS_BIND)
	},
    }
    lrs_pool := &redis.Pool{
	MaxIdle:4,
	IdleTimeout:600 * time.Second,
	Dial:func() (redis.Conn,error) {
	    return redis.Dial("tcp","127.0.0.1:6379")
	},
    }

    crs := crs_pool.Get()
    crs.Do("SELECT",1)
    go StateBeat(crs)

    mar := martini.Classic()
    mar.Use(render.Renderer())
//  External API
    mar.Post(
	"/api/(?P<apikey>[a-z0-9]+)/add_pkg",
	Filter(crs_pool,lrs_pool),
	RestAddPkg,
    )
    mar.Get(
	"/api/(?P<apikey>[a-z0-9]+)/get_pkg/(?P<pkgid>[a-z0-9]+)",
	Filter(crs_pool,lrs_pool),
	RestGetPkg,
    )
    mar.Get(
	"/api/(?P<apikey>[a-z0-9]+)/get_state",
	Filter(crs_pool,lrs_pool),
	RestGetState,
    )
//  Internal API
    mar.Get(
	"/capi/(?P<apikey>[a-z0-9]+)/trans_pkg/(?P<pkgid>[a-z0-9]+)",
	Filter(crs_pool,lrs_pool),
	RestTransPkg,
    )

    fmt.Println("Night Server")
    mar.RunOnAddr(BIND)
}
