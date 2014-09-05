package main

import (
    "fmt"
    "log"
    "time"
    "sync"
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
    PkgTran *PackageTransport
}

func Filter(
    crspl *redis.Pool,
    lrspl *redis.Pool,
    pkgtran *PackageTransport,
) martini.Handler {
    return func(
	ctx martini.Context,
	pam martini.Params,
	ren render.Render,
	log *log.Logger,
    ) {
	apikey := pam["apikey"]
	log.Println("API Key = ",apikey)

	crs := crspl.Get()
	crs.Do("SELECT",1)
	lrs := lrspl.Get()
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
	    pkgtran,
	})
    }
}
func DropPriv() {
    syscall.Umask(0022)
}
func main() {
    martini.Env = "production"
    DropPriv()

    crspl := &redis.Pool{
	MaxIdle:4,
	IdleTimeout:600 * time.Second,
	Dial:func() (redis.Conn,error) {
	    return redis.Dial("tcp",CRS_BIND)
	},
    }
    lrspl := &redis.Pool{
	MaxIdle:4,
	IdleTimeout:600 * time.Second,
	Dial:func() (redis.Conn,error) {
	    return redis.Dial("tcp","127.0.0.1:6379")
	},
    }
    pkgtran := &PackageTransport{
	Port:map[string]*PackagePort{},
	Lock:&sync.Mutex{},
	CRsPl:crspl,
	LRsPl:lrspl,
    }

    crs := crspl.Get()
    crs.Do("SELECT",1)
    go StateBeat(crs)

    mar := martini.Classic()
    mar.Use(render.Renderer())
//  External API
    mar.Post(
	"/api/(?P<apikey>[a-z0-9]+)/add_pkg",
	Filter(crspl,lrspl,pkgtran),
	RestAddPkg,
    )
    mar.Get(
	"/api/(?P<apikey>[a-z0-9]+)/get_pkg/(?P<pkgid>[a-z0-9]+)",
	Filter(crspl,lrspl,pkgtran),
	RestGetPkg,
    )
    mar.Get(
	"/api/(?P<apikey>[a-z0-9]+)/get_state",
	Filter(crspl,lrspl,pkgtran),
	RestGetState,
    )
//  Internal API
    mar.Get(
	"/capi/(?P<apikey>[a-z0-9]+)/tran_pkg/(?P<pkgid>[a-z0-9]+)",
	Filter(crspl,lrspl,pkgtran),
	RestTranPkg,
    )

    fmt.Println("Night Server")
    mar.RunOnAddr(BIND)
}
