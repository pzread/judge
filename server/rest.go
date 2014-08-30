package main

import (
    "os"
    "io"
    "net/http"
    "github.com/go-martini/martini"
    "github.com/martini-contrib/render"
//  "github.com/garyburd/redigo/redis"
)

////////////////
//External API//
////////////////

func RestAddPkg(ren render.Render,req *http.Request,env *APIEnv) {
    ret := map[string]interface{}{"error":""}
    defer ren.JSON(200,ret)

    pkglen := req.ContentLength
    if pkglen <= 0 {
	ret["error"] = "EINVAL"
	return
    }
    if pkglen > PKG_MAXSIZE {
	ret["error"] = "ELIMIT"
	return
    }

    pkgid := PackageGenID()
    pkgfpath := STORAGE_PATH + "/package/" + pkgid + ".tar.xz"
    pkgfile,err := os.Create(pkgfpath)
    if err != nil {
	ret["error"] = "EIO"
	return
    }

    retlen,err := io.CopyN(pkgfile,req.Body,pkglen)
    pkgfile.Close()
    if retlen != pkglen || err != nil {
	os.Remove(pkgfpath)
	ret["error"] = "EIO"
	return
    }

    pkg := PackageCreate(pkgid,env)
    if pkg.Import(pkgfpath) != nil {
	os.Remove(pkgfpath)
	ret["error"] = "EINVAL"
	return
    }

    ret["pkgid"] = pkg.pkgid
}
func RestGetPkg(
    res http.ResponseWriter,
    req *http.Request,
    ram martini.Params,
    env *APIEnv,
) {
    pkg := PackageCreate(ram["pkgid"],env)
    err := pkg.Get()
    if err == nil {
	res.Header().Set("X-Accel-Redirect","/internal" + pkg.Export())
	res.WriteHeader(307)
	return
    } else if _,ok := err.(ErrPackageMiss); ok {
	if pkg.Transport() == nil {
	    res.Header().Set("X-Accel-Redirect","/internal" + pkg.Export())
	    res.WriteHeader(307)
	    return
	}
    }

    res.WriteHeader(404)
}

////////////////
//Internal API//
////////////////

func RestTransPkg(
    res http.ResponseWriter,
    req *http.Request,
    ram martini.Params,
    env *APIEnv,
) {
    pkg := PackageCreate(ram["pkgid"],env)
    err := pkg.Get()
    if err == nil {
	res.Header().Set("X-Accel-Redirect","/internal" + pkg.Export())
	res.WriteHeader(307)
    } else if _,ok := err.(ErrPackageMiss); ok {
	PackageClean(pkg.pkgid,env)
	res.WriteHeader(404)
    } else {
	res.WriteHeader(404)
    }
}
