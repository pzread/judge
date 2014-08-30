package main

import (
    "os"
    "io"
    "io/ioutil"
    "net/http"
    "github.com/go-martini/martini"
    "github.com/martini-contrib/render"
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
    pkgfile,err := ioutil.TempFile(STORAGE_PATH + "/tmp","")
    if err != nil {
	ret["error"] = "EIO"
	return
    }
    pkgfpath := pkgfile.Name()
    defer os.Remove(pkgfpath)
    retlen,err := io.CopyN(pkgfile,req.Body,pkglen)
    pkgfile.Close()
    if retlen != pkglen || err != nil {
	ret["error"] = "EIO"
	return
    }

    pkg := PackageCreate(pkgid,env)
    if pkg.Import(pkgfpath) != nil {
	ret["error"] = "EINVAL"
	return
    }

    ret["pkgid"] = pkg.PkgId
}
func RestGetPkg(
    res http.ResponseWriter,
    req *http.Request,
    ram martini.Params,
    env *APIEnv,
) {
    pkg := PackageCreate(ram["pkgid"],env)
    err := pkg.Get()
    if err == nil && pkg.ApiId == env.ApiId {
	res.Header().Set("X-Accel-Redirect","/internal" + pkg.Export())
	res.WriteHeader(307)
	return
    } else if _,ok := err.(ErrPackageMiss); ok {
	err = pkg.Transport()
	if err == nil {
	    res.Header().Set("X-Accel-Redirect","/internal" + pkg.Export())
	    res.WriteHeader(307)
	    return
	}
    }

    res.WriteHeader(404)
}
func RestGetState(ren render.Render,req *http.Request,env *APIEnv) {
    states,err := StateClus(env)
    if err != nil {
	ren.JSON(200,map[string]string{"error":"EINTAL"})
	return
    }
    ren.JSON(200,map[string]interface{}{"error":"","node":states})
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
	http.ServeFile(res,req,STORAGE_PATH + pkg.Export())
    } else if _,ok := err.(ErrPackageMiss); ok {
	PackageClean(pkg.PkgId,env)
	res.WriteHeader(404)
    } else {
	res.WriteHeader(404)
    }
}
