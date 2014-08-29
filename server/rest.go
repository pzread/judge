package main

import (
    "os"
    "io"
    "net/http"
    //"github.com/go-martini/martini"
    "github.com/martini-contrib/render"
)

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

    pkg := PackageCreate(env)

    pkgfpath := STORAGE_PATH + "/package/" + pkg.pkgid + ".tar.xz"
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

    if pkg.Import(pkgfpath) != nil {
	os.Remove(pkgfpath)
	ret["error"] = "EINVAL"
	return
    }

    ret["pkgid"] = pkg.pkgid
}
func RestGetPkg(ren render.Render,req *http.Request,env *APIEnv) {
    ret := map[string]interface{}{"error":""}
    defer ren.JSON(200,ret)
}
