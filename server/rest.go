package main

import (
    //"fmt"
    "os"
    "io"
    "io/ioutil"
    "net/http"
    //"github.com/go-martini/martini"
    "github.com/martini-contrib/render"
)

func RestAddPkg(ren render.Render,req *http.Request,env APIEnv) {
    ret := map[string]interface{}{"error":""}
    defer ren.JSON(200,ret)

    pkgl := req.ContentLength
    if pkgl <= 0 {
	ret["error"] = "EINVAL"
	return
    }
    if pkgl > PKG_MAXSIZE {
	ret["error"] = "E2BIG"
	return
    }

    tmpf,err := ioutil.TempFile("","")
    if err != nil {
	ret["error"] = "EIO"
	return
    }
    defer tmpf.Close()
    defer os.Remove(tmpf.Name())

    writel,err := io.CopyN(tmpf,req.Body,pkgl)
    if writel != pkgl || err != nil {
	ret["error"] = "EIO"
	return
    }
}
