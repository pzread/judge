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

func RestAddPkg(ren render.Render,req *http.Request) {
    ret := make(map[string]interface{})

    pkgl := req.ContentLength
    if pkgl <= 0 {
	ret["error"] = "EINVAL"
	ren.JSON(200,ret)
	return
    }
    if pkgl > PKG_MAXSIZE {
	ret["error"] = "E2BIG"
	ren.JSON(200,ret)
	return
    }

    tmpf,err := ioutil.TempFile("","")
    if err != nil {
	ret["error"] = "EIO"
	ren.JSON(200,ret)
	return
    }
    writel,err := io.CopyN(tmpf,req.Body,pkgl)
    if writel != pkgl || err != nil {
	os.Remove(tmpf.Name())
	ret["error"] = "EIO"
	ren.JSON(200,ret)
	return
    }

    //os.Remove(tmpf.Name())
    ret["error"] = ""
    ren.JSON(200,ret)
}
