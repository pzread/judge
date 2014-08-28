package main

import (
    "os"
    "io"
    "time"
    "net/http"
    //"github.com/go-martini/martini"
    "github.com/martini-contrib/render"
    "os/exec"
    "encoding/json"
    "code.google.com/p/go-uuid/uuid"
)

func RestAddPkg(ren render.Render,req *http.Request,env APIEnv) {
    var err error
    var meta map[string]interface{}

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

    pkgid := uuid.NewUUID().String()
    pkgfpath := STORAGE_PATH + "/package/" + pkgid + ".tar.xz"
    pkgfile,err := os.OpenFile(
	pkgfpath,
	os.O_WRONLY | os.O_CREATE | os.O_TRUNC,
	0600,
    )
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

    pkgdpath := STORAGE_PATH + "/package/" + pkgid
    if os.Mkdir(pkgdpath,0700) != nil {
	os.Remove(pkgfpath)
	ret["error"] = "EIO"
	return
    }
    defer func() {
	if ret["error"] != "" {
	    os.Remove(pkgfpath)
	    os.RemoveAll(pkgdpath)
	}
    }()

    cmd := exec.Command(TAR_PATH,"-Jxf",pkgfpath,"-C",pkgdpath)
    if err := cmd.Run(); err != nil {
	ret["error"] = "EIO"
	return
    }

    metafile,err := os.Open(pkgdpath + "/meta.json")
    if err != nil {
	ret["error"] = "EINVAL"
	return
    }
    metabuf := make([]byte,65536)
    metalen,err := metafile.Read(metabuf);
    metafile.Close()
    if err != nil {
	ret["error"] = "EINVAL"
	return
    }
    if err := json.Unmarshal(metabuf[:metalen],&meta); err != nil {
	ret["error"] = "ESYNTEX"
	return
    }
    //expire := int64(meta["expire"].(float64))
    meta["pkgid"] = pkgid
    meta["when"] = time.Now().Unix()
    metabuf,err = json.Marshal(meta)
    if err != nil {
	ret["error"] = "EINVAL"
	return
    }
    metafile,err = os.OpenFile(
	pkgdpath + "/meta.json",
	os.O_WRONLY | os.O_CREATE | os.O_TRUNC,
	0600,
    )
    if err != nil {
	ret["error"] = "EINVAL"
	return
    }
    metafile.Write(metabuf)
    metafile.Close()

    ret["pkgid"] = pkgid
}
