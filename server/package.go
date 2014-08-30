package main

import (
    "io"
    "os"
    "os/exec"
    "fmt"
    "time"
    "net/http"
    "crypto/sha256"
    "encoding/json"
    "code.google.com/p/go-uuid/uuid"
    "github.com/garyburd/redigo/redis"
)

type Metadata map[string]interface{}

type Package struct {
    pkgid string
    apiid string
    when int64
    expire int64
    env *APIEnv
}
type ErrPackageMiss struct {
    pkgid string
}
func (err ErrPackageMiss) Error() string {
    return err.pkgid
}
type ErrPackageAccess struct {
    pkgid string
}
func (err ErrPackageAccess) Error() string {
    return err.pkgid
}
/*
    Try to get the package which has been stored at local.
*/
func (pkg *Package) Get() error {
    var err error
    var meta map[string]interface{}

    metabuf,err := redis.Bytes(
	pkg.env.prs.Do("HGET","PACKAGE@" + pkg.pkgid,"meta"))
    if err != nil {
	return ErrPackageMiss{pkg.pkgid}
    }
    if err := json.Unmarshal(metabuf,&meta); err != nil {
	return err
    }

    pkg.pkgid = meta["pkgid"].(string)
    pkg.apiid = meta["apiid"].(string)
    pkg.when = int64(meta["when"].(float64))
    pkg.expire = int64(meta["expire"].(float64))
    return nil
}
/*
    Import new package from uploaded file.
    This function will add the package to the cluster, primarily used by
    API add_pkg.
*/
func (pkg *Package) Import(pkgfpath string) error {
    pkgdpath,err := decompress(pkg.pkgid,pkgfpath)
    if err != nil {
	return err
    }
    meta,err := loadMeta(pkgdpath)
    if err != nil {
	os.RemoveAll(pkgdpath)
	return err
    }
    meta["pkgid"] = pkg.pkgid
    meta["apiid"] = pkg.env.apiid
    meta["when"] = time.Now().Unix()

    if storeMeta(&meta,pkgdpath) != nil {
	os.RemoveAll(pkgdpath)
	return err
    }
    if _,err := compress(pkg.pkgid,pkgdpath); err != nil {
	os.RemoveAll(pkgdpath)
	return err
    }
    if err := updatePackage(pkg,meta); err != nil {
	os.RemoveAll(pkgdpath)
	return err
    }

    return nil
}
/*
    Export nginx internal url.
*/
func (pkg *Package) Export() string {
    return "/package/" + pkg.pkgid + ".tar.xz"
}
/*
    Transport package from other node.
*/
func (pkg *Package) Transport() error {
    bind,err := redis.String(
	pkg.env.crs.Do("SRANDMEMBER","PKG_NODE@" + pkg.pkgid))
    if err != nil {
	return err
    }
    url := fmt.Sprintf(
	"http://%s/capi/%s/trans_pkg/%s",
	bind,
	APIKEY,
	pkg.pkgid,
    )
    trans_res,err := http.Get(url)
    if err != nil {
	return err
    }
    defer trans_res.Body.Close()

    pkgfpath := STORAGE_PATH + "/package/" + pkg.pkgid + ".tar.xz"
    pkgfile,err := os.Create(pkgfpath)
    if err != nil {
	return err
    }
    _,err = io.Copy(pkgfile,trans_res.Body)
    pkgfile.Close()
    if err != nil {
	os.Remove(pkgfpath)
	return err
    }

    pkgdpath,err := decompress(pkg.pkgid,pkgfpath)
    if err != nil {
	os.Remove(pkgfpath)
	return err
    }

    meta,err := loadMeta(pkgdpath)
    if err != nil {
	os.Remove(pkgfpath)
	os.RemoveAll(pkgdpath)
	return err
    }
    if err := updatePackage(pkg,meta); err != nil {
	os.Remove(pkgfpath)
	os.RemoveAll(pkgdpath)
	return err
    }

    return nil
}

/*
    Generate new pkgid.
*/
func PackageGenID() string {
    return fmt.Sprintf("%x",sha256.Sum256([]byte(uuid.NewUUID().String())))
}
/*
    Just a helper which can create an empty package.
*/
func PackageCreate(pkgid string,env *APIEnv) Package {
    return Package{
	pkgid:pkgid,
	apiid:"",
	when:0,
	expire:0,
	env:env,
    }
}
/*
    TBD
*/
func PackageClean(pkgid string,env *APIEnv) {

}

/*
    Compress package to SOTRAGE_PATH/package/pkgid.tar.xz
*/
func compress(pkgid string,dpath string) (string,error) {
    fpath := STORAGE_PATH + "/package/" + pkgid + ".tar.xz"
    cmd := exec.Command(TAR_PATH,"-Jcf",fpath,"-C",dpath,".")
    if err := cmd.Run(); err != nil {
	return "",err
    }

    return fpath,nil
}
/*
    Decompress pkg.tar.xz to SOTRAGE_PATH/package/pkgid.
*/
func decompress(pkgid string,fpath string) (string,error) {
    dpath := STORAGE_PATH + "/package/" + pkgid
    if err := os.Mkdir(dpath,0700); err != nil {
	return "",err
    }
    cmd := exec.Command(TAR_PATH,"-Jxf",fpath,"-C",dpath)
    if err := cmd.Run(); err != nil {
	os.RemoveAll(dpath)
	return "",err
    }

    return dpath,nil
}
/*
    Load metadata from meta.json.
*/
func loadMeta(dpath string) (Metadata,error) {
    var meta Metadata

    metafile,err := os.Open(dpath + "/meta.json")
    if err != nil {
	os.RemoveAll(dpath)
	return Metadata{},err
    }
    metabuf := make([]byte,PKGMETA_MAXSIZE)
    metalen,err := metafile.Read(metabuf);
    metafile.Close()
    if err != nil {
	os.RemoveAll(dpath)
	return Metadata{},err
    }
    if err := json.Unmarshal(metabuf[:metalen],&meta); err != nil {
	os.RemoveAll(dpath)
	return Metadata{},err
    }

    return meta,nil
}
/*
    Store metadata to meta.json.
*/
func storeMeta(meta *Metadata,dpath string) error {
    metabuf,err := json.Marshal(meta)
    if err != nil {
	return err
    }
    metafile,err := os.Create(dpath + "/meta.json")
    if err != nil {
	return err
    }
    _,err = metafile.Write(metabuf)
    metafile.Close()
    if err != nil {
	return err
    }

    return nil
}
/*
    Set package metadata, update database.
*/
func updatePackage(pkg *Package,meta Metadata) error {
    expire := int64(meta["expire"].(float64))
    metabuf,_ := json.Marshal(meta)
    pkg.env.prs.Send("HSET","PACKAGE@" + pkg.pkgid,"meta",metabuf)
    pkg.env.crs.Send("SADD","PKG_NODE@" + pkg.pkgid,BIND)
    pkg.env.prs.Send("EXPIREAT","PACKAGE@" + pkg.pkgid,expire)
    pkg.env.crs.Send("EXPIREAT","PKG_NODE@" + pkg.pkgid,expire)
    pkg.env.prs.Flush()
    pkg.env.crs.Flush()
    pkg.env.prs.Receive()
    pkg.env.crs.Receive()

    pkg.apiid = meta["apiid"].(string)
    if when,ok := meta["when"].(float64); ok {
	pkg.when = int64(when)
    } else {
	pkg.when = meta["when"].(int64)
    }
    pkg.expire = expire

    return nil
}
