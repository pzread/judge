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
    PkgId string
    ApiId string
    When int64
    Expire int64
    Env *APIEnv
}
type ErrPackageMiss struct {
    PkgId string
}
func (err ErrPackageMiss) Error() string {
    return err.PkgId
}
type ErrPackageAccess struct {
    PkgId string
}
func (err ErrPackageAccess) Error() string {
    return err.PkgId
}
/*
    Try to get the package which has been stored at local.
*/
func (pkg *Package) Get() error {
    var err error
    var meta Metadata

    metabuf,err := redis.Bytes(
	pkg.Env.LRs.Do("HGET","PACKAGE@" + pkg.PkgId,"meta"))
    if err != nil {
	return ErrPackageMiss{pkg.PkgId}
    }
    if err := json.Unmarshal(metabuf,&meta); err != nil {
	return err
    }

    pkg.PkgId = meta["pkgid"].(string)
    pkg.ApiId = meta["apiid"].(string)
    pkg.When = int64(meta["when"].(float64))
    pkg.Expire = int64(meta["expire"].(float64))
    return nil
}
/*
    Import new package from uploaded file.
    This function will add the package to the cluster, primarily used by
    API add_pkg.
*/
func (pkg *Package) Import(pkgfpath string) error {
    pkgdpath,err := decompress(pkg.PkgId,pkgfpath)
    if err != nil {
	return err
    }
    meta,err := loadMeta(pkgdpath)
    if err != nil {
	os.RemoveAll(pkgdpath)
	return err
    }
    meta["pkgid"] = pkg.PkgId
    meta["apiid"] = pkg.Env.ApiId
    meta["when"] = time.Now().Unix()

    if storeMeta(&meta,pkgdpath) != nil {
	os.RemoveAll(pkgdpath)
	return err
    }
    if _,err := compress(pkg.PkgId,pkgdpath); err != nil {
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
    return "/package/" + pkg.PkgId + ".tar.xz"
}
/*
    Transport package from other node.
*/
func (pkg *Package) Transport() error {
    bind,err := redis.String(
	pkg.Env.CRs.Do("SRANDMEMBER","PKG_NODE@" + pkg.PkgId))
    if err != nil {
	return err
    }
    url := fmt.Sprintf(
	"http://%s/capi/%s/trans_pkg/%s",
	bind,
	APIKEY,
	pkg.PkgId,
    )
    trans_res,err := http.Get(url)
    if err != nil {
	return err
    }
    defer trans_res.Body.Close()

    pkgfpath := STORAGE_PATH + "/package/" + pkg.PkgId + ".tar.xz"
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

    pkgdpath,err := decompress(pkg.PkgId,pkgfpath)
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
    Generate new PkgId.
*/
func PackageGenID() string {
    return fmt.Sprintf("%x",sha256.Sum256([]byte(uuid.NewUUID().String())))
}
/*
    Just a helper which can create an empty package.
*/
func PackageCreate(PkgId string,env *APIEnv) *Package {
    return &Package{
	PkgId:PkgId,
	ApiId:"",
	When:0,
	Expire:0,
	Env:env,
    }
}
/*
    TBD
*/
func PackageClean(PkgId string,env *APIEnv) error {
    env.LRs.Do("DEL","PACKAGE@" + PkgId)
    env.CRs.Do("SREM","PKG_NODE@" + PkgId,BIND)

    return nil
}

/*
    Compress package to SOTRAGE_PATH/package/PkgId.tar.xz
*/
func compress(PkgId string,dpath string) (string,error) {
    fpath := STORAGE_PATH + "/package/" + PkgId + ".tar.xz"
    cmd := exec.Command(TAR_PATH,"-Jcf",fpath,"-C",dpath,".")
    if err := cmd.Run(); err != nil {
	return "",err
    }

    return fpath,nil
}
/*
    Decompress pkg.tar.xz to SOTRAGE_PATH/package/PkgId.
*/
func decompress(PkgId string,fpath string) (string,error) {
    dpath := STORAGE_PATH + "/package/" + PkgId
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
    Expire := int64(meta["expire"].(float64))
    metabuf,_ := json.Marshal(meta)
    pkg.Env.LRs.Send("HSET","PACKAGE@" + pkg.PkgId,"meta",metabuf)
    pkg.Env.CRs.Send("SADD","PKG_NODE@" + pkg.PkgId,BIND)
    pkg.Env.LRs.Send("EXPIREAT","PACKAGE@" + pkg.PkgId,Expire)
    pkg.Env.CRs.Send("EXPIREAT","PKG_NODE@" + pkg.PkgId,Expire)
    pkg.Env.LRs.Flush()
    pkg.Env.CRs.Flush()
    pkg.Env.LRs.Receive()
    pkg.Env.CRs.Receive()
    pkg.Env.LRs.Receive()
    pkg.Env.CRs.Receive()

    pkg.ApiId = meta["apiid"].(string)
    if When,ok := meta["when"].(float64); ok {
	pkg.When = int64(When)
    } else {
	pkg.When = meta["when"].(int64)
    }
    pkg.Expire = Expire

    return nil
}
