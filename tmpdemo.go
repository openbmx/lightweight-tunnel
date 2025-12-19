package main
import (
  "fmt"
  "os"
  cfgpkg "github.com/openbmx/lightweight-tunnel/internal/config"
  "github.com/openbmx/lightweight-tunnel/pkg/tunnel"
)

func main(){
  tmp, _ := os.CreateTemp("","cfg*.json")
  tmp.WriteString(`{"mode":"client","remote_addr":"x","tunnel_addr":"10.0.0.2/24","key":"old-key-1234567890"}`)
  tmp.Close()
  cfg, _ := cfgpkg.LoadConfig(tmp.Name())
  t, _ := tunnel.NewTunnel(cfg, tmp.Name())
  fmt.Println("path", tmp.Name())
  t.Rotate("new-key-123456789012")
  b, _ := os.ReadFile(tmp.Name())
  fmt.Println(string(b))
}
