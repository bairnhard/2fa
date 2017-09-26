package cfgtest

// package cfgtest

import (
	"fmt"

	"gopkg.in/gcfg.v1"
)

type cfg struct {
	Url  string
	Usr  string
	Pass string
}

func main() {

	gcfg.ReadFileInto(&cfg, "2fa.cfg")

	fmt.Println("User: ", cfg.Usr)
	fmt.Println("Password: ", cfg.Pass)
	fmt.Println("Url: ", cfg.Url)

}
