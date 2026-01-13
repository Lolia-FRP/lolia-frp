package banner

import (
	"fmt"

	"github.com/fatedier/frp/pkg/util/log"
	"github.com/fatedier/frp/pkg/util/version"
)

func DisplayBanner() {
	fmt.Println("    __          ___       __________  ____        ________    ____")
	fmt.Println("   / /   ____  / (_)___ _/ ____/ __ \\/ __ \\      / ____/ /   /  _/")
	fmt.Println("  / /   / __ \\/ / / __ `/ /_  / /_/ / /_/ /_____/ /   / /    / /  ")
	fmt.Println(" / /___/ /_/ / / / /_/ / __/ / _, _/ ____/_____/ /___/ /____/ /   ")
	fmt.Println("/_____/\\____/_/_/\\__,_/_/   /_/ |_/_/          \\____/_____/___/   ")
	fmt.Println("                                                                  ")
	log.Infof("Nya! %s 启动中", version.Full())
}
