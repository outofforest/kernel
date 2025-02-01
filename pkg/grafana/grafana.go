package grafana

import (
	"path/filepath"
	"strconv"

	"github.com/outofforest/cloudless"
	"github.com/outofforest/cloudless/pkg/container"
	"github.com/outofforest/cloudless/pkg/host"
	"github.com/outofforest/cloudless/pkg/host/firewall"
)

const (
	// Port grafana listens on.
	Port = 80

	image = "grafana/grafana@sha256:58aeabeae706b990b3b1fc5ae8c97fd131921b2d6eb26a137ebaa91689d6ebfe"
)

// Container runs grafana container.
func Container(appDir string) host.Configurator {
	return cloudless.Join(
		cloudless.Firewall(firewall.OpenV4TCPPort(Port)),
		container.AppMount(appDir),
		container.RunImage(image,
			container.EnvVar("GF_USERS_ALLOW_SIGN_UP", "false"),
			container.EnvVar("GF_PATHS_PROVISIONING", filepath.Join(container.AppDir, "provisioning")),
			container.EnvVar("GF_PATHS_DATA", filepath.Join(container.AppDir, "data")),
			container.EnvVar("GF_SERVER_HTTP_PORT", strconv.Itoa(Port)),
			container.EnvVar("GF_LOG_MODE", "console"),
			container.EnvVar("GF_LOG_CONSOLE_LEVEL", "info"),
			container.EnvVar("GF_LOG_CONSOLE_FORMAT", "json"),
		))
}
