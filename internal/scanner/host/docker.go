package host

import "github.com/seolcu/hostveil/internal/domain"

type DockerCheck struct{ Root string }

func (c *DockerCheck) Name() string { return "docker" }

func (c *DockerCheck) Scan(_ string) []domain.Finding {
	return []domain.Finding{
		hostFinding(
			domain.FindingHostDockerSocketAccessible,
			domain.AxisHostHardening,
			domain.SeverityHigh,
			"docker",
			"Docker socket is accessible to non-root users",
			"Check whether the docker group or /var/run/docker.sock permissions allow non-root access.",
			"The Docker socket provides root-equivalent access. Any user in the docker group can trivially escalate to root.",
			"Restrict docker group membership and consider using rootless Docker.",
		),
		hostFinding(
			domain.FindingHostDockerDaemonTLS,
			domain.AxisHostHardening,
			domain.SeverityMedium,
			"docker",
			"Docker daemon may not use TLS",
			"Check whether the Docker daemon is configured with TLS for remote access.",
			"Without TLS, Docker API communication is unencrypted and vulnerable to interception.",
			"Configure Docker daemon with --tlsverify and client certificates.",
		),
	}
}
