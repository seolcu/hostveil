package fix

// checkFirst is one thing to confirm before applying a fix, by finding ID.
// It is written for the dashboard's reader, who may not know what an
// sshd_config is: each entry names a check they can do and the answer that
// means "go ahead". Registry.Build copies it onto every action of the fix
// that does not set its own.
//
// It covers the fixes that can lock the operator out, take a service down
// or cannot be undone. TestEveryCheckFirstNamesARegisteredFix holds every key
// to a registration.
var checkFirst = map[string]string{
	"ssh.passwordauth":       "Open a second terminal and log in with your SSH key. Apply this only if that login works without a password.",
	"ssh.rootlogin":          "Log in as your normal user and run `sudo -v`. Apply this only if that works.",
	"ssh.kbdinteractive":     "If your SSH login asks for a one-time code, leave this alone.",
	"ssh.allowtcpforwarding": "List the SSH tunnels you use (`ssh -L`, `-R` or `-D`). Leave this alone if you need any of them.",
	"ssh.permittunnel":       "Leave this alone if you run a VPN over SSH.",
	"ssh.gatewayports":       "Leave this alone if other machines connect through an `ssh -R` tunnel to this host.",

	"firewall.inactive":      "Write down every service you open from another machine (a web interface, a game server, a media server). After this only SSH is reachable until you allow the others again.",
	"firewall.default-allow": "Write down every service you open from another machine (a web interface, a game server, a media server). After this only SSH is reachable until you allow the others again.",
	"firewall.docker-bypass": "Write down the container ports you open to the internet. You will allow each of them again in ufw after this.",

	"accounts.emptypassword":      "Make sure you can log in as another account that has sudo before you lock this one.",
	"accounts.uid0":               "Find out who created this account and what uses it, and make sure you can still become root with sudo.",
	"accounts.weak-password-hash": "Make sure you know this account's password or can reset it.",

	"updates.reboot-required":  "Pick a time when this host can be down for a few minutes, and make sure you can reach it again after it restarts.",
	"updates.pending-security": "Pick a quiet time: services on this host, sshd and Docker included, may restart during the upgrade.",
	"updates.disabled":         "Make sure the services on this host start again on their own after a restart, because updates will now restart them.",

	"cve.outdated-image": "Run `docker compose images` and note the current image ID, so you can go back to it if the new one misbehaves.",
	"compose.ds016":      "Check whether this container manages Docker (Portainer, Traefik, Watchtower). If it does, leave the socket mount.",
	"compose.dr001":      "Note which ports this service listens on. You will publish them in the Compose file after this.",
	"compose.ds009":      "Check the image's documentation for the user it can run as.",
	"compose.ds022":      "Find out where this service writes files (cache, logs, uploads). Those paths need a volume before this works.",
	"compose.ds001":      "Check whether the service needs host hardware or kernel access (a VPN client, a hardware monitor). If it does, leave this alone.",

	"dockerd.api-unauthenticated": "List the tools that reach Docker over the network (Portainer on another machine, a Docker context on your laptop). They stop working.",
	"dockerd.api-tls-unverified":  "Make sure you have a CA certificate and client certificates ready before you apply this.",
	"dockerd.userns-remap":        "Back up your container volumes first. Existing containers and images do not carry over and have to be pulled and recreated.",
	"dockerd.no-new-privileges":   "Pick a time when every container can restart.",
	"dockerd.group-members":       "Check whether this account runs containers for a service. If it does, give it another way to reach Docker first.",

	"ports.exposed-datastore": "List the machines that connect to this service. They lose access after this.",
	"ports.exposed-admin":     "List the machines that connect to this service. They lose access after this.",

	"agent.gateway-exposed": "List the devices that use the agent over the network (a phone, a laptop). They lose access after this.",
	"agent.auth-disabled":   "List the devices that use the agent over the network (a phone, a laptop). They lose access after this.",

	"proxy.admin-api-exposed":    "Check whether anything on another machine manages Caddy through its admin API.",
	"proxy.traefik-api-insecure": "Leave this alone if you use the Traefik dashboard and have not yet put it behind a login.",

	"kube.secrets-unencrypted": "Back up /var/lib/rancher/k3s first. This change cannot be rolled back.",
	"kube.kubeconfig-readable": "List the accounts that run kubectl without sudo. Each needs a kubeconfig of its own after this.",
	"kube.anonymous-auth":      "Check whether a monitoring tool reaches the API server or kubelet without credentials.",

	"systemd.private-tmp":               "Restart the service right after applying and watch its log (`journalctl -u <unit> -f`) for errors.",
	"systemd.protect-home":              "Check whether the service keeps data in a home directory. If it does, leave this alone.",
	"systemd.protect-system":            "Restart the service right after applying and watch its log (`journalctl -u <unit> -f`) for errors.",
	"systemd.private-devices":           "Check whether the service uses hardware (a GPU, a USB device, a VPN tunnel). If it does, leave this alone.",
	"systemd.protect-kernel-tunables":   "Restart the service right after applying and watch its log (`journalctl -u <unit> -f`) for errors.",
	"systemd.protect-control-groups":    "Leave this alone for container runtimes (Docker, containerd, k3s).",
	"systemd.restrict-namespaces":       "Leave this alone for container runtimes, sandboxes and browsers.",
	"systemd.memory-deny-write-execute": "Leave this alone for Node.js, Java, .NET and PHP services.",
}

// withCheckFirst fills CheckFirst on every action of fx that has none.
func withCheckFirst(fx *Fix, id string) {
	text, ok := checkFirst[id]
	if !ok {
		return
	}
	for i := range fx.Actions {
		if fx.Actions[i].CheckFirst == "" {
			fx.Actions[i].CheckFirst = text
		}
	}
}
