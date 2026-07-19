# Ariava Installation Guide

This guide covers platform-specific prerequisites and installation steps for the Ariava Host.

## WSL

Ariava runs its Bridge on WSL as a systemd **user service** for the current Linux user. Having `systemctl` installed, or seeing systemd as PID 1, is not sufficient by itself: `systemctl --user` must also be able to connect to the user D-Bus.

These instructions target Ubuntu and Debian WSL distributions that use `apt`. On other distributions, install the equivalent systemd PAM and user D-Bus packages.

### 1. Install the user-manager dependencies

Run inside WSL:

```bash
sudo apt update
sudo apt install libpam-systemd dbus-user-session
```

`sudo` is required only to install distribution packages. Do not run `ariava` with `sudo`; Ariava installs a systemd user unit for the current user.

### 2. Enable systemd in WSL

Make sure `/etc/wsl.conf` contains:

```ini
[boot]
systemd=true
```

If the file already contains other settings, preserve them and merge this section instead of replacing the entire file.

### 3. Fully restart WSL

After closing your WSL windows, run this command from **Windows PowerShell**:

```powershell
wsl.exe --shutdown
```

Reopen the WSL distribution and log in directly as the regular Linux user that will run Ariava. Do not reach that user through `sudo` or `su`.

### 4. Verify the systemd user manager

Run inside the reopened WSL distribution:

```bash
ps -p 1 -o comm=
systemctl --user show-environment
ls -l "/run/user/$(id -u)/bus"
```

Expected results:

- `ps` prints `systemd`;
- `systemctl --user show-environment` exits successfully;
- `/run/user/<UID>/bus` exists.

The second command tests the same core capability Ariava requires. If it reports `Failed to connect to bus: No such file or directory`, `libpam-systemd` or `dbus-user-session` may be missing, or WSL may not have been fully restarted with `wsl.exe --shutdown` after installation and systemd configuration.

### 5. Install and initialize Ariava

After the checks pass, run as the regular user:

```bash
npm i -g ariava
ariava init
ariava config set relayBaseUrl https://your-relay.example.com
ariava service install
ariava service status
ariava install pi
```

Run `/reload` in an open pi session, or restart pi.

### Troubleshooting

Collect the following diagnostics:

```bash
id
ps -p 1 -o pid=,comm=,args=
systemctl --user show-environment
systemctl status "user@$(id -u).service" --no-pager
ls -la /run/user
ls -la "/run/user/$(id -u)" 2>&1
```

The relevant directory is `/run/user`, not `/run/usr`.

Do not work around an unavailable user manager with:

- `sudo ariava ...`;
- a system-level unit;
- `loginctl enable-linger`;
- `nohup`, PID files, or shell-profile startup;
- a Windows Task Scheduler fallback.
