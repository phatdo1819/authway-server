[Authway Server](../README.md) › First steps

# First steps

Once Authway Server is [installed](install.md):

1. **Log in**: open `https://<the address of the host>:8443`, accept the self-signed certificate, and log in with the
   first administrator and the password that the install script printed (the log has them, after an install by
   hand). The web UI asks for a new password first.
2. **Secure the administration**: **your account**, your name at the bottom of the menu, sets up your authenticator
   app. In **Settings**, check the password policy, and require an authenticator of every administrator if you want.
   **Administrators** adds the other administrators, each with its role.
3. **Add the users**, in **Users**, each with a password. For the servers that ask for a code, set up their
   authenticator: the user scans the QR code with their app.
4. **Add a WireGuard server**, in **WireGuard servers > Add server**:
   - a name, the public address (the one of the install, proposed) and the UDP port: 51820 for the first, forwarded
     by your router;
   - the tunnel network and its IPv6 one, both proposed;
   - the networks the peers reach, your LAN for example `192.168.1.0/24`, and the DNS servers of the peers;
   - the login: key only, password, or password and code; then the protections against copies, device binding, NAT
     or routed, and the traffic between peers. Each setting says what it does, and the **?** explains NAT and routed.
5. **Add a peer** to the server: on a server with login, choose its user. The address in the tunnel is the next free
   one. The configuration opens: download the file, or show the QR code to a phone.
6. **Connect a device**: import the file in Authway, or in a WireGuard app and log in with a browser. See
   [Connect a device](#connect-a-device) below.
7. **Check**: the panel of the server shows the peers connected and logged in, **Sessions** who is logged in now,
   and the **System** page whether everything works.

## Connect a device

The configuration file of a peer, or its QR code, goes into a WireGuard app. Which app depends on the login of the
server:

| Login of the server | Authway (Windows, macOS) | Official WireGuard apps (Windows, macOS, Linux, iOS, Android) |
|---|---|---|
| WireGuard key only | Connects | Connects, as with any WireGuard server |
| Password, or password and code | Connects, and opens its login window by itself | Connect, then the user logs in with a browser |
| With device binding | Connects, logs in and enrolls the computer | Can't log in |

### With Authway

Import the file in [Authway](https://github.com/phatdo1819/authway). When the tunnel comes up, its login window opens
by itself and asks for what the server needs: the password, and the code of the authenticator app. Authway is the only
app that logs in on a server with **device binding**: it enrolls the computer at the first login, signs every login
after, and then gives the peer a WireGuard key of its own.

### With the official WireGuard apps

On a server with **WireGuard key only**, import the file or scan the QR code, and turn the tunnel on: that's all.

On a server with **password**, or **password and authenticator code**:

1. **Import the file**, or scan the QR code with a phone, and **turn the tunnel on**. The peer connects, but until the
   login it reaches only the login page of its server.
2. **Open the login page in a browser**: go to any plain `http://` address, `http://neverssl.com` for example. With
   **Lead to the login page** on, in the settings of the server (it's on by default), every name leads to the server
   and every `http://` address opens its login page. Or type the address of the page, shown in the panel of the
   server: `http://10.8.0.1:8181/` for example. An `https://` address can't lead there: the browser shows an error
   instead.
3. **Log in** with the username and the password of the user, and the 6-digit code of their authenticator app when the
   server asks for one. The page then says *You're connected*, and when the session ends.
4. **Use the tunnel**: everything the server lets its peers reach now passes. The page can be closed.
5. **Log in again** when the session ends: at the end of its length (8 hours by default), after 5 minutes without the
   tunnel, or when an administrator changes the user, the peer or the server. Open the page again, the same way.
   **Log out**, on the page, ends the session at once.

On a phone it's the same, in its browser. A phone that moves from Wi-Fi to mobile data gets a new public IP: on a
server with the **strict** lock, its session pauses, and ends after 5 minutes: the user logs in again. Choose
**Roaming** for the servers of devices that move a lot: see [Good to know](good-to-know.md#peers-and-devices).

On a server with **device binding**, the browser and the WireGuard apps can't log in: the login has to be signed by the
enrolled computer, which only Authway does.
