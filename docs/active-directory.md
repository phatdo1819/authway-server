[Authway Server](../README.md) › Active Directory

# Active Directory

Authway Server can add VPN users from a group in Active Directory and let Active Directory check their passwords.
Users keep the Windows password they already know, and you add or remove VPN access by changing the group.

What stays in Authway Server, as for any other user: the authenticator app, the user's peers on each server, device
binding and the protections against copied configuration files. Administrators of the web UI are always local
accounts, so the web UI keeps working if Active Directory is down or set up wrong.

Samba as an Active Directory domain controller works too. Other LDAP directories, such as OpenLDAP, aren't supported
yet.

## What you need in Active Directory

- **A service account** that Authway Server uses to read the directory. A normal domain user is enough, because
  domain users can read users and groups by default. Give it a long password that doesn't expire, or remember to
  update it in Authway Server when it does. Authway Server never writes to the directory.
- **A group of VPN users**, for example `VPN Users`. Members of groups inside it count too. Don't use a primary group
  such as Domain Users: Active Directory doesn't list primary group members the way Authway Server asks for them.
- **An encrypted connection** to at least one domain controller: LDAPS on port 636, or StartTLS on port 389. Plain LDAP
  isn't accepted, because passwords cross it. A domain controller only offers either when it has a certificate,
  usually from Active Directory Certificate Services. If that certificate comes from your own certificate authority,
  you'll paste the CA certificate into Authway Server.
- **The network**: the Docker host must reach the domain controllers on that port.

## Set it up

1. Log in to the web UI as an Administrator, open **Settings** and its **Active Directory** tab.
2. Fill in:
   - **Domain controllers**: their host names, such as `dc1.example.com`. Add `:port` only for a non-standard port.
     They're tried in order. Use the names in their certificates, or the connection is refused.
   - **Connection**: LDAPS or StartTLS.
   - **CA certificate**: only if the domain controllers' certificates come from your own certificate authority. Paste
     it in PEM format (the text that starts with `-----BEGIN CERTIFICATE-----`). In Windows, export it from the
     Certificates console as *Base-64 encoded X.509*.
   - **Service account** and its **password**: `svc-authway@example.com` or the account's full DN.
   - **Search base**: usually your whole domain, such as `DC=example,DC=com`.
   - **VPN users group**: the group's full distinguished name, such as
     `CN=VPN Users,OU=Groups,DC=example,DC=com`. In *Active Directory Users and Computers*, turn on *View › Advanced
     Features*, open the group, and copy *distinguishedName* from the *Attribute Editor* tab.
   - **Username**: the logon name (`alice`) or the user principal name (`alice@example.com`). This is what users
     enter on the VPN login page. With the user principal name, `alice` alone works too.
3. Click **Test connection**. It reads the group without changing anything and shows how many members it found.
4. Turn on **Sync users from Active Directory** and click **Save**. The first sync starts at once.
5. Open **Users**. Members of the group appear, marked *From Active Directory*. Set up an authenticator for each one
   if your servers require a code, then give each user a peer on the servers they use, as for any user.

## What the sync does

The sync runs every 15 minutes by default (5 to 1440 in the settings). You can also click **Sync now**.

| In Active Directory | In Authway Server |
|---|---|
| A new member of the group | A new user, with the account's username and display name |
| The account is renamed, or its display name changes | The user follows |
| The account is disabled or expires | The user is disabled and logged out |
| The account is enabled again | The user is enabled again |
| The account leaves the group, or is deleted | The user is disabled and logged out. Their peers are kept |

A few things are left out and listed under **Members not added**:

- A username with characters Authway Server doesn't accept. Usernames can only use letters, digits and `. _ @ -`.
- A username that a local user already has. See [Existing local users](#existing-local-users).
- A username that another, older Active Directory account had, for example after an account was deleted and created
  again. Delete the old user in Authway Server and the next sync adds the new account.

If the group suddenly has no members at all, the sync disables nobody and shows an error instead: a wrong group, or a
service account that can't read it, is much more likely than everyone leaving at once.

For the same reason, a sync that would disable more than 5 users, and more than a quarter of the users from Active
Directory, at once disables none of them. It still adds and renames users as usual. A warning appears at the top of
every page, and **Settings > Active Directory** lists the users it held back. If they really left, click **Disable**
there to confirm. Until you do, those users still can't log in if their account is gone, because every login asks
Active Directory, but their open sessions stay open.

The username, full name, password and status of these users can't be changed in Authway Server, because the next sync
would undo it. Change them in Active Directory. If you delete such a user in Authway Server while the account is still
in the group, the next sync adds it back, without peers.

## Logging in

Users log in on the VPN login page, or in the Authway app, with their Active Directory username and password, plus a
code from their authenticator app if the server asks for one. `EXAMPLE\alice` works as well as `alice`. With the
logon name, so does `alice@example.com`; with the user principal name, so does `alice` alone.

When a user's password has expired, or an administrator set "User must change password at next logon", the login page
tells them to change it. It only says so when the password, and the code if the server asks for one, are right.
Otherwise it says, as always, that the username, password or code is wrong.

Every login asks Active Directory directly, so an account that was just disabled, locked, or removed from the group
can't log in, even before the next sync. Sessions that are already open last until the sync disables the user.

### When a domain controller is down

A domain controller that's switched off or stops answering is skipped after 5 seconds, and the next one in the list
is tried. After that, logins go straight to the domain controllers that answer, so only the first login waits. The sync
still tries the list in order, and once the first domain controller answers again, logins use it again. If a domain
controller stops answering in the middle of a sync, the sync moves on to the next one. The System page lists the
domain controllers that didn't answer at the latest sync.

A login gives up after 12 seconds in all, so users always get an answer. If no domain controller answers,
users of Active Directory can't log in and the page asks them to try again later. Those attempts don't count as failed
logins.

Everything else keeps working meanwhile: the web UI, VPN sessions that are already open, and the logins of local
users. Only the logins of Active Directory users, the sync, and the **Test connection** and **Sync now** buttons wait
for the domain controllers. A sync or a test gives up after 50 seconds.

### Account lockout

Wrong passwords that Authway Server sends to Active Directory also count toward your domain's account lockout policy.
To stop someone with a copied configuration file from locking a user out of Windows, Authway Server stops asking Active
Directory after 5 failed logins from networks other than the user's latest one. With the 5 allowed from that network,
Active Directory sees at most 10 wrong passwords for a user every 15 minutes. Set the domain's lockout threshold above
10, or make sure its observation window is short enough.

## Warnings

A warning appears at the top of every page of the web UI when:

- **The sync failed twice in a row.** One failure can be a domain controller restarting. After a failure, the next sync
  runs within 5 minutes, whatever the sync interval.
- **A sync is waiting for you**, because it would disable too many users at once. See
  [What the sync does](#what-the-sync-does).
- **The service account's password expires within 14 days**, or has expired. Authway Server reads the date from Active
  Directory at each sync. When it expires, nobody from Active Directory can log in until you set a new one in Active
  Directory and then in **Settings > Active Directory**.

The System page has the same checks. **Activity > Events** records when the sync starts failing and when it works
again, when it holds users back, and who confirmed disabling them.

## Existing local users

If you already have local users with the same usernames as the group members, the sync leaves them alone at first. To
switch them to Active Directory, turn on **Take over local users with the same username** and save. At the next sync,
each matching local user becomes that member's user: their peers and authenticator stay, their password comes from
Active Directory from then on, and they're logged out once.

## Troubleshooting

The latest sync's error appears in **Settings > Active Directory** and on the System page. The log has the
details: `docker compose logs authway-server`.

| Error | What to check |
|---|---|
| `certificate signed by unknown authority` | Paste your CA certificate into **CA certificate** |
| `certificate is valid for …, not …` | Use the domain controller's name as it appears in its certificate |
| `x509: negative serial number` | The domain controller's certificate is invalid. Samba's temporary self-signed certificate has this problem: give the domain controller a certificate from a proper certificate authority |
| `connection refused`, `i/o timeout` | LDAPS or StartTLS isn't enabled on the domain controller, or a firewall blocks the port |
| `no such host` | The container can't resolve the domain controller's name. Check the Docker host's DNS, or add the name with `extra_hosts` in `compose.override.yaml` |
| `the service account can't log in: check its name and password` | The service account's name or password |
| `the service account can't log in: its password has expired` | Set a new password for the service account in Active Directory, then in Settings |
| `the service account can't log in: it's locked out` or `disabled` | Unlock or enable the service account in Active Directory |
| `the group has no members` | The group's DN, that it isn't a primary group, and that the service account can read it |

## Backups

Backups include the Active Directory settings and the service account's password, encrypted with the backup's
passphrase like everything else in it. Restoring a backup on a new host brings back the same users, linked to the same
accounts.
