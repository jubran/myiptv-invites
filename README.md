# myiptv-invites

Encrypted invite codes for the My IPTV iOS app. **No credentials here, in plain text or otherwise.**

`invites.json` entries `{id, nonce, ct}`: the app derives a key from the code the user types
(PBKDF2-HMAC-SHA256, 600k rounds), finds its entry by `id`, and decrypts `{server, key}`. It then loads
that server's encrypted details from the `myiptv-servers` repo and decrypts them with `key`.

Manage invites with `tools/invite.py` (see its header). Use long random codes.
