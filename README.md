# COMPX518-21A Assignment 3: Password Manager
## Lee So 1364878

Simple stupid password manager, written in Go.

Stored credentials are stored in an encrypted "vaultfile", locked behind a master password.

This password manager program can be invoked with 4 different commands (`pwman [COMMAND]`).

1. init

If a password vault doesn't already exist, this command creates it. Prompts the user for a master password to use for the vault.

If you already have a vault, this command won't let you overwrite it. Manually delete the vault files first if that's what you want.

The following commands only work after a vault has been created, and require the user to authenticate with their master password:

2. add

Lists the identifiers in the vault and then prompts for an identifier. If the identifier doesn't already exist in the vault, prompts for password length and then generates the new password. If it does, prompts to update the password entry.

3. remove

Lists the identifiers in the vault and then prompts for an identifier. If there is an entry in the vault matching the identifier, removes the entry.

4. fetch

Lists the identifiers in the vault and then prompts for an identifier. If there is an entry in the vault matching the identifier, shows the password.