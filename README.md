# decrypt-and-start

This project began as a shell script to invoke the `kms-encryption decrypt`
on the variables in the environment, looking for anything with a prefix of
"decrypt:", decrypting it using AWS KMS using the instance's profile, and
exporting the decrypted value back to the environment before exec to the
next command.

This is used as a Docker entrypoint for containers to be able to decrypt
encrypted environment variables passed into it.

## Usage

This project is a replacement for the ApplauseOSS/kms-encryption-toolbox
supplied shell script, `decrypt-and-start`.

It can be run as:

```bash
$ decrypt-and-start some other program
```

It can also take an optional flag to control the number of parallel workers:

```bash
$ decrypt-and-start -p 20 -- some other program
```
