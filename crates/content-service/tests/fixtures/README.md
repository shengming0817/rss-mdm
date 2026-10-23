# Apple installer metadata fixtures

`pkgbuild.pkg` and `productbuild.pkg` were generated using the system tools on macOS 26.4.
They contain one text file (`usr/local/share/rss/fixture.txt`), identifier `com.rss.agent`,
version `1.2.3`, with no installer scripts or signatures. They are format samples, not Agent releases.

Reproduce in a temporary directory:

```sh
mkdir -p root/usr/local/share/rss
printf 'RSS installer metadata fixture.\n' > root/usr/local/share/rss/fixture.txt
/usr/bin/pkgbuild --root root --identifier com.rss.agent --version 1.2.3 --install-location / component.pkg
/usr/bin/productbuild --package component.pkg product.pkg
```

The byte fixtures preserve the actual Apple TOC and compression. Inspection reads only
`PackageInfo`/`Distribution`; it does not decompress Payload or execute the package.
