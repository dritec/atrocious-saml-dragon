# Atrocius-Saml-Dragon

This is a fork of [Corto](http://code.google.com/p/corto).

# Introduction

Corto is configured entirely by SAML2 metadata - no other configuration is needed.

Corto runs in demo mode right out of the box, using corto.php as it's 'landing page' and
the metadata file `metadata/corto.optimized.metadata.php` as a pre-prepared metadafile.

`index.php` works as a simple application/sp which allows you to immediately test the
downloaded version of corto.

Corto uses a simple naming convention for mapping a Corto instance to the its metadata:
if you use `myproxy.php` as the landing page the metadata import script should be named
`myproxy.mdmgmt.php` and be placed in the metadata directory. `myproxy.mdmgmt.php` should
produce two metadata files: `myproxy.optimized.metadata.php` and `myproxy.public.metadata.php`.

## Configuration of Corto in a non-demo mode is done in two steps

We assume that we are installing in `/var/www/corto` and accessable at `http://example.com/corto`

- Check out the Corto code from the repository

	```sh
	cd /var/www
	svn checkout http://corto.googlecode.com/svn/trunk/ corto
	```

- Create a virtual host that maps `http://example.com/corto` to `/var/www/corto/public`
- Test that the setup is working by going to `http://example.com/corto`
- Create the 'landing page' by copying that index.php to myproxy.php
	`cp /var/www/corto/public/index.php /var/www/corto/public/myproxy.php`
- Configure a metadata import script
	`cp /var/www/corto/metadata/corto.mdmgmt.php /var/www/corto/metadata/myproxy.mdmgmt.php`
- Create metadata (We assume that we have metadata for both an SP and an IdP in SAML 2.0 XML format)
  Edit `/var/www/corto/metadata/myproxy.mdmgmt.php

  The `$metadatasources` contains pointers to all metadata used by Corto.

  Metadata can be imported as `private`, `public` or `remote`:
  * `private` is for non-public metadata eg. encryption keys for hosted entities
  * `public` is for public metadata for hosted entities. 'public' metadata will be served
     at the entity's well known address ie. the entityID.
  * `remote` is for remote entities

  There are two different handlers `php` and `xml` for metadata in different formats:
  * `php` points to a file on the disc in corto php format (ie. xml as php)
  * `xml` points to an xml file either on disk or on a remote location. All protocols
     recognized by php can be used.

	```php
	<?php
	$metadatasources = array(
		'public:php:' . dirname(__FILE__) . '/../metadata/corto.meta.php',
		'remote:xml:' . dirname(__FILE__) . '/../metadata/mysp.meta.xml',
		'remote:xml:' . dirname(__FILE__) . '/../metadata/myidp.meta.xml',
	);
	```

  All metadata sources are merged into one metadata document, ie. merging duplicate
  entities. Allowing public and private metadata to be merged for internal use in Corto.
  You can parse in metadata that contains commen metadata used for all entitites by using
  `_COMMON_` as the entityID. The metadata `corto.meta.php` is Cortos own internal
  metadata.

- Run the `myproxy.mdmgmt.php` script

	```
	php /var/www/corto/metadata/myproxy.mdmgmt.php
	```

  Now Corto has produced metadata fit for Corto consumtion.

- Metadata for Corto can be located at http://example.com/corto/myproxy.php/corto
- Configure you sp and idp with metadata from corto.
- You should now be able to login to your service via Corto to your IdP.

## NOTES

Always use https in production