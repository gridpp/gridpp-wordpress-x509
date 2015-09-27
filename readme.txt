=== Client Certificate Authentication ===
Contributors: MarioLipinski
Donate link: http://www.cacert.org/index.php?id=13
Tags: authentication, ssl, client certificate, client certificate authentication, ssl authentication, login, registration
Requires at least: 3.1
Tested up to: 3.5.2
Stable tag: 1.0.2
License: GPLv2 or later
License URI: http://www.gnu.org/licenses/gpl-2.0.html

Authenticating with a SSL Client Certificate by using the email address. Optionally, new accounts can be created with the name from the certificate.

== Description ==

The Client Certificate Authentication plugin enables Wordpress to login a user with a SSL client certificate. The plugin uses the email address from the subject field to identify the user by the email address of his wordpress account. Optionally, new accounts can be created on the fly by using email address and name from the certificate. By limiting login and registration to users providing a client certificate, bots are locked out and spam is eliminated. 

Acknowledgements:  This plugin is based on the [HTTP Authentication plugin](http://wordpress.org/plugins/http-authentication/ "HTTP Authentication plugin") by Daniel Westermann-Clark. Ideas taken from Dan B.'s implementation for client certificate authentication.

== Installation ==

1. Login as an existing user, such as admin.
2. Upload the `client-certificate-authentication` folder to your plugins folder, usually `wp-content/plugins`. (Or simply via the built-in installer.)
3. Activate the plugin on the Plugins screen.
4. Logout.
5. Require certificate authentication for `wp-login.php` and `wp-admin`.
6. Try logging in with your client certificate.

== Changelog ==

= 1.0 =

Initial release.

= 1.0.1 =

Documentation updates.

= 1.0.2 =

Fixes to the short description.

== Frequently Asked Questions ==

= How should I set up client certificate authentication? =

This depends on your hosting environment and your means of authentication.
The plugin uses the $_SERVER environment variables `SSL_CLIENT_S_DN_Email` (beginning with) for the email address and `SSL_CLIENT_S_DN_CN` for the name.
A working example is given below:

In Apache HTTP (non-HTTPS) config add:

	RewriteEngine On
	RewriteRule ^/(wp-(admin|login\.php).*) https://%{HTTP_HOST}/$1
		
In Apache HTTPS config:

	<Location /wp-login.php>
		SSLVerifyClient optional
		<IfModule mod_rewrite.c>
			RewriteEngine   on
			RewriteCond  %{HTTP_USER_AGENT}  .*Safari.*
			RewriteCond  %{SSL:SSL_CLIENT_VERIFY} !=SUCCESS
			RewriteRule  .* /wp-admin [redirect,last]
		</IfModule>
	</Location>
	<Location /wp-admin>
		SSLVerifyClient require
	</Location>

Also make sure to set SSLCACertificatePath and enable CRL checks.
