#!/bin/sh
a2enmod proxy
a2enmod proxy_http
a2enmod proxy_ajp
a2enmod rewrite
a2enmod deflate
a2enmod headers
a2enmod proxy_balancer
a2enmod proxy_connect
a2enmod proxy_html
a2dissite 000-default
a2ensite 000-default
apache2ctl -D FOREGROUND
