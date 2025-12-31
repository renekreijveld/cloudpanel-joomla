server {
  listen 80;
  listen [::]:80;
  listen 443 quic;
  listen 443 ssl;
  listen [::]:443 quic;
  listen [::]:443 ssl;
  http2 on;
  http3 off;
  {{ssl_certificate_key}}
  {{ssl_certificate}}
  {{server_name}}
  {{root}}

  {{nginx_access_log}}
  {{nginx_error_log}}

  if ($scheme != "https") {
    rewrite ^ https://$host$request_uri permanent;
  }

  ######################################################################
  ## Protect against common exploits in query strings in NginX
  ######################################################################
  set $common_exploit 0;
  if ($query_string ~ "proc/self/environ") {set $common_exploit 1;}
  if ($query_string ~ "mosConfig_[a-zA-Z_]{1,21}(=|\%3D)") {set $common_exploit 1;}
  if ($query_string ~ "base64_(en|de)code\(.*\)") {set $common_exploit 1;}
  if ($query_string ~ "(<|%3C).*script.*(>|%3E)") {set $common_exploit 1;}
  if ($query_string ~ "GLOBALS(=|\[|\%[0-9A-Z]{0,2})") {set $common_exploit 1;}
  if ($query_string ~ "_REQUEST(=|\[|\%[0-9A-Z]{0,2})") {set $common_exploit 1;}
  if ($common_exploit = 1) {return 403;}

  ######################################################################
  ## Protect against common file injection attacks
  ######################################################################
  set $file_injection 0;
  if ($query_string ~ "[a-zA-Z0-9_]=http://") {set $file_injection 1;}
  if ($query_string ~ "[a-zA-Z0-9_]=(\.\.//?)+") {set $file_injection 1;}
  if ($query_string ~ "[a-zA-Z0-9_]=/([a-z0-9_.]//?)+") {set $file_injection 1;}
  if ($file_injection = 1) {return 403;}

  location ~ /.well-known {
    auth_basic off;
    allow all;
  }

  {{settings}}

  include /etc/nginx/global_settings;

  ######################################################################
  ## Block access to common Joomla sensitive files in NginX
  ######################################################################
  location = /configuration.php {
    log_not_found off;
    deny all;
    return 404;
  }
  location = /configuration.php-dist {
    log_not_found off;
    deny all;
    return 404;
  }
  location = /CONTRIBUTING.md {
    log_not_found off;
    deny all;
    return 404;
  }
  location = /htaccess.txt {
      log_not_found off;
      deny all;
      return 404;
  }
  location = /joomla.xml {
    log_not_found off;
    deny all;
    return 404;
  }
  location = /LICENSE.txt {
    log_not_found off;
    deny all;
    return 404;
  }
  location /phpunit.xml {
    log_not_found off;
    deny all;
    return 404;
  }
  location = /README.txt {
    log_not_found off;
    deny all;
    return 404;
  }
  location = /web.config {
    log_not_found off;
    deny all;
    return 404;
  }
  location = /language/en-GB/install.xml {
    log_not_found off;
    deny all;
    return 404;
  }
  location = /language/en-GB/langmetadata.xml {
    log_not_found off;
    deny all;
    return 404;
  }
  location = /language/nl-NL/install.xml {
    log_not_found off;
    deny all;
    return 404;
  }
  location = /language/nl-NL/langmetadata.xml {
    log_not_found off;
    deny all;
    return 404;
  }

  ######################################################################
  ## Block access to common Joomla sensitive folders
  ######################################################################
  location ^~ /logs/ {
    log_not_found off;
    deny all;
    return 404;
  }

  location ^~ /administrator/logs/ {
    log_not_found off;
    deny all;
    return 404;
  }

  try_files $uri $uri/ /index.php?$args;
  index index.php index.html;

  location ~ \.php$ {
    include fastcgi_params;
    fastcgi_intercept_errors on;
    fastcgi_index index.php;
    fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
    try_files $uri =404;
    fastcgi_read_timeout 3600;
    fastcgi_send_timeout 3600;
    fastcgi_param HTTPS $fastcgi_https;
    fastcgi_pass 127.0.0.1:{{php_fpm_port}};
    fastcgi_param PHP_VALUE "{{php_settings}}";
  }

  location ~* ^.+\.(css|js|jpg|jpeg|gif|png|ico|gz|svg|svgz|ttf|otf|woff|woff2|eot|mp4|ogg|ogv|webm|webp|zip|swf)$ {
    add_header Access-Control-Allow-Origin "*";
    add_header alt-svc 'h3=":443"; ma=86400';
    expires max;
    access_log off;
  }

  location /api/ {
    try_files $uri $uri/ /api/index.php?$args;
  }

  if (-f $request_filename) {
    break;
  }
}