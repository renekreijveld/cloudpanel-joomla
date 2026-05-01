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

  # -- Maximum client body size set to 1 Gigabyte
  client_max_body_size 1G;

  ######################################################################
  ## Protect against common file injection attacks
  ######################################################################
  set $file_injection 0;
  if ($query_string ~ "[a-zA-Z0-9_]=http://") {set $file_injection 1;}
  if ($query_string ~ "[a-zA-Z0-9_]=(\.\.//?)+") {set $file_injection 1;}
  if ($query_string ~ "[a-zA-Z0-9_]=/([a-z0-9_.]//?)+") {set $file_injection 1;}
  if ($file_injection = 1) {return 403;}

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
  ## Disable PHP Easter Eggs
  ######################################################################
  if ($query_string ~ "\=PHP[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}") {return 403;}
  
  # add global x-content-type-options header
  add_header X-Content-Type-Options nosniff;

  location ~ /.well-known {
    auth_basic off;
    allow all;
  }

  {{settings}}

  include /etc/nginx/global_settings;

  ######################################################################
  ## Block access to common Joomla sensitive files in NginX
  ######################################################################
  # Block sensitive root-level files
  location ~* ^/(configuration\.php(-dist)?|CONTRIBUTING\.md|htaccess\.txt|joomla\.xml|LICENSE\.txt|phpunit\.xml|README\.txt|robots\.txt\.dist|web\.config)$ {
    log_not_found off;
    deny all;
    return 404;
  }

  # Block access to language metadata files
  location ~* ^/language/[a-z][a-z]-[A-Z][A-Z]/(install|langmetadata)\.xml$ {
    log_not_found off;
    deny all;
    return 404;
  }

  ######################################################################
  ## Block access to common Joomla sensitive folders
  ######################################################################
  location ~* ^/(administrator/)?logs/ {
    log_not_found off;
    deny all;
    return 404;
  }

  ######################################################################
  ## Password protect access to /administrator
  ## Uncomment the lines below if you want to prevent access
  ######################################################################
  # location /administrator {
  #   satisfy any;
  #
  #.  # Add ip addresses here you want to whitelist
  #   # First IP
  #   allow 1.2.3.4
  #   # Second ip
  #   allow 5.6.6.7.8
  #   deny all;
  #
  #   auth_basic "Restricted Area";
  #   # Add path here to .htpasswd file
  #   # See https://www.cyberciti.biz/faq/create-update-user-authentication-files/
  #   auth_basic_user_file /path/to/your/.htpasswd;
  # }

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

  if (-f $request_filename) {
    break;
  }
}
