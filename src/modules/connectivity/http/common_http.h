/*
 *
 * Copyright 2017 Samsung Electronics All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 *
 */

#ifndef HTTP_COMMON_H
#define HTTP_COMMON_H

#include <artik_http.h>
#include <artik_ssl.h>

artik_ssl_config *copy_ssl_config(artik_ssl_config *from);
artik_http_headers *copy_http_headers(artik_http_headers *from);
void free_ssl_config(artik_ssl_config *ssl);
void free_http_headers(artik_http_headers *headers);

#endif /* HTTP_COMMON_H */
